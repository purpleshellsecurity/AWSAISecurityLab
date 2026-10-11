import importlib.util
from pathlib import Path

import pytest


def load():
    path = Path(__file__).resolve().parents[1] / "scripts" / "lab.py"
    spec = importlib.util.spec_from_file_location("lab_runner_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("lab_id", ["dev-123", "sandbox-a1", "e2e-20261011"])
def test_valid_ids_map_to_deterministic_local_paths(lab_id):
    runner = load()
    paths = runner.paths_for(lab_id)
    assert paths["state"] == runner.STATE_ROOT / lab_id / "terraform.tfstate"
    assert paths["plan"] == runner.STATE_ROOT / lab_id / "terraform.tfplan"


@pytest.mark.parametrize("lab_id", [
    "../escape", "default", "e2e-20261010", "legacy", "main", "prod", "production", "shared", "ai-rag-lab",
    "ai-rag-lab-copy", "UPPER", "ab", "a" * 25,
])
def test_invalid_or_reserved_ids_are_rejected(lab_id):
    runner = load()
    with pytest.raises(runner.LabError):
        runner.validate_id(lab_id)


def test_terraform_arguments_are_explicitly_local_and_hardened(tmp_path):
    runner = load()
    state = tmp_path / "terraform.tfstate"
    args = runner.terraform_args("dev-123", state, "plan")
    assert f"-state={state}" in args
    assert "-var=name_prefix=ai-rag-dev-123" in args
    assert "-var=environment_id=dev-123" in args
    assert "-var=controls_enabled=true" in args
    assert "-var=manage_account_region_singletons=false" in args
    assert "-var=alarm_email=" in args
    assert "terraform/terraform.tfstate" not in " ".join(args)


def test_command_environment_clears_terraform_variable_and_argument_overrides(monkeypatch):
    runner = load()
    monkeypatch.setenv("TF_VAR_alarm_email", "unsafe@example.test")
    monkeypatch.setenv("TF_CLI_ARGS_apply", "-auto-approve")
    env = runner.command_env("default", "us-east-1")
    assert "TF_VAR_alarm_email" not in env
    assert "TF_CLI_ARGS_apply" not in env
    assert env["AWS_PROFILE"] == "default"
    assert env["AWS_REGION"] == "us-east-1"


def test_down_requires_exact_confirmation(tmp_path):
    runner = load()
    paths = {"state": tmp_path / "terraform.tfstate", "plan": tmp_path / "terraform.tfplan", "directory": tmp_path}
    with pytest.raises(runner.LabError, match="--confirm dev-123"):
        runner.down("dev-123", paths, {}, "wrong-id")


def test_down_preserves_local_state_when_destroy_fails(monkeypatch, tmp_path):
    runner = load()
    state = tmp_path / "terraform.tfstate"
    plan = tmp_path / "terraform.tfplan"
    state.write_text("state")
    plan.write_text("plan")
    paths = {"state": state, "plan": plan, "directory": tmp_path}
    monkeypatch.setattr(runner, "init", lambda *_: None)
    monkeypatch.setattr(runner, "state_identity", lambda *_: None)
    monkeypatch.setattr(runner, "run", lambda *_: (_ for _ in ()).throw(runner.LabError("destroy failed")))
    with pytest.raises(runner.LabError, match="destroy failed"):
        runner.down("dev-123", paths, {}, "dev-123")
    assert state.exists()
    assert plan.exists()


def test_symlinked_state_root_is_rejected(monkeypatch, tmp_path):
    runner = load()
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "state-link"
    link.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(runner, "STATE_ROOT", link)
    with pytest.raises(runner.LabError, match="symbolic link"):
        runner.paths_for("dev-123")
