#!/usr/bin/env python3
"""Operate disposable local-state lab deployments without touching legacy state."""

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TERRAFORM_DIR = ROOT / "terraform"
STATE_ROOT = ROOT / ".lab-state"
RESERVED_IDS = {
    "ai-rag-lab",
    "default",
    "e2e-20261010",
    "legacy",
    "main",
    "prod",
    "production",
    "shared",
}
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,23}$")


class LabError(RuntimeError):
    """A safe, actionable runner failure."""


def validate_id(lab_id):
    if not ID_PATTERN.fullmatch(lab_id):
        raise LabError(
            "Deployment ID must be 3-24 lowercase letters, numbers, or hyphens, "
            "start with a letter or number, and contain no path separators."
        )
    if lab_id in RESERVED_IDS or lab_id.startswith("ai-rag-lab-"):
        raise LabError(f"Deployment ID '{lab_id}' is reserved to avoid legacy/shared collisions.")
    return lab_id


def paths_for(lab_id):
    validate_id(lab_id)
    if STATE_ROOT.is_symlink():
        raise LabError(".lab-state must not be a symbolic link.")
    directory = STATE_ROOT / lab_id
    root = STATE_ROOT.resolve()
    if directory.parent != STATE_ROOT or (directory.exists() and directory.is_symlink()):
        raise LabError("Deployment state path escapes .lab-state.")
    if directory.resolve().parent != root:
        raise LabError("Deployment state path escapes .lab-state.")
    return {
        "directory": directory,
        "state": directory / "terraform.tfstate",
        "plan": directory / "terraform.tfplan",
    }


def terraform_args(lab_id, state, command):
    prefix = f"ai-rag-{lab_id}"
    return [
        "terraform",
        f"-chdir={TERRAFORM_DIR}",
        command,
        "-input=false",
        "-lock=true",
        f"-state={state}",
        f"-var=name_prefix={prefix}",
        f"-var=environment_id={lab_id}",
        "-var=controls_enabled=true",
        "-var=manage_account_region_singletons=false",
        "-var=alarm_email=",
    ]


def command_env(profile, region):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("TF_VAR_") or key.startswith("TF_CLI_ARGS"):
            env.pop(key)
    env["AWS_PROFILE"] = profile
    env["AWS_REGION"] = region
    env["AWS_DEFAULT_REGION"] = region
    return env


def run(args, env, capture_output=False):
    try:
        return subprocess.run(args, check=True, text=True, env=env, capture_output=capture_output)
    except FileNotFoundError as exc:
        raise LabError(f"Required command not found: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip()
        raise LabError(f"Command failed ({' '.join(args[:3])}): {detail or exc.returncode}") from exc


def preflight(env, region):
    if shutil.which("terraform") is None:
        raise LabError("Terraform is required. Install Terraform >= 1.5.")
    if shutil.which("aws") is None:
        raise LabError("AWS CLI is required. Install AWS CLI v2.")
    run(["aws", "sts", "get-caller-identity", "--output", "json"], env, capture_output=True)
    configured_region = run(["aws", "configure", "get", "region"], env, capture_output=True).stdout.strip()
    if configured_region and configured_region != region:
        print(
            f"Note: AWS profile region is {configured_region}; using explicit requested region {region}.",
            file=sys.stderr,
        )


def init(env):
    run(
        ["terraform", f"-chdir={TERRAFORM_DIR}", "init", "-backend=false", "-reconfigure", "-input=false"],
        env,
    )


def ensure_new(paths):
    if paths["state"].exists() or paths["state"].is_symlink():
        raise LabError(
            f"State already exists: {paths['state']}. Use verify or down; up refuses to modify an existing lab."
        )


def state_identity(lab_id, paths, env):
    if paths["state"].is_symlink() or not paths["state"].is_file():
        raise LabError(f"No local state exists for '{lab_id}': {paths['state']}")
    output = run(
        [
            "terraform",
            f"-chdir={TERRAFORM_DIR}",
            "output",
            f"-state={paths['state']}",
            "-raw",
            "detection_alarm_prefix",
        ],
        env,
        capture_output=True,
    ).stdout.strip()
    expected = f"ai-rag-{lab_id}"
    if output != expected:
        raise LabError(f"State identity mismatch: expected '{expected}', observed '{output or '<empty>'}'.")
    resources = run(
        ["terraform", f"-chdir={TERRAFORM_DIR}", "state", f"-state={paths['state']}", "list"],
        env,
        capture_output=True,
    ).stdout.splitlines()
    forbidden = [
        address
        for address in resources
        if address.startswith("aws_api_gateway_account.")
        or address.startswith("aws_bedrock_model_invocation_logging_configuration.")
    ]
    if forbidden:
        raise LabError("State contains forbidden account/Region singleton resources: " + ", ".join(forbidden))


def print_locations(lab_id, paths):
    print(f"Deployment: {lab_id}")
    print(f"State: {paths['state']}")
    print(f"Name prefix: ai-rag-{lab_id}")
    print(f"Environment: {lab_id}")
    print(f"Cleanup: python3 scripts/lab.py down {lab_id} --confirm {lab_id}")


def plan(lab_id, paths, env):
    paths["directory"].mkdir(mode=0o700, parents=True, exist_ok=True)
    if paths["plan"].is_symlink():
        raise LabError(f"Refusing to overwrite symbolic-link plan path: {paths['plan']}")
    if paths["plan"].exists():
        paths["plan"].unlink()
    args = terraform_args(lab_id, paths["state"], "plan") + [f"-out={paths['plan']}"]
    run(args, env)
    print(f"Saved plan: {paths['plan']}")


def up(lab_id, paths, env):
    ensure_new(paths)
    init(env)
    plan(lab_id, paths, env)
    run(terraform_args(lab_id, paths["state"], "apply") + [str(paths["plan"])], env)
    state_identity(lab_id, paths, env)
    print("Apply complete with account/Region singleton management disabled.")


def verify(lab_id, paths, env):
    init(env)
    state_identity(lab_id, paths, env)
    endpoint = run(
        [
            "terraform",
            f"-chdir={TERRAFORM_DIR}",
            "output",
            f"-state={paths['state']}",
            "-raw",
            "api_invoke_url",
        ],
        env,
        capture_output=True,
    ).stdout.strip()
    if not endpoint:
        raise LabError("State has no API endpoint output.")
    print("Local state identity and singleton exclusion verified.")
    print(f"API endpoint: {endpoint}")


def down(lab_id, paths, env, confirmation):
    if confirmation != lab_id:
        raise LabError(f"Refusing destroy: pass --confirm {lab_id} exactly.")
    init(env)
    state_identity(lab_id, paths, env)
    run(terraform_args(lab_id, paths["state"], "destroy") + ["-auto-approve"], env)
    paths["state"].unlink()
    if paths["plan"].exists() and not paths["plan"].is_symlink():
        paths["plan"].unlink()
    try:
        paths["directory"].rmdir()
    except OSError:
        pass
    print("Destroy complete; local state was removed after Terraform succeeded.")


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="default", help="AWS profile to use (default: default)")
    parser.add_argument("--region", default="us-east-1", help="AWS region to use (default: us-east-1)")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("plan", "up", "verify", "down"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("id", help="Safe local deployment identifier")
        if command == "down":
            subparser.add_argument("--confirm", help="Must exactly equal the deployment identifier")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        lab_id = validate_id(args.id)
        paths = paths_for(lab_id)
        env = command_env(args.profile, args.region)
        preflight(env, args.region)
        if args.command == "plan":
            init(env)
            plan(lab_id, paths, env)
        elif args.command == "up":
            up(lab_id, paths, env)
        elif args.command == "verify":
            verify(lab_id, paths, env)
        else:
            down(lab_id, paths, env, args.confirm)
        print_locations(lab_id, paths)
        return 0
    except LabError as exc:
        print(f"LAB RUNNER ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
