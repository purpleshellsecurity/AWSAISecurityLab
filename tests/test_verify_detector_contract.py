import importlib.util
from pathlib import Path


def _contract_gate():
    path = Path(__file__).resolve().parents[1] / "scripts" / "verify_detector_contract.py"
    spec = importlib.util.spec_from_file_location("verify_detector_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_event_receipt_ttl_requires_executable_baseline_block():
    gate = _contract_gate()
    terraform = """
resource "aws_dynamodb_table" "baseline" {
  # Event receipts use expires_at. Baseline principal rows have no TTL and persist.\\n  ttl {\\n
  #   attribute_name = "expires_at"\\n    enabled = true\\n  }\\n
}
"""
    assert not gate.has_event_receipt_ttl(terraform)


def test_event_receipt_ttl_accepts_baseline_ttl_block():
    gate = _contract_gate()
    terraform = """
resource "aws_dynamodb_table" "baseline" {
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}
"""
    assert gate.has_event_receipt_ttl(terraform)


def test_isolation_configuration_requires_environment_namespace_and_singleton_opt_in():
    gate = _contract_gate()
    variables = """
    variable "environment_id" { default = "default" }
    variable "manage_account_region_singletons" { default = false }
    """
    main = 'detections_namespace = "AIRagLab/Detections/${var.environment_id}"'
    providers = "Environment = var.environment_id"
    api_gateway_account = "count = var.manage_account_region_singletons ? 1 : 0"
    logging = "count = var.manage_account_region_singletons ? 1 : 0"
    detections = """
    METRIC_NAMESPACE       = local.detections_namespace
    namespace           = local.detections_namespace
    """
    assert gate.has_isolation_configuration(
        variables, main, providers, api_gateway_account, logging, detections
    )


def test_isolation_configuration_rejects_ungated_singleton_management():
    gate = _contract_gate()
    assert not gate.has_isolation_configuration(
        'variable "environment_id" { default = "default" }',
        'detections_namespace = "AIRagLab/Detections/${var.environment_id}"',
        "Environment = var.environment_id",
        "cloudwatch_role_arn = aws_iam_role.apigw_cloudwatch.arn",
        "logging_config {}",
        "METRIC_NAMESPACE = local.detections_namespace",
    )
