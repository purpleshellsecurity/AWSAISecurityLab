#!/usr/bin/env python3
"""Enforce detector-specific structural invariants in CI. Not live AWS proof."""
import ast
from pathlib import Path
import re


def require(condition, reason):
    if not condition:
        raise SystemExit("DETECTOR GATE FAILED: " + reason)


def hcl_tokens(source):
    """Return HCL tokens while excluding comments, including escaped comment text."""
    tokens = []
    index = 0
    while index < len(source):
        if source[index].isspace():
            index += 1
        elif source.startswith("#", index) or source.startswith("//", index):
            newline = source.find("\n", index)
            index = len(source) if newline == -1 else newline + 1
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            index = len(source) if end == -1 else end + 2
        elif source[index] == '"':
            index += 1
            value = []
            while index < len(source) and source[index] != '"':
                if source[index] == "\\" and index + 1 < len(source):
                    index += 1
                value.append(source[index])
                index += 1
            tokens.append(("string", "".join(value)))
            index += 1
        elif source[index].isalnum() or source[index] in "_-":
            end = index + 1
            while end < len(source) and (source[end].isalnum() or source[end] in "_-"):
                end += 1
            tokens.append(("identifier", source[index:end]))
            index = end
        elif source[index] in "{}=":
            tokens.append(("symbol", source[index]))
            index += 1
        else:
            index += 1
    return tokens


def block_end(tokens, opening_brace):
    depth = 0
    for index in range(opening_brace, len(tokens)):
        if tokens[index] == ("symbol", "{"):
            depth += 1
        elif tokens[index] == ("symbol", "}"):
            depth -= 1
            if depth == 0:
                return index
    return None


def direct_block(tokens, start, end, name):
    depth = 0
    for index in range(start + 1, end):
        token = tokens[index]
        if token == ("symbol", "{"):
            depth += 1
        elif token == ("symbol", "}"):
            depth -= 1
        elif (depth == 0 and token == ("identifier", name)
              and index + 1 < end and tokens[index + 1] == ("symbol", "{")):
            return index + 1, block_end(tokens, index + 1)
    return None, None


def has_event_receipt_ttl(source):
    """Verify the baseline DynamoDB resource contains an executable TTL block."""
    tokens = hcl_tokens(source)
    for index in range(len(tokens) - 3):
        if tokens[index:index + 4] != [
            ("identifier", "resource"),
            ("string", "aws_dynamodb_table"),
            ("string", "baseline"),
            ("symbol", "{"),
        ]:
            continue
        resource_end = block_end(tokens, index + 3)
        if resource_end is None:
            return False
        ttl_start, ttl_end = direct_block(tokens, index + 3, resource_end, "ttl")
        if ttl_end is None:
            return False
        has_attribute = False
        has_enabled = False
        depth = 0
        for token_index in range(ttl_start + 1, ttl_end - 2):
            token = tokens[token_index]
            if token == ("symbol", "{"):
                depth += 1
            elif token == ("symbol", "}"):
                depth -= 1
            elif depth == 0 and tokens[token_index + 1] == ("symbol", "="):
                value = tokens[token_index + 2]
                has_attribute |= (token == ("identifier", "attribute_name")
                                  and value == ("string", "expires_at"))
                has_enabled |= (token == ("identifier", "enabled")
                                and value == ("identifier", "true"))
        return has_attribute and has_enabled
    return False


def has_isolation_configuration(variables, main, providers, api_gateway_account, logging, detections):
    """Verify the isolation guards are executable Terraform wiring, not comments."""
    compact = lambda source: re.sub(r"\s+", "", source)
    variables = compact(variables)
    main = compact(main)
    providers = compact(providers)
    api_gateway_account = compact(api_gateway_account)
    logging = compact(logging)
    detections = compact(detections)
    return all((
        'variable"environment_id"' in variables,
        'default="default"' in variables,
        'variable"manage_account_region_singletons"' in variables,
        'default=false' in variables,
        'detections_namespace="AIRagLab/Detections/${var.environment_id}"' in main,
        'Environment=var.environment_id' in providers,
        'count=var.manage_account_region_singletons?1:0' in api_gateway_account,
        'count=var.manage_account_region_singletons?1:0' in logging,
        'METRIC_NAMESPACE=local.detections_namespace' in detections,
        'namespace=local.detections_namespace' in detections,
    ))


def calls(fn, target):
    return [x for x in ast.walk(fn) if isinstance(x, ast.Call)
            and ((isinstance(x.func, ast.Name) and x.func.id == target)
                 or (isinstance(x.func, ast.Attribute) and x.func.attr == target))]


def run(root):
    source = (root / "src/detector/handler.py").read_text()
    tree = ast.parse(source)
    iam = (root / "terraform/iam.tf").read_text()
    infra = (root / "terraform/detections.tf").read_text()
    tests = (root / "tests/test_detector_handler.py").read_text()
    variables = (root / "terraform/variables.tf").read_text()
    main = (root / "terraform/main.tf").read_text()
    providers = (root / "terraform/providers.tf").read_text()
    api_gateway_account = (root / "terraform/api_gateway_account.tf").read_text()
    logging = (root / "terraform/logging.tf").read_text()

    def function(name):
        matches = [x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == name]
        require(len(matches) == 1, "missing/duplicate function " + name)
        return matches[0]

    for name in ("detection_sensitive_retrieval", "detection_indirect_injection"):
        found = calls(function(name), "alert")
        require(found, name + " has no alert")
        for call in found:
            require(any(k.arg == "event_id" and isinstance(k.value, ast.Call)
                        and isinstance(k.value.func, ast.Attribute)
                        and k.value.func.attr == "get"
                        and k.value.args and isinstance(k.value.args[0], ast.Constant)
                        and k.value.args[0].value == "_event_id"
                        for k in call.keywords),
                    name + " does not forward CloudWatch event ID")

    require(calls(function("lambda_handler"), "process_token_event"),
            "chat events bypass durable token processing")
    require(calls(function("process_token_event"), "transact_write_items"),
            "baseline processing not transactional")
    for permission in ("dynamodb:ConditionCheckItem", "dynamodb:PutItem", "dynamodb:UpdateItem"):
        require(permission in iam, "missing IAM permission " + permission)
    require(has_event_receipt_ttl(infra), "event receipt TTL missing")
    require(
        has_isolation_configuration(
            variables, main, providers, api_gateway_account, logging, infra
        ),
        "isolated environment or singleton-management guard missing",
    )
    require(calls(function("alert"), "deliver_once"), "finding delivery bypasses sink receipts")
    for case in (
        "test_duplicate_cloudwatch_delivery_does_not_republish",
        "test_duplicate_normal_chat_event_does_not_change_ewma_twice",
        "test_concurrent_same_event_one_metric_and_one_sns",
        "test_sns_failed_first_delivery_is_retried_without_repeating_metric",
        "test_duplicate_token_spike_republishes_neither_metric_nor_sns",
        "test_indirect_injection_replay_does_not_duplicate_notifications",
        "test_inflight_sink_is_not_treated_as_success",
        "test_transaction_capacity_failure_is_not_mistaken_for_duplicate",
    ):
        require(case in tests, "missing regression test " + case)


if __name__ == "__main__":
    run(Path(__file__).resolve().parents[1])
    print("Detector structural gate PASS; live AWS validation remains separate.")
