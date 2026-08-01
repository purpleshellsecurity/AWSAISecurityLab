"""
Shared test setup for the two Lambda handlers.

Both handlers create boto3 clients and read required config from the environment at IMPORT time, so
the environment must be populated before the modules load. Neither the AWS SDK nor any AWS service
is exercised in tests: client CONSTRUCTION only needs a region, and every call site is either
monkeypatched or replaced with an in-memory fake.

The two files are both named handler.py, so they are loaded under distinct module names via
importlib rather than a plain `import`.
"""

import importlib.util
import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# Required by boto3 client construction / the handlers' os.environ reads. setdefault so a developer's
# real environment (if any) wins; none of these values is ever used against real AWS.
_TEST_ENV = {
    "AWS_DEFAULT_REGION": "us-east-1",
    # chat handler
    "CORPUS_BUCKET": "test-corpus-bucket",
    "MODEL_ID": "test-model-id",
    "INTERNAL_CIDRS": "10.12.0.0/16",
    # detector handler
    "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-alarms",
    "BASELINE_TABLE": "test-baseline-table",
    "SERVICE_ACCOUNTS": "enso-rag-svc,enso-vector-svc,enso-assistant-api",
    "HIGH_VOLUME_ALLOWLIST": "batch-indexer",
    "TOKEN_DEVIATION_FACTOR": "10",
}
for _k, _v in _TEST_ENV.items():
    os.environ.setdefault(_k, _v)


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relpath)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def chat():
    """The chat-assistant Lambda module, loaded once per test session."""
    return _load("chat_handler", "src/chat/handler.py")


@pytest.fixture(scope="session")
def detector():
    """The detector Lambda module, loaded once per test session."""
    return _load("detector_handler", "src/detector/handler.py")


@pytest.fixture(scope="session")
def manifest():
    """The real corpus manifest — tests authorize against the same catalog the deployed lab ships."""
    import json

    with open(REPO_ROOT / "corpus" / "manifest.json") as f:
        return json.load(f)
