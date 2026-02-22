import os
import sys
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.parser import IaCParser
from rules.exposed_tokens import ExposedAWSTokens
from rules.iam_privesc import IAMPrivilegeEscalation
from rules.lateral_movement import SSRFTokenTheft
from rules.s3_exposure import S3PublicExposure

@pytest.fixture
def parsed_sample():
    parser = IaCParser("tests/samples")
    return parser.load_files()

def test_exposed_tokens_rule(parsed_sample):
    rule = ExposedAWSTokens()
    findings = rule.analyze(parsed_sample)
    assert len(findings) == 1, "Expected exactly 1 finding for HV-001"
    assert findings[0]["rule_id"] == "HV-001"
    assert findings[0]["severity"] == "CRITICAL"

def test_iam_privesc_rule(parsed_sample):
    rule = IAMPrivilegeEscalation()
    findings = rule.analyze(parsed_sample)
    assert len(findings) == 1, "Expected exactly 1 finding for HV-002"
    assert findings[0]["rule_id"] == "HV-002"

def test_ssrf_token_theft_rule(parsed_sample):
    rule = SSRFTokenTheft()
    findings = rule.analyze(parsed_sample)
    assert len(findings) == 1, "Expected exactly 1 finding for HV-003"
    assert findings[0]["rule_id"] == "HV-003"

def test_s3_exposure_rule(parsed_sample):
    rule = S3PublicExposure()
    findings = rule.analyze(parsed_sample)
    assert len(findings) >= 1, "Expected at least 1 finding for HV-004 in CloudFormation"
    assert findings[0]["rule_id"] == "HV-004"
