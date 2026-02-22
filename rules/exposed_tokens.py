from rules.base import BaseRule

class ExposedAWSTokens(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule_id = "HV-001"
        self.title = "Hardcoded AWS Credentials in Provider"
        self.severity = "CRITICAL"
        self.description = "Identified hardcoded AWS access_key or secret_key. This grants immediate Initial Access to the Cloud environment."

    def analyze(self, parsed_data):
        findings = []
        tf_data = parsed_data.get("terraform", {})
        
        for filepath, content in tf_data.items():
            providers = content.get("provider", [])
            for provider_block in providers:
                # Extract AWS provider configurations
                aws_provider = provider_block.get("aws", {})
                
                # Check for hardcoded keys
                if "access_key" in aws_provider or "secret_key" in aws_provider:
                    findings.append({
                        "rule_id": self.rule_id,
                        "title": self.title,
                        "severity": self.severity,
                        "file": filepath,
                        "details": "Found AWS access_key or secret_key defined explicitly in the provider block."
                    })
        return findings
