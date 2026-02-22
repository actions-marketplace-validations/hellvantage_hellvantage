from rules.base import BaseRule

class S3PublicExposure(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule_id = "HV-004"
        self.title = "S3 Bucket Public Exposure"
        self.severity = "CRITICAL"
        self.description = "Identified an S3 Bucket with public access. This leads to immediate data exposure and potential cloud ransomware."

    def analyze(self, parsed_data):
        findings = []
        
        # Analisi Terraform
        tf_data = parsed_data.get("terraform", {})
        for filepath, content in tf_data.items():
            resources = content.get("resource", [])
            for resource_block in resources:
                if "aws_s3_bucket" in resource_block:
                    for bucket_name, bucket_config in resource_block["aws_s3_bucket"].items():
                        acl = bucket_config.get("acl", "")
                        if "public-read" in str(acl) or "public-read-write" in str(acl):
                            findings.append(self._create_finding(filepath, f"Terraform S3 bucket '{bucket_name}' has public ACL."))
        
        # Analisi CloudFormation
        cfn_data = parsed_data.get("cloudformation", {})
        for filepath, content in cfn_data.items():
            if not content or not isinstance(content, dict):
                continue
            resources = content.get("Resources", {})
            for resource_name, resource_config in resources.items():
                if resource_config.get("Type") == "AWS::S3::Bucket":
                    properties = resource_config.get("Properties", {})
                    acl = properties.get("AccessControl", "")
                    if acl in ["PublicRead", "PublicReadWrite"]:
                        findings.append(self._create_finding(filepath, f"CloudFormation S3 bucket '{resource_name}' has public AccessControl."))
        
        return findings

    def _create_finding(self, filepath, details):
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file": filepath,
            "details": details
        }
