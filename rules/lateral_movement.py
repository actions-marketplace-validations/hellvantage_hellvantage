from rules.base import BaseRule

class SSRFTokenTheft(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule_id = "HV-003"
        self.title = "EC2 IMDSv1 Enabled (SSRF to Token Theft Vector)"
        self.severity = "HIGH"
        self.description = "Identified an EC2 instance allowing IMDSv1 (http_tokens = 'optional' or missing). This permits an attacker with an SSRF vulnerability to steal temporary IAM credentials for lateral movement."

    def analyze(self, parsed_data):
        findings = []
        tf_data = parsed_data.get("terraform", {})
        
        for filepath, content in tf_data.items():
            resources = content.get("resource", [])
            for resource_block in resources:
                if "aws_instance" in resource_block:
                    for instance_name, instance_config in resource_block["aws_instance"].items():
                        
                        # Verifica la presenza e la configurazione del blocco metadata_options
                        metadata_options = instance_config.get("metadata_options", [])
                        is_vulnerable = True
                        
                        if metadata_options:
                            # HCL2 restituisce una lista di dizionari per i blocchi nidificati
                            for option in metadata_options:
                                if option.get("http_tokens") == "required":
                                    is_vulnerable = False
                        
                        if is_vulnerable:
                            findings.append({
                                "rule_id": self.rule_id,
                                "title": self.title,
                                "severity": self.severity,
                                "file": filepath,
                                "details": f"EC2 instance '{instance_name}' does not enforce IMDSv2. Vulnerable to SSRF metadata attacks."
                            })
        return findings
