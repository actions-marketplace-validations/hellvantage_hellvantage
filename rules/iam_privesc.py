from rules.base import BaseRule

class IAMPrivilegeEscalation(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule_id = "HV-002"
        self.title = "IAM Privilege Escalation (Wildcard Policy)"
        self.severity = "HIGH"
        self.description = "Identified IAM policy allowing '*' actions on '*' resources. This permits full administrative access and lateral movement."

    def analyze(self, parsed_data):
        findings = []
        tf_data = parsed_data.get("terraform", {})
        
        for filepath, content in tf_data.items():
            resources = content.get("resource", [])
            for resource_block in resources:
                # Inspect critical IAM resource types
                for policy_type in ["aws_iam_policy", "aws_iam_role_policy"]:
                    if policy_type in resource_block:
                        for policy_name, policy_config in resource_block[policy_type].items():
                            policy_str = str(policy_config.get("policy", ""))
                            
                            # Detection logic for the triad: Allow, Action *, Resource *
                            if ("'Effect': 'Allow'" in policy_str or '"Effect": "Allow"' in policy_str) and \
                               ("'Action': '*'" in policy_str or '"Action": "*"' in policy_str) and \
                               ("'Resource': '*'" in policy_str or '"Resource": "*"' in policy_str):
                                
                                findings.append({
                                    "rule_id": self.rule_id,
                                    "title": self.title,
                                    "severity": self.severity,
                                    "file": filepath,
                                    "details": f"Wildcard IAM policy found in resource '{policy_name}'. Potential Shadow Admin vector."
                                })
        return findings
