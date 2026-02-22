class BaseRule:
    def __init__(self):
        self.rule_id = "UNDEFINED"
        self.title = "Undefined Rule"
        self.severity = "INFO"
        self.description = "N/A"

    def analyze(self, parsed_data):
        """
        Analyzes the parsed data (Terraform/CloudFormation).
        Must return a list of findings (dictionaries).
        """
        raise NotImplementedError("The analyze() method must be implemented.")
