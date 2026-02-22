class Scanner:
    def __init__(self, parsed_data):
        self.parsed_data = parsed_data
        self.rules = []
        self.findings = []

    def register_rule(self, rule):
        self.rules.append(rule)

    def run(self):
        for rule in self.rules:
            # Execute the rule against the parsed data
            results = rule.analyze(self.parsed_data)
            if results:
                self.findings.extend(results)
        
        return self.findings
