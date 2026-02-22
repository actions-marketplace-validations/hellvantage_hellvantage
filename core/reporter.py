import json

class SARIFReporter:
    def __init__(self, findings):
        self.findings = findings

    def generate(self):
        # Estraiamo le regole uniche per il manifesto SARIF
        rules_dict = {}
        for f in self.findings:
            if f["rule_id"] not in rules_dict:
                rules_dict[f["rule_id"]] = {
                    "id": f["rule_id"],
                    "name": f["title"],
                    "shortDescription": {"text": f["title"]},
                    "fullDescription": {"text": f.get("details", f["title"])},
                    "properties": {
                        "security-severity": self._map_severity(f["severity"])
                    }
                }
        
        rules_list = list(rules_dict.values())

        # Mappiamo i findings nel formato SARIF
        results = []
        for f in self.findings:
            results.append({
                "ruleId": f["rule_id"],
                "level": self._map_level(f["severity"]),
                "message": {"text": f["details"]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {"startLine": 1} # Linea 1 di default per IaC file-level
                    }
                }]
            })

        # Struttura ufficiale OASIS SARIF 2.1.0
        sarif_log = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "HellVantage",
                            "informationUri": "https://github.com/marketplace/hellvantage",
                            "rules": rules_list
                        }
                    },
                    "results": results
                }
            ]
        }
        return json.dumps(sarif_log, indent=2)

    def _map_severity(self, severity):
        mapping = {"CRITICAL": "9.0", "HIGH": "7.0", "MEDIUM": "4.0", "LOW": "1.0"}
        return mapping.get(severity, "1.0")
        
    def _map_level(self, severity):
        if severity in ["CRITICAL", "HIGH"]: return "error"
        if severity == "MEDIUM": return "warning"
        return "note"
