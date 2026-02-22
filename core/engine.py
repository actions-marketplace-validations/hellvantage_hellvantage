import os
import logging
from core.parser import IaCParser
from core.scanner import Scanner
from rules.exposed_tokens import ExposedAWSTokens
from rules.iam_privesc import IAMPrivilegeEscalation
from rules.lateral_movement import SSRFTokenTheft
from rules.s3_exposure import S3PublicExposure

class HellVantageEngine:
    def __init__(self, target_dir):
        self.target_dir = target_dir

    def run(self):
        try:
            parser = IaCParser(self.target_dir)
            parsed_data = parser.load_files()

            # Se non ha trovato nulla, non c'è motivo di inizializzare lo scanner
            if not parsed_data.get("terraform") and not parsed_data.get("cloudformation"):
                logging.info("No valid IaC files found to scan.")
                return []

            scanner = Scanner(parsed_data)
            
            scanner.register_rule(ExposedAWSTokens())
            scanner.register_rule(IAMPrivilegeEscalation())
            scanner.register_rule(SSRFTokenTheft())
            scanner.register_rule(S3PublicExposure())

            return scanner.run()
        except Exception as e:
            logging.error(f"Critical error during scan execution: {e}")
            return []
