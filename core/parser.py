import os
import json
import yaml
import hcl2
import logging

# Configurazione base del logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

class IaCParser:
    def __init__(self, target_dir):
        self.target_dir = target_dir

    def load_files(self):
        parsed_data = {"terraform": {}, "cloudformation": {}}
        
        if not os.path.exists(self.target_dir):
            logging.error(f"Target directory '{self.target_dir}' does not exist.")
            return parsed_data

        if not os.path.isdir(self.target_dir):
            logging.error(f"Target '{self.target_dir}' is not a directory.")
            return parsed_data

        for root, _, files in os.walk(self.target_dir):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    if file.endswith('.tf'):
                        parsed_content = self._parse_hcl(filepath)
                        if parsed_content: parsed_data["terraform"][filepath] = parsed_content
                    elif file.endswith(('.yaml', '.yml')):
                        parsed_content = self._parse_yaml(filepath)
                        if parsed_content: parsed_data["cloudformation"][filepath] = parsed_content
                    elif file.endswith('.json'):
                        parsed_content = self._parse_json(filepath)
                        if parsed_content: parsed_data["cloudformation"][filepath] = parsed_content
                except PermissionError:
                    logging.warning(f"Permission denied accessing {filepath}. Skipping.")
                except Exception as e:
                    logging.debug(f"Unexpected error processing {filepath}: {e}")

        return parsed_data

    def _parse_hcl(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return hcl2.load(f)
        except Exception as e:
            logging.warning(f"Failed to parse Terraform file {filepath}: Malformed HCL syntax.")
            return None

    def _parse_yaml(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.warning(f"Failed to parse YAML file {filepath}: Malformed syntax.")
            return None

    def _parse_json(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"Failed to parse JSON file {filepath}: Malformed syntax.")
            return None
