import os
import sys
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.parser import IaCParser

def test_terraform_parsing():
    parser = IaCParser("tests/samples")
    parsed_data = parser.load_files()
    
    assert "terraform" in parsed_data, "Terraform key missing in parsed data"
    assert len(parsed_data["terraform"]) > 0, "No Terraform files parsed"
    
    # Verifica che il file infetto sia stato caricato
    tf_files = list(parsed_data["terraform"].keys())
    assert any("htb_vectors.tf" in f for f in tf_files), "Target file not found by parser"
