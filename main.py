import argparse
import json
import sys
from core.engine import HellVantageEngine
from core.reporter import SARIFReporter

def main():
    parser = argparse.ArgumentParser(description="HellVantage - Elite Cloud SAST Scanner")
    parser.add_argument("-d", "--directory", required=True, help="Target directory containing IaC files to scan")
    parser.add_argument("-f", "--format", choices=['text', 'json', 'sarif'], default="text", help="Output format")

    args = parser.parse_args()

    if args.format != "sarif":
        print(f"[*] HellVantage initialized. Target: {args.directory}")
    
    engine = HellVantageEngine(args.directory)
    findings = engine.run()

    if not findings:
        if args.format != "sarif":
            print("\n[+] Scan completed. No vulnerabilities detected. Infrastructure is secure.")
        else:
            # Genera un SARIF vuoto ma valido
            print(SARIFReporter([]).generate())
        sys.exit(0)

    if args.format == "sarif":
        print(SARIFReporter(findings).generate())
        sys.exit(1)
        
    print(f"\n[!] Scan completed. FOUND {len(findings)} VULNERABILITIES:\n")
    
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print(f"[{f['severity']}] {f['rule_id']} - {f['title']}")
            print(f"  |-- File: {f['file']}")
            print(f"  |-- Details: {f['details']}\n")
    
    sys.exit(1)

if __name__ == "__main__":
    main()
