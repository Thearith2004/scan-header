import json
from pathlib import Path


class JSONReporter:

    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, target, findings):

        report = {
            "target": target,
            "total_findings": len(findings),
            "findings": []
        }

        for finding in findings:
            report["findings"].append({
                "title": finding.title,
                "severity": finding.severity,
                "description": finding.description,
                "url": finding.url,
                "evidence": finding.evidence
            })

        output_file = self.output_dir / "scan.json"

        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(f"\nReport saved: {output_file}")

        return output_file
import json
from pathlib import Path


class JSONReporter:

    def __init__(
        self,
        output_dir="reports"
    ):

        self.output_dir = Path(
            output_dir
        )

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

    def generate(
        self,
        target,
        findings,
        endpoints
    ):

        report = {
            "target": target,
            "total_findings": len(findings),
            "total_endpoints": len(endpoints),
            "findings": [],
            "endpoints": endpoints,
        }

        for finding in findings:

            report["findings"].append(
                {
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                    "url": finding.url,
                    "evidence": finding.evidence,
                }
            )

        output_file = (
            self.output_dir / "scan.json"
        )

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(
            f"\nReport saved: {output_file}"
        )

        return output_file
