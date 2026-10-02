from dataclasses import dataclass


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    url: str
    evidence: str
    parameter: str | None = None

    def display(self):
        print(f"\n[!] {self.title}")
        print(f"    Severity: {self.severity}")
        print(f"    URL: {self.url}")

        if self.parameter:
            print(f"    Parameter: {self.parameter}")

        print(f"    Description: {self.description}")
        print(f"    Evidence: {self.evidence}")
