import sys

from app.scanner.http_scanner import HTTPScanner
from app.scanner.crawler import Crawler
from app.scanner.injection.sqli import SQLiScanner
from app.reports.json_reporter import JSONReporter


def main():

    if len(sys.argv) != 2:
        print("Usage: python cli.py <url>")
        return

    url = sys.argv[1]

    print("\n========================================")
    print("          SECSCANNER")
    print("========================================")

    # ============================================================
    # 1. HTTP SECURITY SCAN
    # ============================================================

    print("\n[1/5] HTTP Security Scan")

    scanner = HTTPScanner()

    findings, final_url = scanner.scan(url)

    # ============================================================
    # 2. ENDPOINT DISCOVERY
    # ============================================================

    print("\n[2/5] Endpoint Discovery")

    crawler = Crawler(max_pages=20)

    endpoints = crawler.crawl(final_url)

    print("\n=== Discovered Endpoints ===")

    for endpoint in endpoints:

        print(f"[+] {endpoint['url']}")

        if endpoint["parameters"]:
            print(
                f"    Parameters: "
                f"{', '.join(endpoint['parameters'])}"
            )

    # ============================================================
    # 3. INJECTION SCAN
    # ============================================================

    print("\n[3/5] Injection Scan")

    sqli_scanner = SQLiScanner()

    for endpoint in endpoints:

        if not endpoint["parameters"]:
            continue

        sqli_findings = sqli_scanner.scan(endpoint)

        findings.extend(sqli_findings)

    # ============================================================
    # 4. SCAN SUMMARY
    # ============================================================

    print("\n[4/5] Scan Summary")

    print(f"Target: {final_url}")
    print(f"Endpoints: {len(endpoints)}")
    print(f"Findings: {len(findings)}")

    # ============================================================
    # 5. GENERATE REPORT
    # ============================================================

    print("\n[5/5] Generate Report")

    reporter = JSONReporter()

    reporter.generate(
        target=final_url,
        findings=findings,
        endpoints=endpoints
    )


if __name__ == "__main__":
    main()
