import httpx

class HTTPScanner:

    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "description": "Helps protect against XSS and content injection",
        },
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "description": "Forces HTTPS connections",
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "description": "Prevents MIME-type sniffing",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": "Helps prevent clickjacking",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": "Controls referrer information",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "description": "Controls browser features",
        },
    }

    def scan(self, url: str):

        try:
            response = httpx.get(
                url,
                follow_redirects=True,
                timeout=10
            )

            # Basic information
            print(f"\nTarget: {response.url}")
            print(f"Status: {response.status_code}")
            print(f"Server: {response.headers.get('server')}")
            print(f"Content-Type: {response.headers.get('content-type')}")
            print(f"Response Size: {len(response.content)} bytes")

            # Security headers
            print("\n=== Security Headers ===")

            for header, info in self.SECURITY_HEADERS.items():

                value = response.headers.get(header)

                if value:
                    print(f"[+] {header}: PRESENT")
                    print(f"    Value: {value}")
                else:
                    print(f"[!] {header}: MISSING")
                    print(f"    Severity: {info['severity']}")
                    print(f"    {info['description']}")

        except httpx.RequestError as e:
            print(f"Request failed: {e}")
import httpx

from app.vulnerabilities.finding import Finding


class HTTPScanner:

    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "description": "Helps protect against XSS and content injection",
        },
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "description": "Forces HTTPS connections",
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "description": "Prevents MIME-type sniffing",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": "Helps prevent clickjacking",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": "Controls referrer information",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "description": "Controls browser features",
        },
    }

    def scan(self, url: str):

        findings = []

        try:
            response = httpx.get(
                url,
                follow_redirects=True,
                timeout=10
            )

            print(f"\nTarget: {response.url}")
            print(f"Status: {response.status_code}")
            print(f"Server: {response.headers.get('server')}")
            print(f"Content-Type: {response.headers.get('content-type')}")
            print(f"Response Size: {len(response.content)} bytes")

            print("\n=== Security Headers ===")

            for header, info in self.SECURITY_HEADERS.items():

                value = response.headers.get(header)

                if value:
                    print(f"[+] {header}: PRESENT")
                    print(f"    Value: {value}")

                else:
                    finding = Finding(
                        title=f"Missing {header}",
                        severity=info["severity"],
                        description=info["description"],
                        url=str(response.url),
                        evidence=f"{header} header was not found in the HTTP response",
                    )

                    findings.append(finding)

            print("\n=== Findings ===")

            for finding in findings:
                finding.display()

            print(f"\nTotal Findings: {len(findings)}")

            return findings

        except httpx.RequestError as e:
            print(f"Request failed: {e}")

            return []
import httpx

from app.vulnerabilities.finding import Finding


class HTTPScanner:

    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "description": "Helps protect against XSS and content injection",
        },
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "description": "Forces HTTPS connections",
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "description": "Prevents MIME-type sniffing",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": "Helps prevent clickjacking",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": "Controls referrer information",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "description": "Controls browser features",
        },
    }

    def scan(self, url: str):

        findings = []

        try:
            response = httpx.get(
                url,
                follow_redirects=True,
                timeout=10
            )

            final_url = str(response.url)

            print(f"\nTarget: {final_url}")
            print(f"Status: {response.status_code}")
            print(f"Server: {response.headers.get('server')}")
            print(
                f"Content-Type: "
                f"{response.headers.get('content-type')}"
            )
            print(
                f"Response Size: "
                f"{len(response.content)} bytes"
            )

            print("\n=== Security Headers ===")

            for header, info in self.SECURITY_HEADERS.items():

                value = response.headers.get(header)

                if value:
                    print(f"[+] {header}: PRESENT")
                    print(f"    Value: {value}")

                    # CSP analysis
                    if header == "Content-Security-Policy":
                        self._analyze_csp(
                            value,
                            final_url,
                            findings
                        )

                else:
                    print(f"[-] {header}: MISSING")

                    findings.append(
                        Finding(
                            title=f"Missing {header}",
                            severity=info["severity"],
                            description=info["description"],
                            url=final_url,
                            evidence=(
                                f"{header} header was not found "
                                "in the HTTP response"
                            ),
                        )
                    )

            # Cookie scanner
            self._analyze_cookies(
                response,
                final_url,
                findings
            )

            print("\n=== Findings ===")

            for finding in findings:
                finding.display()

            print(
                f"\nTotal Findings: {len(findings)}"
            )

            return findings, final_url

        except httpx.RequestError as e:

            print(f"Request failed: {e}")

            return [], url

    def _analyze_cookies(
        self,
        response,
        url,
        findings
    ):

        cookies = response.headers.get_list(
            "set-cookie"
        )

        if not cookies:
            print("\n=== Cookie Security ===")
            print("No Set-Cookie headers found.")
            return

        print("\n=== Cookie Security ===")

        for cookie in cookies:

            parts = [
                part.strip()
                for part in cookie.split(";")
            ]

            cookie_name = parts[0].split("=")[0]

            attributes = {
                part.split("=")[0].lower()
                for part in parts[1:]
            }

            print(f"[+] Cookie: {cookie_name}")

            if "secure" in attributes:
                print("    Secure: PRESENT")
            else:
                print("    Secure: MISSING")

                findings.append(
                    Finding(
                        title=(
                            f"Cookie {cookie_name} "
                            "missing Secure flag"
                        ),
                        severity="MEDIUM",
                        description=(
                            "Cookie can potentially be sent "
                            "over an unencrypted connection."
                        ),
                        url=url,
                        evidence=cookie,
                    )
                )

            if "httponly" in attributes:
                print("    HttpOnly: PRESENT")
            else:
                print("    HttpOnly: MISSING")

                findings.append(
                    Finding(
                        title=(
                            f"Cookie {cookie_name} "
                            "missing HttpOnly flag"
                        ),
                        severity="MEDIUM",
                        description=(
                            "JavaScript may be able to access "
                            "this cookie."
                        ),
                        url=url,
                        evidence=cookie,
                    )
                )

            if "samesite" in attributes:
                print("    SameSite: PRESENT")
            else:
                print("    SameSite: MISSING")

                findings.append(
                    Finding(
                        title=(
                            f"Cookie {cookie_name} "
                            "missing SameSite attribute"
                        ),
                        severity="LOW",
                        description=(
                            "Cookie does not explicitly define "
                            "SameSite behavior."
                        ),
                        url=url,
                        evidence=cookie,
                    )
                )

    def _analyze_csp(
        self,
        csp,
        url,
        findings
    ):

        print("\n=== CSP Analysis ===")

        if "'unsafe-inline'" in csp:

            print(
                "[!] CSP allows unsafe-inline"
            )

            findings.append(
                Finding(
                    title="CSP allows unsafe-inline",
                    severity="MEDIUM",
                    description=(
                        "The Content-Security-Policy permits "
                        "inline JavaScript."
                    ),
                    url=url,
                    evidence=csp,
                )
            )

        if "'unsafe-eval'" in csp:

            print(
                "[!] CSP allows unsafe-eval"
            )

            findings.append(
                Finding(
                    title="CSP allows unsafe-eval",
                    severity="MEDIUM",
                    description=(
                        "The Content-Security-Policy permits "
                        "dynamic code evaluation."
                    ),
                    url=url,
                    evidence=csp,
                )
            )

        if "frame-ancestors" in csp:

            print(
                "[+] frame-ancestors: PRESENT"
            )

        else:

            print(
                "[-] frame-ancestors: MISSING"
            )
