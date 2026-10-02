import difflib
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from app.scanner.injection.base import InjectionScanner
from app.vulnerabilities.finding import Finding


class SQLiScanner(InjectionScanner):

    SQL_ERROR_MESSAGES = [
        "sql syntax",
        "mysql",
        "mysqli",
        "postgresql",
        "postgres",
        "sqlite",
        "sqlite3",
        "ora-",
        "oracle",
        "sqlstate",
        "syntax error",
        "unclosed quotation mark",
        "odbc",
        "jdbc",
    ]

    def __init__(self, timeout=5):
        self.timeout = timeout

    def _build_url(self, parsed, query_params, parameter, value):

        test_params = {
            key: values[0]
            for key, values in query_params.items()
        }

        test_params[parameter] = value

        test_query = urlencode(test_params, doseq=True)

        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                test_query,
                parsed.fragment,
            )
        )

    def _request(self, url):

        try:
            return requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )
        except requests.RequestException:
            return None

    def _similarity(self, first, second):

        return difflib.SequenceMatcher(
            None,
            first,
            second
        ).ratio()

    def scan(self, endpoint):

        findings = []

        if not endpoint["parameters"]:
            return findings

        url = endpoint["url"]

        print(f"[+] SQLi testing: {url}")

        parsed = urlparse(url)

        query_params = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        for parameter in endpoint["parameters"]:

            if parameter not in query_params:
                continue

            original_value = query_params[parameter][0]

            # =================================================
            # 1. BASELINE REQUEST
            # =================================================

            baseline_response = self._request(url)

            if baseline_response is None:
                print(
                    f"    [-] Baseline request failed "
                    f"for {parameter}"
                )
                continue

            baseline_status = baseline_response.status_code
            baseline_body = baseline_response.text
            baseline_length = len(baseline_body)

            # =================================================
            # 2. ERROR-BASED SQLi
            # =================================================

            quote_url = self._build_url(
                parsed,
                query_params,
                parameter,
                original_value + "'"
            )

            quote_response = self._request(quote_url)

            if quote_response is not None:

                quote_status = quote_response.status_code
                quote_body = quote_response.text
                quote_length = len(quote_body)

                response_text = quote_body.lower()

                matched_errors = [
                    error
                    for error in self.SQL_ERROR_MESSAGES
                    if error in response_text
                ]

                status_changed = (
                    baseline_status != quote_status
                )

                if matched_errors:

                    confidence = "MEDIUM"

                    if status_changed:
                        confidence = "HIGH"

                    evidence = (
                        f"Parameter: {parameter}; "
                        f"SQL error indicator: "
                        f"{matched_errors[0]}; "
                        f"Baseline status: {baseline_status}; "
                        f"Test status: {quote_status}; "
                        f"Baseline response size: "
                        f"{baseline_length} bytes; "
                        f"Test response size: "
                        f"{quote_length} bytes; "
                        f"Confidence: {confidence}"
                    )

                    findings.append(
                        Finding(
                            title="Possible SQL Injection",
                            severity="HIGH",
                            description=(
                                "The parameter produced a "
                                "database error indicator "
                                "after a quote-based test."
                            ),
                            url=quote_url,
                            evidence=evidence,
                            parameter=parameter,
                        )
                    )

                    print(
                        f"    [!] Possible SQL Injection: "
                        f"{parameter}"
                    )

                    print(
                        f"        Type: Error-based"
                    )

                    print(
                        f"        Confidence: {confidence}"
                    )

            # =================================================
            # 3. BOOLEAN-BASED SQLi
            # =================================================

            # MVP: only test numeric parameters.
            if not re.fullmatch(r"-?\d+", original_value):
                print(
                    f"    [-] Boolean test skipped: "
                    f"{parameter} is not numeric"
                )
                continue

            true_value = (
                f"{original_value} AND 1=1"
            )

            false_value = (
                f"{original_value} AND 1=2"
            )

            true_url = self._build_url(
                parsed,
                query_params,
                parameter,
                true_value
            )

            false_url = self._build_url(
                parsed,
                query_params,
                parameter,
                false_value
            )

            true_response = self._request(true_url)
            false_response = self._request(false_url)

            if true_response is None or false_response is None:
                print(
                    f"    [-] Boolean test failed: "
                    f"{parameter}"
                )
                continue

            true_status = true_response.status_code
            false_status = false_response.status_code

            true_body = true_response.text
            false_body = false_response.text

            true_length = len(true_body)
            false_length = len(false_body)

            # Compare baseline with TRUE condition.
            true_similarity = self._similarity(
                baseline_body,
                true_body
            )

            # Compare baseline with FALSE condition.
            false_similarity = self._similarity(
                baseline_body,
                false_body
            )

            # TRUE should behave like baseline.
            true_matches_baseline = (
                baseline_status == true_status
                and true_similarity >= 0.95
            )

            # FALSE should behave differently.
            false_differs = (
                baseline_status != false_status
                or false_similarity <= 0.90
            )

            if true_matches_baseline and false_differs:

                confidence = "MEDIUM"

                if (
                    baseline_status == true_status
                    and baseline_status != false_status
                    and true_similarity >= 0.98
                ):
                    confidence = "HIGH"

                evidence = (
                    f"Parameter: {parameter}; "
                    f"Baseline status: {baseline_status}; "
                    f"TRUE status: {true_status}; "
                    f"FALSE status: {false_status}; "
                    f"Baseline response size: "
                    f"{baseline_length} bytes; "
                    f"TRUE response size: "
                    f"{true_length} bytes; "
                    f"FALSE response size: "
                    f"{false_length} bytes; "
                    f"Baseline/TRUE similarity: "
                    f"{true_similarity:.2f}; "
                    f"Baseline/FALSE similarity: "
                    f"{false_similarity:.2f}; "
                    f"Confidence: {confidence}"
                )

                findings.append(
                    Finding(
                        title="Possible Boolean-based SQL Injection",
                        severity="HIGH",
                        description=(
                            "The parameter behaved like the "
                            "baseline when a TRUE condition "
                            "was supplied, but behaved "
                            "differently when a FALSE "
                            "condition was supplied."
                        ),
                        url=false_url,
                        evidence=evidence,
                        parameter=parameter,
                    )
                )

                print(
                    f"    [!] Possible SQL Injection: "
                    f"{parameter}"
                )

                print(
                    f"        Type: Boolean-based"
                )

                print(
                    f"        Confidence: {confidence}"
                )

                print(
                    f"        Baseline: "
                    f"{baseline_status}"
                )

                print(
                    f"        TRUE: "
                    f"{true_status}"
                )

                print(
                    f"        FALSE: "
                    f"{false_status}"
                )

            else:

                print(
                    f"    [+] No Boolean SQLi detected: "
                    f"{parameter}"
                )

        return findings