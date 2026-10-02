import httpx

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class Crawler:

    def __init__(self, max_pages=10):
        self.max_pages = max_pages
        self.visited = set()
        self.discovered = set()

    def crawl(self, start_url):

        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc

        self._crawl_page(start_url, base_domain)

        return sorted(self.discovered)

    def _crawl_page(self, url, base_domain):

        if len(self.visited) >= self.max_pages:
            return

        if url in self.visited:
            return

        self.visited.add(url)

        print(f"[+] Crawling: {url}")

        try:
            response = httpx.get(
                url,
                follow_redirects=True,
                timeout=10
            )

        except httpx.RequestError as e:
            print(f"[!] Request failed: {e}")
            return

        if "text/html" not in response.headers.get(
            "content-type",
            ""
        ):
            return

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        for link in soup.find_all("a", href=True):

            next_url = urljoin(
                url,
                link["href"]
            )

            parsed_url = urlparse(next_url)

            # Only crawl the same domain
            if parsed_url.netloc != base_domain:
                continue

            # Remove fragments
            clean_url = next_url.split("#")[0]

            self.discovered.add(clean_url)

            if clean_url not in self.visited:
                self._crawl_page(
                    clean_url,
                    base_domain
                )
import httpx

from bs4 import BeautifulSoup
from urllib.parse import (
    urljoin,
    urlparse,
    parse_qs,
    urlunparse,
)


class Crawler:

    def __init__(self, max_pages=20):

        self.max_pages = max_pages
        self.visited = set()
        self.discovered = {}

    def crawl(self, start_url):

        parsed_start = urlparse(start_url)

        base_domain = parsed_start.netloc

        self._crawl_page(
            start_url,
            base_domain
        )

        return sorted(
            self.discovered.values(),
            key=lambda x: x["url"]
        )

    def _crawl_page(
        self,
        url,
        base_domain
    ):

        if len(self.visited) >= self.max_pages:
            return

        if url in self.visited:
            return

        self.visited.add(url)

        print(f"[+] Crawling: {url}")

        try:

            response = httpx.get(
                url,
                follow_redirects=True,
                timeout=10
            )

        except httpx.RequestError as e:

            print(
                f"[!] Request failed: {e}"
            )

            return

        if "text/html" not in response.headers.get(
            "content-type",
            ""
        ):

            return

        final_url = str(response.url)

        self._register_endpoint(
            final_url
        )

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        for link in soup.find_all(
            "a",
            href=True
        ):

            next_url = urljoin(
                final_url,
                link["href"]
            )

            parsed_url = urlparse(
                next_url
            )

            # Same domain only
            if parsed_url.netloc != base_domain:
                continue

            # Only HTTP/HTTPS
            if parsed_url.scheme not in (
                "http",
                "https"
            ):
                continue

            # Remove fragments
            clean_url = urlunparse(
                (
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    parsed_url.query,
                    "",
                )
            )

            self._register_endpoint(
                clean_url
            )

            if clean_url not in self.visited:

                self._crawl_page(
                    clean_url,
                    base_domain
                )

    def _register_endpoint(self, url):

        parsed = urlparse(url)

        parameters = list(
            parse_qs(
                parsed.query
            ).keys()
        )

        self.discovered[url] = {
            "url": url,
            "method": "GET",
            "parameters": parameters,
        }
