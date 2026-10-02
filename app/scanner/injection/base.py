from abc import ABC, abstractmethod


class InjectionScanner(ABC):

    @abstractmethod
    def scan(self, endpoint):
        """
        Scan a single endpoint for an injection vulnerability.
        """
        pass
