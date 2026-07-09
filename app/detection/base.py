from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple

class BaseDetector(ABC):
    """
    Abstract Base Class for all Prompt Injection detectors.
    """
    @property
    @abstractmethod
    def name(self) -> str:
        """
        The unique identifier for the detector (e.g., 'direct_regex_detector').
        """
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """
        The threat category this detector addresses (e.g., 'direct_injection', 'jailbreak').
        """
        pass

    @abstractmethod
    def evaluate(self, prompt: str) -> Tuple[float, Dict[str, Any]]:
        """
        Evaluates the prompt text.
        
        Returns:
            A tuple of (score, metadata) where:
            - score: A float between 0.0 (no threat) and 100.0 (certain threat).
            - metadata: A dictionary containing details of what was matched (e.g., matched terms, context).
        """
        pass
