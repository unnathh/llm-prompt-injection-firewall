import time
from collections import defaultdict
from typing import Dict, List
import threading

class RateLimiter:
    """
    Sliding window log rate limiter using thread-safe memory storage.
    """
    def __init__(self) -> None:
        # Map of identifier (IP or Key) to list of query timestamps
        self.history: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, identifier: str, max_requests: int = 60, window_seconds: int = 60) -> bool:
        """
        Check if the identifier is allowed under sliding window limits.
        """
        now = time.time()
        boundary = now - window_seconds
        
        with self.lock:
            timestamps = self.history[identifier]
            
            # Prune obsolete timestamps outside window
            pruned_timestamps = [ts for ts in timestamps if ts > boundary]
            
            if len(pruned_timestamps) >= max_requests:
                # Limit exceeded
                self.history[identifier] = pruned_timestamps
                return False
                
            # Log current request
            pruned_timestamps.append(now)
            self.history[identifier] = pruned_timestamps
            return True

# Export rate limiter singleton
rate_limiter = RateLimiter()
