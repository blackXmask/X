from abc import ABC, abstractmethod
import random
import string
import math
from typing import Dict, List, Any, Optional

from config.targets import load_targets_from_file

class BaseEngine(ABC):
    def __init__(self, label: str, base_url: Optional[str] = None):
        self.label = label
        self.attack_type = self.__class__.__name__.replace('Engine', '').lower()
        
        # Set base URL
        if base_url:
            self.base_url = base_url.rstrip('/')
        else:
            targets = load_targets_from_file()
            self.base_url = random.choice(targets)
    
    def get_url(self, path: str = "", query: str = "") -> str:
        """Build full URL from base"""
        url = f"{self.base_url}{path}"
        if query:
            url += f"?{query}"
        return url
    
    @abstractmethod
    def generate_samples(self, count: int) -> List[Dict[str, Any]]:
        pass
    
    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy
    
    def count_special_chars(self, text: str) -> int:
        return sum(1 for c in text if not c.isalnum() and not c.isspace())
    
    def random_ip(self) -> str:
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    
    def random_string(self, length: int = 10) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def random_user_agent(self) -> str:
        uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.0',
            'python-requests/2.28.0',
            'curl/7.68.0',
            'sqlmap/1.7.0',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        ]
        return random.choice(uas)