import random
from typing import Dict, List, Any
from .base_engine import BaseEngine

class SQLEngine(BaseEngine):
    def __init__(self, base_url: str = None):
        super().__init__('injection', base_url)
        
        self.sql_keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 
                            'EXEC', 'EXECUTE', 'SCRIPT', 'FROM', 'WHERE', 'AND', 'OR', 'NULL']
        self.sql_comments = ['--', '/*', '#', ';%00', '--+', '--+-']
        self.boolean_patterns = ["' OR '1'='1", "' AND '1'='1", "1=1", "1=2", "' OR 1=1--", "' OR 1=1#"]
        self.time_based = ['SLEEP(5)', 'BENCHMARK(1000000,MD5(1))', 'WAITFOR DELAY', 'pg_sleep(5)']
        
    def generate_payload(self) -> str:
        techniques = [
            lambda: f"' OR '{random.choice(['1', 'a'])}'='{random.choice(['1', 'a'])}",
            lambda: f"{random.choice(self.sql_comments)} {random.choice(self.sql_keywords)} {random.choice(self.sql_keywords)}",
            lambda: f"' UNION {random.choice(self.sql_keywords)} {random.choice(self.sql_keywords)}--",
            lambda: f"1; {random.choice(self.sql_keywords)} {random.choice(self.sql_keywords)}--",
            lambda: f"' {random.choice(self.time_based)}--",
            lambda: f"{random.choice(self.boolean_patterns)}",
            lambda: f"admin'--",
            lambda: f"' OR 1=1 LIMIT 1--",
            lambda: f"1' AND 1=1--",
            lambda: f"' HAVING 1=1--",
        ]
        return random.choice(techniques)()
    
    def generate_samples(self, count: int) -> List[Dict[str, Any]]:
        samples = []
        for _ in range(count):
            payload = self.generate_payload()
            url = f"http://example.com/search?q={payload}"
            
            sample = {
                'url': url,
                'method': random.choice(['GET', 'POST']),
                'payload': payload,
                'headers': {
                    'User-Agent': self.random_user_agent(),
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                'status_code': random.choice([200, 500, 403]),
                'response_time': random.uniform(0.1, 5.0),
                'label': self.label,
                'attack_type': 'sql'
            }
            samples.append(sample)
        return samples