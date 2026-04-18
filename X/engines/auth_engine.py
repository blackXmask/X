import random
from typing import Dict, List, Any
from .base_engine import BaseEngine

class AuthEngine(BaseEngine):
    def __init__(self, base_url: str = None):
        super().__init__('auth_attack', base_url)
        
        self.usernames = ['admin', 'administrator', 'root', 'user', 'test', 'guest']
        self.passwords = ['123456', 'password', 'admin', 'root', 'qwerty']
        
        self.bypass_techniques = [
            lambda u, p: (f"{u}'--", 'anything'),
            lambda u, p: (f"{u}' OR '1'='1", 'anything'),
            lambda u, p: (f"{u}'#", 'anything'),
            lambda u, p: (f"admin'--", 'password'),
            lambda u, p: (f"{u}%00", p),
            lambda u, p: (u, ''),
            lambda u, p: ('', ''),
        ]
    
    def generate_payload(self) -> Dict[str, str]:
        user = random.choice(self.usernames)
        pwd = random.choice(self.passwords)
        technique = random.choice(self.bypass_techniques)
        return {'username': technique(user, pwd)[0], 'password': technique(user, pwd)[1]}
    
    def generate_samples(self, count: int) -> List[Dict[str, Any]]:
        samples = []
        paths = ['/login', '/auth', '/admin/login', '/signin', '/authenticate']
        
        for _ in range(count):
            creds = self.generate_payload()
            payload = f"username={creds['username']}&password={creds['password']}"
            path = random.choice(paths)
            
            url = self.get_url(path=path)
            
            sample = {
                'url': url,
                'method': 'POST',
                'payload': payload,
                'headers': {
                    'User-Agent': random.choice(['Mozilla/5.0', 'python-requests/2.28.0']),
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': str(len(payload)),
                },
                'status_code': random.choice([200, 401, 403, 302, 500]),
                'response_time': random.uniform(0.1, 2.0),
                'label': self.label,
                'attack_type': 'auth_bypass'
            }
            samples.append(sample)
        return samples