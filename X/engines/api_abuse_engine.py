import random
import json
from typing import Dict, List, Any
from .base_engine import BaseEngine

class APIAbuseEngine(BaseEngine):
    def __init__(self, base_url: str = None):
        super().__init__('api_abuse', base_url)
        
        self.endpoints = [
            '/api/users', '/api/admin', '/api/orders', '/api/payments',
            '/api/v1/users', '/api/v2/admin', '/graphql', '/rest'
        ]
    
    def generate_excessive_rate(self) -> Dict:
        return {
            'path': random.choice(self.endpoints),
            'method': 'GET',
            'headers': {'X-Forwarded-For': self.random_ip()}
        }
    
    def generate_parameter_pollution(self) -> Dict:
        return {
            'path': f"{random.choice(self.endpoints)}?id=1&id=2&id=3&admin=true",
            'method': 'GET',
            'headers': {}
        }
    
    def generate_mass_assignment(self) -> Dict:
        payload = json.dumps({
            'username': 'user',
            'password': 'pass',
            'admin': True,
            'role': 'admin'
        })
        return {
            'path': random.choice(self.endpoints),
            'method': 'POST',
            'payload': payload,
            'headers': {'Content-Type': 'application/json'}
        }
    
    def generate_broken_access(self) -> Dict:
        admin_endpoints = ['/api/admin/users', '/api/admin/config', '/api/internal']
        return {
            'path': random.choice(admin_endpoints),
            'method': random.choice(['GET', 'DELETE', 'PUT']),
            'headers': {'Authorization': 'Bearer invalid_token'}
        }
    
    def generate_samples(self, count: int) -> List[Dict[str, Any]]:
        generators = [
            self.generate_excessive_rate,
            self.generate_parameter_pollution,
            self.generate_mass_assignment,
            self.generate_broken_access,
        ]
        
        samples = []
        for _ in range(count):
            gen = random.choice(generators)
            data = gen()
            
            url = self.get_url(path=data['path'])
            
            sample = {
                'url': url,
                'method': data['method'],
                'payload': data.get('payload', ''),
                'headers': {**data['headers'], 'User-Agent': self.random_user_agent()},
                'status_code': random.choice([200, 401, 403, 429, 500]),
                'response_time': random.uniform(0.05, 0.5),
                'label': self.label,
                'attack_type': 'api_abuse'
            }
            samples.append(sample)
        return samples