import random
from typing import Dict, List, Any
from .base_engine import BaseEngine

class PathTraversalEngine(BaseEngine):
    def __init__(self, base_url: str = None):
        super().__init__('path_traversal', base_url)
        
        self.traversal_sequences = [
            '../', '..\\', '..%2f', '..%5c', '%2e%2e%2f', '%252e%252e%252f',
            '....//', '....\\\\', '..%00/', '%c0%ae%c0%ae/', '..;/'
        ]
        
        self.target_files = [
            'etc/passwd', 'etc/hosts', 'etc/shadow', 'windows/win.ini',
            'windows/system32/drivers/etc/hosts', 'proc/self/environ',
            'var/log/apache2/access.log', 'config.php', '.env', 'id_rsa',
            'WEB-INF/web.xml', 'META-INF/MANIFEST.MF'
        ]
        
        self.wrappers = [
            'file://', 'php://filter/', 'php://input',
            'expect://', 'data://', 'zip://', 'phar://'
        ]
    
    def generate_payload(self) -> str:
        traversal = random.choice(self.traversal_sequences) * random.randint(1, 5)
        target = random.choice(self.target_files)
        
        variations = [
            f"{traversal}{target}",
            f"{traversal}{traversal}{target}",
            f"{random.choice(self.wrappers)}{traversal}{target}",
            f"{traversal}{target}%00",
        ]
        
        return random.choice(variations)
    
    def generate_samples(self, count: int) -> List[Dict[str, Any]]:
        samples = []
        paths = ['/download', '/view', '/image', '/page', '/include', '/file']
        params = ['file', 'path', 'name', 'template', 'module', 'page']
        
        for _ in range(count):
            payload = self.generate_payload()
            path = random.choice(paths)
            param = random.choice(params)
            
            url = self.get_url(path=path, query=f"{param}={payload}")
            
            sample = {
                'url': url,
                'method': random.choice(['GET', 'POST']),
                'payload': payload,
                'headers': {
                    'User-Agent': self.random_user_agent(),
                },
                'status_code': random.choice([200, 403, 404, 500]),
                'response_time': random.uniform(0.1, 3.0),
                'label': self.label,
                'attack_type': 'path_traversal'
            }
            samples.append(sample)
        return samples