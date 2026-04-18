import random
from typing import Dict, List, Any
from .base_engine import BaseEngine

class XSSEngine(BaseEngine):
    def __init__(self, base_url: str = None):  # <-- ADD base_url
        super().__init__('xss', base_url)  # <-- PASS to parent
        
        self.xss_vectors = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<body onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<details open ontoggle=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            "';alert(1);//",
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
        ]
        
        self.event_handlers = [
            'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus',
            'onblur', 'onchange', 'onsubmit', 'onkeydown', 'ontoggle'
        ]
    
    def generate_payload(self) -> str:
        vector = random.choice(self.xss_vectors)
        encodings = [
            lambda x: x,
            lambda x: x.replace('<', '%3C').replace('>', '%3E'),
            lambda x: x.upper(),
            lambda x: x.lower(),
        ]
        encoder = random.choice(encodings)
        return encoder(vector)
    
    def generate_samples(self, count: int) -> List[Dict[str, Any]]:
        samples = []
        paths = ['/search', '/comment', '/profile', '/post', '/message']
        
        for _ in range(count):
            payload = self.generate_payload()
            path = random.choice(paths)
            param = random.choice(['q', 'text', 'name', 'message', 'content'])
            
            url = self.get_url(path=path, query=f"{param}={payload}")
            
            sample = {
                'url': url,
                'method': random.choice(['GET', 'POST']),
                'payload': payload,
                'headers': {
                    'User-Agent': self.random_user_agent(),
                    'Referer': self.get_url('/'),
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                'status_code': random.choice([200, 403, 500]),
                'response_time': random.uniform(0.1, 2.0),
                'label': self.label,
                'attack_type': 'xss'
            }
            samples.append(sample)
        return samples