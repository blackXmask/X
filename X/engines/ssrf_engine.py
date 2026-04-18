import random
from typing import Dict, List, Any
from .base_engine import BaseEngine

class SSREngine(BaseEngine):
    def __init__(self, base_url: str = None):
        super().__init__('ssrf', base_url)
        
        # IPv4 addresses only (can use .split('.'))
        self.internal_ipv4 = [
            '127.0.0.1',
            '0.0.0.0',
            '169.254.169.254',  # AWS metadata
            '192.168.1.1',
            '10.0.0.1',
            '172.16.0.1',
            '169.254.170.2',    # AWS ECS
        ]
        
        # IPv6 and hostnames (no dot-split obfuscation)
        self.internal_other = [
            '::1',                      # IPv6 loopback
            'localhost',
            'metadata.google.internal',
            'metadata.compute.internal',
            '[::1]',                    # bracketed IPv6
            '[::ffff:127.0.0.1]',       # IPv4-mapped IPv6
        ]
        
        self.protocols = ['http', 'https', 'file', 'ftp', 'gopher', 'dict', 'ldap']
    
    def _is_ipv4(self, addr: str) -> bool:
        """Check if address is IPv4"""
        return '.' in addr and ':' not in addr
    
    def generate_payload(self) -> str:
        # Choose between IPv4 or other
        if random.random() > 0.3:
            target = random.choice(self.internal_ipv4)
            
            # IPv4 obfuscations (safe to use .split('.'))
            obfuscations = [
                lambda x: x,  # plain
                lambda x: x.replace('.', '[.]'),  # bracket bypass
                lambda x: x.replace('.', '[dot]'),  # word bypass
                lambda x: ''.join([f'{int(o):03d}.' for o in x.split('.')]).rstrip('.'),  # decimal
                lambda x: '0x' + ''.join([hex(int(o))[2:].zfill(2) for o in x.split('.')]),  # hex
                lambda x: '.'.join([oct(int(o))[2:] for o in x.split('.')]),  # octal
            ]
            obfuscator = random.choice(obfuscations)
            target = obfuscator(target)
        else:
            target = random.choice(self.internal_other)
        
        protocol = random.choice(self.protocols)
        
        variations = [
            f"{protocol}://{target}",
            f"{protocol}://{target}:22",
            f"{protocol}://{target}:80",
            f"{protocol}://{target}:443",
            f"{protocol}://{target}:3306",
            f"{protocol}://{target}:6379",
            f"{protocol}://{target}:8080",
            f"{protocol}://user:pass@{target}",
        ]
        
        return random.choice(variations)
    
    def generate_samples(self, count: int) -> List[Dict[str, Any]]:
        samples = []
        paths = ['/fetch', '/proxy', '/webhook', '/import', '/avatar', '/load']
        params = ['url', 'target', 'callback', 'source', 'image', 'resource']
        
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
                    'Accept': '*/*',
                },
                'status_code': random.choice([200, 403, 500, 502]),
                'response_time': random.uniform(0.5, 10.0),
                'label': self.label,
                'attack_type': 'ssrf'
            }
            samples.append(sample)
        return samples