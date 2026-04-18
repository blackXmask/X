import random
from typing import Dict, List, Any
from .base_engine import BaseEngine

class ReconEngine(BaseEngine):
    def __init__(self, base_url: str = None):
        super().__init__('recon', base_url)
        
        self.scan_signatures = ['nikto', 'sqlmap', 'nmap', 'dirb', 'gobuster']
        self.common_paths = ['/admin', '/api', '/.git', '/.env', '/phpmyadmin', '/wp-admin']
        self.ports = [21, 22, 80, 443, 3306, 8080, 8443]
    
    def generate_port_scan(self) -> str:
        """Generate URL with different port"""
        port = random.choice(self.ports)
        # Build URL with port manually
        return f"{self.base_url}:{port}"
    
    def generate_dir_enum(self) -> str:
        """Generate URL with sensitive path"""
        return self.get_url(path=random.choice(self.common_paths))
    
    def generate_vuln_scan(self) -> str:
        """Generate URL with test payload"""
        payloads = ["' AND 1=1", "<script>alert(1)</script>", "../../../etc/passwd"]
        return self.get_url(path='/search', query=f"q={random.choice(payloads)}")
    
    def generate_samples(self, count: int) -> List[Dict[str, Any]]:
        samples = []
        scan_types = [
            ('port_scan', self.generate_port_scan),
            ('dir_enum', self.generate_dir_enum),
            ('vuln_scan', self.generate_vuln_scan),
        ]
        
        for _ in range(count):
            scan_type, generator = random.choice(scan_types)
            url = generator()
            
            ua = self.random_user_agent()
            if random.random() > 0.7:
                ua = random.choice(self.scan_signatures)
            
            sample = {
                'url': url,
                'method': random.choice(['GET', 'HEAD', 'OPTIONS']),
                'payload': '',
                'headers': {'User-Agent': ua, 'Accept': '*/*'},
                'status_code': random.choice([200, 301, 302, 403, 404]),
                'response_time': random.uniform(0.05, 1.0),
                'label': self.label,
                'attack_type': scan_type
            }
            samples.append(sample)
        return samples