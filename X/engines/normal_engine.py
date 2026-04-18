import random
from typing import Dict, List, Any
from .base_engine import BaseEngine

class NormalEngine(BaseEngine):
    def __init__(self, base_url: str = None):
        super().__init__('normal', base_url)
        
        self.paths = [
            '/', '/home', '/about', '/contact', '/products', '/services',
            '/blog', '/news', '/help', '/faq', '/terms', '/privacy',
            '/login', '/register', '/profile', '/settings', '/dashboard',
            '/search', '/cart', '/checkout', '/orders', '/history',
            '/api/users/profile', '/api/products/list', '/api/search',
            '/team', '/careers', '/pricing', '/features', '/docs',
            '/download', '/support', '/feedback', '/subscribe'
        ]
        
        self.search_terms = [
            'laptop', 'phone', 'shoes', 'book', 'tutorial', 'python',
            'javascript', 'security', 'machine learning', 'news',
            'weather today', 'restaurants near me', 'how to code',
            'best practices', 'getting started', 'documentation',
            'api reference', 'user guide', 'example project'
        ]
        
        self.content_types = [
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'application/json, text/plain, */*',
            'text/html,application/xhtml+xml,application/xml;q=0.9'
        ]
        
        self.accept_languages = [
            'en-US,en;q=0.9',
            'en-GB,en;q=0.9',
            'en-US,en;q=0.8,es;q=0.6',
            'fr-FR,fr;q=0.9,en;q=0.8',
            'de-DE,de;q=0.9,en;q=0.7'
        ]
        
        self.referers = [
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://www.facebook.com/',
            'https://twitter.com/',
            'https://www.linkedin.com/',
            'https://www.reddit.com/',
            'https://www.youtube.com/',
            'https://stackoverflow.com/',
            '/',
            '/home',
            '/blog',
            '/products'
        ]
    
    def generate_normal_request(self) -> Dict[str, Any]:
        path = random.choice(self.paths)
        
        # 30% chance of search query
        if 'search' in path or random.random() > 0.7:
            query = random.choice(self.search_terms)
            url = self.get_url(path=path, query=f"q={query.replace(' ', '+')}")
        else:
            url = self.get_url(path=path)
        
        # Randomize headers for realism
        headers = {
            'User-Agent': self.random_user_agent(),
            'Accept': random.choice(self.content_types),
            'Accept-Language': random.choice(self.accept_languages),
            'Accept-Encoding': random.choice(['gzip, deflate, br', 'gzip, deflate']),
            'Referer': random.choice(self.referers) if random.random() > 0.3 else self.get_url('/'),
            'Connection': 'keep-alive',
        }
        
        # Sometimes add extra headers
        if random.random() > 0.5:
            headers['DNT'] = '1'
        if random.random() > 0.7:
            headers['Upgrade-Insecure-Requests'] = '1'
        
        return {
            'url': url,
            'method': 'GET' if random.random() > 0.15 else 'POST',
            'payload': '',
            'headers': headers,
            'status_code': 200,
            'response_time': random.uniform(0.05, 0.8),
            'label': self.label,
            'attack_type': 'normal'
        }
    
    def generate_post_request(self) -> Dict[str, Any]:
        """Generate POST request for forms (login, contact, etc.)"""
        post_paths = ['/login', '/register', '/contact', '/subscribe', '/feedback', '/api/login']
        path = random.choice(post_paths)
        
        # Generate realistic POST data
        if 'login' in path:
            payload = f"username=user{random.randint(1,9999)}&password={self.random_string(12)}"
        elif 'register' in path:
            payload = f"email=user{random.randint(1,9999)}@email.com&password={self.random_string(12)}&confirm_password={self.random_string(12)}"
        elif 'contact' in path:
            payload = f"name=John Doe&email=john{random.randint(1,999)}@email.com&message=Hello, I have a question about your services."
        elif 'subscribe' in path:
            payload = f"email=subscriber{random.randint(1,9999)}@email.com"
        else:
            payload = f"data={self.random_string(20)}&timestamp={random.randint(1000000, 9999999)}"
        
        return {
            'url': self.get_url(path=path),
            'method': 'POST',
            'payload': payload,
            'headers': {
                'User-Agent': self.random_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': random.choice(self.accept_languages),
                'Accept-Encoding': 'gzip, deflate, br',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': str(len(payload)),
                'Origin': self.base_url,
                'Referer': self.get_url(path),
            },
            'status_code': random.choice([200, 302, 201]),
            'response_time': random.uniform(0.1, 1.2),
            'label': self.label,
            'attack_type': 'normal'
        }
    
    def generate_api_request(self) -> Dict[str, Any]:
        """Generate normal API request"""
        api_paths = ['/api/users', '/api/products', '/api/search', '/api/v1/data']
        path = random.choice(api_paths)
        
        headers = {
            'User-Agent': random.choice([
                'Mozilla/5.0 (compatible; MyApp/1.0)',
                'PostmanRuntime/7.28.4',
                'okhttp/4.9.0'
            ]),
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Authorization': f'Bearer eyJhbGciOiJIUzI1NiIs{self.random_string(20)}',
            'Content-Type': 'application/json',
        }
        
        return {
            'url': self.get_url(path=path),
            'method': random.choice(['GET', 'GET', 'POST', 'GET']),  # Mostly GET
            'payload': '' if random.random() > 0.3 else '{"limit": 10, "offset": 0}',
            'headers': headers,
            'status_code': 200,
            'response_time': random.uniform(0.05, 0.5),
            'label': self.label,
            'attack_type': 'normal'
        }
    
    def generate_samples(self, count: int) -> List[Dict[str, Any]]:
        samples = []
        
        # Mix of request types
        generators = [
            (self.generate_normal_request, 0.6),      # 60% normal browsing
            (self.generate_post_request, 0.25),       # 25% form submissions
            (self.generate_api_request, 0.15),        # 15% API calls
        ]
        
        for _ in range(count):
            # Weighted random choice
            r = random.random()
            cumulative = 0
            chosen_generator = generators[0][0]
            
            for generator, weight in generators:
                cumulative += weight
                if r <= cumulative:
                    chosen_generator = generator
                    break
            
            samples.append(chosen_generator())
        
        return samples