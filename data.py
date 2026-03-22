#C:\Users\p7inc3\AppData\Local\Programs\Python\Python312\python.exe data.py
import asyncio
import aiohttp
import aiofiles
import json
import csv
import re
import hashlib
import time
import os
import ssl
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
from datetime import datetime
from typing import Set, Dict, List, Optional, Any

class VulnerabilityDataCollector:
    def __init__(self, config_path: str = "config.json"):
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.visited_urls: Set[str] = set()
        self.results: List[Dict] = []
        self.stats = {'requests': 0, 'vulns': 0, 'errors': 0}
        
        # Create output dir if needed
        if self.config['output']['save_raw_responses']:
            os.makedirs(self.config['output']['response_dir'], exist_ok=True)

    async def init_session(self):
        """Initialize HTTP session"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            limit=self.config['scanning']['concurrent_requests'],
            limit_per_host=5,
            ssl=ssl_context
        )
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate'
        }
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=self.config['scanning']['timeout'])
        )

    def load_urls(self) -> List[str]:
        """Load target URLs from config"""
        urls = set(self.config['targets']['urls'])
        
        # Load from file if exists
        url_file = self.config['targets']['url_file']
        if os.path.exists(url_file):
            with open(url_file, 'r') as f:
                file_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                urls.update(file_urls)
        
        return list(urls)[:self.config['targets']['max_urls']]

    async def crawl(self, url: str, depth: int = 0) -> Set[str]:
        """Smart crawler with form/JS detection"""
        max_depth = self.config['targets'].get('max_depth', 2)
        if (max_depth >= 0 and depth > max_depth) or url in self.visited_urls:
            return set()
        
        self.visited_urls.add(url)
        discovered = {url}
        
        try:
            async with self.session.get(url, allow_redirects=self.config['scanning']['follow_redirects']) as resp:
                if 'text/html' not in resp.headers.get('Content-Type', ''):
                    return discovered
                
                text = await resp.text()
                soup = BeautifulSoup(text, 'html.parser')
                
                # Extract all links
                for tag in soup.find_all(['a', 'link', 'script', 'iframe', 'img', 'form']):
                    href = tag.get('href') or tag.get('src') or tag.get('action')
                    if href:
                        full_url = urljoin(url, href)
                        if self._same_domain(full_url, url) and not self._should_skip_url(full_url):
                            discovered.add(full_url)
                
                # Extract inline API endpoints from JS
                scripts = ' '.join([s.string for s in soup.find_all('script') if s.string])
                api_endpoints = re.findall(r'["\'](/api/[a-zA-Z0-9/_-]+)["\']', scripts)
                for endpoint in api_endpoints:
                    discovered.add(urljoin(url, endpoint))
                
        except Exception as e:
            pass
        
        return discovered

    def _same_domain(self, url1: str, url2: str) -> bool:
        return urlparse(url1).netloc == urlparse(url2).netloc

    async def _send_baseline_request(self, url: str) -> Optional[Dict]:
        """Send baseline request without payload for comparison"""
        try:
            async with self.session.get(url) as resp:
                if 'text/html' not in resp.headers.get('Content-Type', ''):
                    return None
                text = await resp.text()
                return {
                    'status': resp.status,
                    'size': len(text),
                    'hash': hashlib.sha256(text.encode()).hexdigest()[:16],
                    'content': text[:1000]  # Store first 1000 chars for diff
                }
        except:
            return None

    async def _extract_form_params(self, url: str) -> List[str]:
        """Extract form input names from HTML"""
        try:
            async with self.session.get(url) as resp:
                if 'text/html' not in resp.headers.get('Content-Type', ''):
                    return []
                text = await resp.text()
                soup = BeautifulSoup(text, 'html.parser')
                inputs = soup.find_all('input', {'name': True})
                return [inp['name'] for inp in inputs if inp['name']]
        except:
            return []

    def _should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped (non-text content)"""
        skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg',
            '.pdf', '.zip', '.exe', '.dll', '.bin',
            '.mp4', '.mp3', '.avi', '.mov', '.wmv',
            '.css', '.woff', '.woff2', '.ttf', '.eot',
            '.ico', '.manifest'
        }
        parsed = urlparse(url.lower())
        path = parsed.path
        return any(path.endswith(ext) for ext in skip_extensions)

    def _analyze_security_headers(self, headers: Dict) -> Dict:
        """Extract security header features"""
        h = {k.lower(): v for k, v in headers.items()}
        return {
            'x_frame_options': headers.get('X-Frame-Options', 'missing'),
            'csp': headers.get('Content-Security-Policy', 'missing'),
            'hsts': headers.get('Strict-Transport-Security', 'missing'),
            'x_content_type': headers.get('X-Content-Type-Options', 'missing'),
            'x_xss_protection': headers.get('X-XSS-Protection', 'missing'),
            'referrer_policy': headers.get('Referrer-Policy', 'missing'),
            'cors_origin': headers.get('Access-Control-Allow-Origin', 'none'),
            'server': headers.get('Server', 'unknown'),
            'has_secure_headers': all([
                'X-Frame-Options' in headers,
                'X-Content-Type-Options' in headers,
                'X-XSS-Protection' in headers
            ])
        }

    def _analyze_cookies(self, cookies: List[str]) -> Dict:
        """Analyze cookie security"""
        if not cookies:
            return {'secure': False, 'httponly': False, 'samesite': 'none', 'count': 0}
        
        cookie_str = ';'.join(cookies).lower()
        return {
            'secure': 'secure' in cookie_str,
            'httponly': 'httponly' in cookie_str,
            'samesite': 'strict' if 'samesite=strict' in cookie_str else ('lax' if 'samesite=lax' in cookie_str else 'none'),
            'count': len(cookies)
        }

    def _detect_vulnerability(self, payload_type: str, response: str, status: int, response_time: float) -> Dict:
        """Multi-layer detection logic"""
        result = {
            'detected': False,
            'type': 'none',
            'severity': 'info',
            'confidence': 0.0,
            'evidence': '',
            'false_positive_risk': 'low'
        }
        
        patterns = self.config['detection']['error_patterns']
        
        # Check error-based detection
        if payload_type == 'sqli' and re.search(patterns['sql'], response, re.I):
            result.update({
                'detected': True,
                'type': 'SQL Injection',
                'severity': 'critical',
                'confidence': 0.95,
                'evidence': 'SQL error pattern detected in response'
            })
        
        elif payload_type == 'xss' and re.search(patterns['xss'], response, re.I):
            result.update({
                'detected': True,
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'high',
                'confidence': 0.9,
                'evidence': 'XSS payload reflected in response'
            })
        
        elif payload_type == 'command' and re.search(patterns['command'], response, re.I):
            result.update({
                'detected': True,
                'type': 'Command Injection',
                'severity': 'critical',
                'confidence': 0.92,
                'evidence': 'Command output detected in response'
            })
        
        elif payload_type == 'path_traversal' and re.search(patterns['path'], response, re.I):
            result.update({
                'detected': True,
                'type': 'Path Traversal',
                'severity': 'high',
                'confidence': 0.88,
                'evidence': 'System file content detected'
            })
        
        elif payload_type == 'ssrf' and re.search(patterns['ssrf'], response, re.I):
            result.update({
                'detected': True,
                'type': 'Server-Side Request Forgery (SSRF)',
                'severity': 'high',
                'confidence': 0.85,
                'evidence': 'Internal/Cloud metadata accessed'
            })
        
        elif payload_type == 'idor' and re.search(patterns['idor'], response, re.I):
            result.update({
                'detected': True,
                'type': 'Insecure Direct Object Reference (IDOR)',
                'severity': 'medium',
                'confidence': 0.75,
                'evidence': 'Sensitive data accessible with modified ID',
                'false_positive_risk': 'medium'
            })
        
        elif payload_type == 'xxe' and re.search(patterns['xxe'], response, re.I):
            result.update({
                'detected': True,
                'type': 'XML External Entity (XXE)',
                'severity': 'high',
                'confidence': 0.85,
                'evidence': 'External entity content leaked in response'
            })
        
        elif payload_type == 'ssti' and re.search(patterns['ssti'], response, re.I):
            result.update({
                'detected': True,
                'type': 'Server-Side Template Injection (SSTI)',
                'severity': 'critical',
                'confidence': 0.9,
                'evidence': 'Template injection executed successfully'
            })
        
        # Time-based detection for blind injection
        if not result['detected'] and response_time > self.config['detection']['slow_threshold']:
            if payload_type in ['sqli', 'command']:
                result.update({
                    'detected': True,
                    'type': f'Time-based {payload_type.upper()}',
                    'severity': 'high',
                    'confidence': 0.7,
                    'evidence': f'Delayed response ({response_time:.2f}s) indicates time-based injection',
                    'false_positive_risk': 'high'
                })
        
        return result

    def _extract_features(self, url: str, method: str, payload: str, 
                         response: str, headers: Dict, response_time: float, status: int) -> Dict:
        """Generate ML-ready features"""
        
        # Text features (cleaned for NLP)
        text_clean = re.sub(r'<[^>]+>', ' ', response)
        text_clean = re.sub(r'\s+', ' ', text_clean).strip()[:500]
        
        # Extract error snippets
        error_snippets = []
        for pattern in self.config['detection']['error_patterns'].values():
            matches = re.findall(pattern, response, re.I)
            error_snippets.extend(matches[:2])
        
        # Numeric features
        numeric = [
            len(response),  # response_size
            response_time,  # response_time
            response.count('\n'),  # line_count
            len(re.findall(r'<script', response, re.I)),  # script_tags
            len(re.findall(r'<input', response, re.I)),  # input_fields
            len(re.findall(r'https?://', response)),  # external_links
            response.lower().count('error'),  # error_keyword_count
            response.lower().count('warning'),  # warning_count
            int('login' in response.lower()),  # has_login_form
            int('admin' in response.lower()),  # has_admin_ref
            int(response_time > self.config['detection']['slow_threshold']),  # is_slow
            status  # response_status
        ]
        
        # Content type category
        content_type = headers.get('Content-Type', 'unknown').split(';')[0]
        
        # Categorical features
        categorical = [
            method,
            content_type,
            'https' if urlparse(url).scheme == 'https' else 'http',
            'json' if response.strip().startswith(('{', '[')) else ('xml' if response.strip().startswith('<') else 'html'),
            'has_error' if error_snippets else 'clean'
        ]
        
        # Semantic hash (structural fingerprint)
        structure = re.sub(r'>[^<]+<', '><', response)
        semantic_hash = hashlib.md5(structure.encode()).hexdigest()[:16]
        
        return {
            'text_features': text_clean,
            'error_patterns': '|'.join(set(error_snippets))[:200],
            'numeric_features': json.dumps(numeric),
            'categorical_features': json.dumps(categorical),
            'semantic_hash': semantic_hash,
            'payload_hash': hashlib.md5(payload.encode()).hexdigest()[:8]
        }

    async def test_payload(self, url: str, method: str, param: str, 
                          payload: str, payload_type: str, baseline_response: Optional[Dict] = None) -> Optional[Dict]:
        """Test single payload and collect data"""
        start_time = time.time()
        scan_id = hashlib.md5(f"{url}{method}{payload}{time.time()}".encode()).hexdigest()[:12]
        
        try:
            # Construct request based on method
            is_api = '/api/' in url or url.endswith('.json') or 'application/json' in str(self.session.headers.get('Accept', ''))
            
            if method == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = payload
                new_query = urlencode(params, doseq=True)
                target_url = parsed._replace(query=new_query).geturl()
                resp = await self.session.get(target_url)
            
            elif method in ['POST', 'PUT']:
                if is_api:
                    # Send JSON payload for API endpoints
                    data = {param: payload}
                    headers = {'Content-Type': 'application/json'}
                    resp = await self.session.request(method, url, json=data, headers=headers)
                else:
                    # Send form data for regular endpoints
                    data = {param: payload}
                    resp = await self.session.request(method, url, data=data)
            
            else:
                resp = await self.session.request(method, url)
            
            response_time = time.time() - start_time
            self.stats['requests'] += 1
            
            response_text = await resp.text()
            response_hash = hashlib.sha256(response_text.encode()).hexdigest()[:16]
            
            # Baseline comparison
            baseline_diff = 0
            baseline_content_changed = False
            baseline_status_changed = False
            if baseline_response:
                baseline_diff = len(response_text) - baseline_response['size']
                baseline_content_changed = response_hash != baseline_response['hash']
                baseline_status_changed = resp.status != baseline_response['status']
            
            # Security analysis
            sec_headers = self._analyze_security_headers(dict(resp.headers))
            cookies = self._analyze_cookies(resp.headers.getall('Set-Cookie', []))
            
            # Vulnerability detection
            vuln = self._detect_vulnerability(payload_type, response_text, resp.status, response_time)
            
            # Feature extraction
            features = self._extract_features(url, method, payload, response_text, dict(resp.headers), response_time, resp.status)
            
            # New features: payload reflection and exploit confirmation
            payload_reflected = payload in response_text
            payload_transformed = quote(payload) in response_text or payload.replace(' ', '%20') in response_text
            exploit_confirmed = vuln['detected'] and vuln['confidence'] >= 0.9
            
            # Save raw response if significant
            if self.config['output']['save_raw_responses'] and vuln['detected']:
                async with aiofiles.open(f"{self.config['output']['response_dir']}/{scan_id}.txt", 'w') as f:
                    await f.write(response_text[:5000])
            
            if vuln['detected']:
                self.stats['vulns'] += 1
            
            # Compile comprehensive record
            record = {
                # IDs & Timestamps
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat(),
                'dataset_version': '1.0',
                
                # Target Info
                'target_url': url,
                'base_domain': urlparse(url).netloc,
                'endpoint_path': urlparse(url).path,
                'depth_level': 0,  # Will be set by crawler
                'is_api_endpoint': is_api,
                
                # Request Details
                'http_method': method,
                'tested_parameter': param,
                'payload': payload,
                'payload_type': payload_type,
                'payload_encoded': quote(payload),
                'attack_vector': 'url_param' if method == 'GET' else 'body',
                
                # Response Details
                'response_status': resp.status,
                'response_time_ms': round(response_time * 1000, 2),
                'response_size_bytes': len(response_text),
                'response_hash': response_hash,
                'content_type': resp.headers.get('Content-Type', 'unknown'),
                
                # Security Headers (Individual fields for AI)
                'header_x_frame': sec_headers['x_frame_options'],
                'header_csp': sec_headers['csp'],
                'header_hsts': sec_headers['hsts'],
                'header_x_content_type': sec_headers['x_content_type'],
                'header_xss_protection': sec_headers['x_xss_protection'],
                'header_referrer': sec_headers['referrer_policy'],
                'header_cors': sec_headers['cors_origin'],
                'server_tech': sec_headers['server'],
                'secure_headers_present': sec_headers['has_secure_headers'],
                
                # Cookie Security
                'cookie_secure_flag': cookies['secure'],
                'cookie_httponly_flag': cookies['httponly'],
                'cookie_samesite': cookies['samesite'],
                'cookie_count': cookies['count'],
                
                # Vulnerability Detection (Target variable + features)
                'vulnerability_detected': vuln['detected'],
                'vulnerability_type': vuln['type'],
                'vulnerability_severity': vuln['severity'],
                'confidence_score': vuln['confidence'],
                'evidence': vuln['evidence'],
                'false_positive_risk': vuln['false_positive_risk'],
                'exploit_confirmed': exploit_confirmed,
                
                # Payload Analysis
                'payload_reflected': payload_reflected,
                'payload_transformed': payload_transformed,
                
                # ML Features
                'text_features': features['text_features'],
                'error_pattern_matches': features['error_patterns'],
                'numeric_features_vector': features['numeric_features'],
                'categorical_features_vector': features['categorical_features'],
                'semantic_structure_hash': features['semantic_hash'],
                'payload_fingerprint': features['payload_hash'],
                
                # Behavioral Analysis
                'status_changed': baseline_status_changed,
                'content_changed': baseline_content_changed,
                'baseline_size_diff': baseline_diff,
                'time_anomaly': response_time > self.config['detection']['slow_threshold'],
                
                # Context
                'requires_authentication': resp.status == 401,
                'is_redirect': resp.status in [301, 302, 307, 308],
                'is_error_page': resp.status >= 400,
                
                # Raw Data (Optional, for debugging)
                'response_preview': response_text[:500].replace('\n', ' ').replace('\r', ''),
                'request_headers': str(dict(resp.request_info.headers)),
            }
            
            return record
            
        except asyncio.TimeoutError:
            self.stats['errors'] += 1
            return None
        except Exception as e:
            self.stats['errors'] += 1
            return None

    async def analyze_javascript(self, url: str) -> Optional[Dict]:
        """Static analysis of JS files"""
        if not url.endswith('.js'):
            return None
        
        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return None
                
                js_code = await resp.text()
                
                # Analysis
                findings = {
                    'api_endpoints': re.findall(r'["\'](/api/[a-zA-Z0-9/_-]+)["\']', js_code),
                    'secrets': re.findall(r'(api[_-]?key|secret|token|password)\s*[:=]\s*["\']([^"\']+)["\']', js_code, re.I),
                    'dom_xss': len(re.findall(r'(innerHTML|outerHTML|document\.write|eval\()', js_code)),
                    'postmessage': len(re.findall(r'postMessage\(', js_code)),
                    'websocket': len(re.findall(r'new\s+WebSocket\(', js_code)),
                    'dangerous_eval': len(re.findall(r'eval\s*\(', js_code)),
                    'jquery_present': 'jquery' in js_code.lower(),
                    'react_present': 'react' in js_code.lower(),
                    'size_kb': len(js_code) / 1024
                }
                
                # Determine if vulnerable
                is_vulnerable = any([
                    len(findings['secrets']) > 0,
                    findings['dom_xss'] > 0,
                    findings['dangerous_eval'] > 0
                ])
                
                return {
                    'scan_id': hashlib.md5(url.encode()).hexdigest()[:12],
                    'timestamp': datetime.now().isoformat(),
                    'target_url': url,
                    'base_domain': urlparse(url).netloc,
                    'endpoint_path': urlparse(url).path,
                    'http_method': 'GET',
                    'tested_parameter': 'js_analysis',
                    'payload': 'static_analysis',
                    'payload_type': 'code_review',
                    'attack_vector': 'client_side',
                    
                    'response_status': 200,
                    'response_time_ms': 0,
                    'response_size_bytes': len(js_code),
                    
                    'vulnerability_detected': is_vulnerable,
                    'vulnerability_type': 'Client-Side Vulnerability' if is_vulnerable else 'None',
                    'vulnerability_severity': 'high' if findings['secrets'] else ('medium' if findings['dom_xss'] > 0 else 'info'),
                    'confidence_score': 0.9 if findings['secrets'] else 0.7,
                    'evidence': f"Secrets:{len(findings['secrets'])}, DOM_XSS:{findings['dom_xss']}, Eval:{findings['dangerous_eval']}",
                    
                    'js_api_endpoints': '|'.join(findings['api_endpoints'][:10]),
                    'js_secrets_found': len(findings['secrets']),
                    'js_dom_sinks': findings['dom_xss'],
                    'js_framework': 'jquery' if findings['jquery_present'] else ('react' if findings['react_present'] else 'vanilla'),
                    'js_size_kb': round(findings['size_kb'], 2),
                    
                    'text_features': js_code[:500],
                    'numeric_features_vector': json.dumps([
                        findings['size_kb'],
                        findings['dom_xss'],
                        findings['dangerous_eval'],
                        len(findings['api_endpoints']),
                        len(findings['secrets'])
                    ]),
                    'categorical_features_vector': json.dumps(['js', 'static', 'analysis']),
                    'semantic_structure_hash': hashlib.md5(js_code[:1000].encode()).hexdigest()[:16],
                    
                    # Fill other fields with defaults
                    'payload_encoded': '',
                    'response_hash': '',
                    'content_type': 'application/javascript',
                    'header_x_frame': 'N/A',
                    'header_csp': 'N/A',
                    'header_hsts': 'N/A',
                    'header_x_content_type': 'N/A',
                    'header_xss_protection': 'N/A',
                    'header_referrer': 'N/A',
                    'header_cors': 'N/A',
                    'server_tech': resp.headers.get('Server', 'unknown'),
                    'secure_headers_present': False,
                    'cookie_secure_flag': False,
                    'cookie_httponly_flag': False,
                    'cookie_samesite': 'none',
                    'cookie_count': 0,
                    'error_pattern_matches': '',
                    'payload_fingerprint': '',
                    'time_anomaly': False,
                    'requires_authentication': False,
                    'is_redirect': False,
                    'is_error_page': False,
                    'response_preview': js_code[:300],
                    'request_headers': '',
                    'dataset_version': '1.0',
                    'depth_level': 0,
                    'status_changed': False,
                    'content_changed': False,
                    'false_positive_risk': 'low'
                }
        except:
            return None

    async def scan_single_url(self, url: str, depth: int = 0):
        """Comprehensive scan of single URL"""
        # Skip non-scannable file types
        if self._should_skip_url(url):
            return
        
        print(f"[+] Scanning: {url} (Depth: {depth})")
        
        # Send baseline request (no payload)
        baseline_response = await self._send_baseline_request(url)
        
        # Parse forms for real parameter names
        form_params = await self._extract_form_params(url)
        
        # Determine parameters to test
        parsed = urlparse(url)
        query_params = list(parse_qs(parsed.query).keys())
        
        # Combine query params and form params
        all_params = set(query_params + form_params)
        if not all_params:
            all_params = {'fuzz'}  # Default param if none found
        
        max_depth = self.config['targets'].get('max_depth', 2)
        # First, crawl for more URLs if depth permits
        if max_depth < 0 or depth < max_depth:
            discovered = await self.crawl(url, depth)
            for new_url in discovered:
                if new_url != url:
                    await self.scan_single_url(new_url, depth + 1)
        
        # Test each payload type
        methods = ['GET', 'POST']
        
        for method in methods:
            for param_name in all_params:
                for payload_type, payloads in self.config['payloads'].items():
                    for payload in payloads:
                        await asyncio.sleep(self.config['scanning']['delay'])
                        result = await self.test_payload(url, method, param_name, payload, payload_type, baseline_response)
                        if result:
                            result['depth_level'] = depth
                            result['form_params_count'] = len(form_params)
                            self.results.append(result)
        
        # JavaScript analysis if applicable
        if self.config['ai_features']['extract_js'] and url.endswith('.js'):
            js_result = await self.analyze_javascript(url)
            if js_result:
                self.results.append(js_result)
        
        # API endpoint testing (if URL looks like API)
        if '/api/' in url or url.endswith('.json'):
            # Additional API-specific tests would go here
            pass

    async def run(self):
        """Main execution"""
        await self.init_session()
        
        try:
            urls = self.load_urls()
            print(f"[*] Loaded {len(urls)} target URLs")
            
            # Process with semaphore for concurrency
            sem = asyncio.Semaphore(self.config['scanning']['concurrent_requests'])
            
            async def bounded_scan(url):
                async with sem:
                    await self.scan_single_url(url)
            
            await asyncio.gather(*[bounded_scan(url) for url in urls])
            
        finally:
            await self.session.close()
            self.save_csv()
            
            # Print stats
            print(f"\n[+] Scan Complete!")
            print(f"    Total Requests: {self.stats['requests']}")
            print(f"    Vulnerabilities: {self.stats['vulns']}")
            print(f"    Errors: {self.stats['errors']}")
            print(f"    Dataset saved to: {self.config['output']['csv_file']}")

    def save_csv(self):
        """Save results to CSV"""
        if not self.results:
            print("[!] No results to save")
            return
        
        output_file = self.config['output']['csv_file']
        fieldnames = list(self.results[0].keys())
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)
        
        print(f"[+] Saved {len(self.results)} records to {output_file}")

if __name__ == "__main__":
    collector = VulnerabilityDataCollector()
    asyncio.run(collector.run())