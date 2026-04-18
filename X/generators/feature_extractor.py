import math
import re
import random
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

class FeatureExtractor:
    SQL_KEYWORDS = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'FROM', 'WHERE', 'AND', 'OR']
    SQL_COMMENTS = ['--', '/*', '#', ';%00']
    XSS_KEYWORDS = ['script', 'alert', 'onerror', 'onload', 'javascript', 'eval', 'document.cookie']
    XSS_EVENTS = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur']
    TRAVERSAL_PATTERNS = ['../', '..\\', '..%2f', '%2e%2e', '....//']
    SSRF_PATTERNS = ['localhost', '127.0.0.1', '169.254.169.254', '0.0.0.0', '::1']
    LFI_WRAPPERS = ['file://', 'php://', 'data://', 'expect://', 'zip://']
    
    def __init__(self):
        pass
    
    def extract(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        url = sample.get('url', '')
        payload = sample.get('payload', '')
        headers = sample.get('headers', {})
        
        parsed = urlparse(url)
        query = parsed.query
        path = parsed.path
        
        features = {
            # Basic lengths
            'url_length': len(url),
            'path_length': len(path),
            'query_string_length': len(query),
            'payload_length': len(payload),
            
            # Character counts
            'special_char_count': self._count_special(url + payload),
            'digit_count': sum(c.isdigit() for c in url + payload),
            'uppercase_count': sum(c.isupper() for c in url + payload),
            'lowercase_count': sum(c.islower() for c in url + payload),
            'dot_count': url.count('.') + payload.count('.'),
            'slash_count': url.count('/') + payload.count('/'),
            
            # Encoding indicators
            'percent_encoding_count': url.count('%') + payload.count('%'),
            'null_byte_count': url.count('%00') + payload.count('\x00'),
            
            # Structure
            'path_depth': path.count('/'),
            'query_param_count': len(parse_qs(query)),
            'has_ip_in_url': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
            'is_https': 1 if url.startswith('https') else 0,
            
            # Entropy and ratios
            'payload_entropy': self._entropy(payload),
            'special_char_ratio': self._ratio(self._count_special(url + payload), len(url + payload)),
            'digit_ratio': self._ratio(sum(c.isdigit() for c in url + payload), len(url + payload)),
            
            # SQL injection
            'sql_keyword_count': self._count_patterns(url + payload, self.SQL_KEYWORDS),
            'sql_comment_sequence_count': self._count_patterns(url + payload, self.SQL_COMMENTS),
            'sql_boolean_logic_count': self._count_boolean_logic(url + payload),
            
            # NoSQL/Command
            'nosql_operator_count': self._count_nosql(url + payload),
            'command_injection_count': self._count_command_injection(url + payload),
            
            # XSS
            'xss_keyword_count': self._count_patterns(url.lower() + payload.lower(), self.XSS_KEYWORDS),
            'xss_event_handler_count': self._count_patterns(url.lower() + payload.lower(), self.XSS_EVENTS),
            'xss_context_break_count': self._count_context_breaks(url + payload),
            
            # Path traversal
            'path_traversal_sequence_count': self._count_patterns(url + payload, self.TRAVERSAL_PATTERNS),
            'path_traversal_depth': self._traversal_depth(url + payload),
            'lfi_wrapper_usage': self._count_patterns(url + payload, self.LFI_WRAPPERS),
            
            # SSRF
            'ssrf_indicator_count': self._count_patterns(url + payload, self.SSRF_PATTERNS),
            'open_redirect_param_count': self._count_redirect_params(url),
            
            # Headers
            'has_user_agent': 1 if 'User-Agent' in headers else 0,
            'user_agent_length': len(headers.get('User-Agent', '')),
            'user_agent_known_bot': self._is_known_bot(headers.get('User-Agent', '')),
            'header_order_anomaly': self._header_anomaly(headers),
            'has_cookie': 1 if 'Cookie' in headers else 0,
            'cookie_count': len(headers.get('Cookie', '').split(';')) if 'Cookie' in headers else 0,
            'has_referer': 1 if 'Referer' in headers else 0,
            'has_origin': 1 if 'Origin' in headers else 0,
            'has_authorization': 1 if 'Authorization' in headers else 0,
            
            # Security headers (simulated for generation)
            'has_content_security_policy': random.choice([0, 1]),
            'has_strict_transport_security': 1 if url.startswith('https') else 0,
            'has_x_frame_options': random.choice([0, 1]),
            
            # Response features
            'status_code': sample.get('status_code', 200),
            'response_length': random.randint(100, 50000),
            'response_time': sample.get('response_time', 0.5),
            'contains_error': 1 if sample.get('status_code', 200) >= 400 else 0,
            'is_redirect': 1 if str(sample.get('status_code', 200)).startswith('3') else 0,
            'response_entropy': random.uniform(0.5, 8.0),
            
            # Cookie security
            'secure_cookie_present': random.choice([0, 1]),
            'httponly_cookie_present': random.choice([0, 1]),
            
            # Server info
            'server_header_present': random.choice([0, 1]),
            'missing_security_headers_count': random.randint(0, 5),
            
            # Anomaly score
            'request_anomaly_score': self._calculate_anomaly(url, payload, headers),
        }
        
        return features
    
    def _count_special(self, text: str) -> int:
        return sum(1 for c in text if not c.isalnum() and not c.isspace())
    
    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum(p * math.log(p, 2) for p in prob if p > 0)
    
    def _ratio(self, count: int, total: int) -> float:
        return count / max(total, 1)
    
    def _count_patterns(self, text: str, patterns: list) -> int:
        return sum(1 for p in patterns if p.lower() in text.lower())
    
    def _count_boolean_logic(self, text: str) -> int:
        patterns = ["' or '", "' and '", "or 1=1", "and 1=1", "or '1'='1", "||", "&&"]
        return sum(1 for p in patterns if p in text.lower())
    
    def _count_nosql(self, text: str) -> int:
        patterns = ['$gt', '$ne', '$regex', '$where', '$exists', '$nin']
        return sum(1 for p in patterns if p in text)
    
    def _count_command_injection(self, text: str) -> int:
        patterns = [';', '|', '&&', '||', '`', '$(', '${', '>', '<']
        return sum(1 for p in patterns if p in text)
    
    def _count_context_breaks(self, text: str) -> int:
        return text.count('"') + text.count("'") + text.count('<') + text.count('>')
    
    def _traversal_depth(self, text: str) -> int:
        patterns = ['../', '..\\', '..%2f', '%2e%2e']
        return sum(text.count(p) for p in patterns)
    
    def _count_redirect_params(self, url: str) -> int:
        params = ['url=', 'redirect=', 'return=', 'next=', 'goto=', 'return_to=']
        return sum(1 for p in params if p in url.lower())
    
    def _is_known_bot(self, ua: str) -> int:
        bots = ['sqlmap', 'nikto', 'nmap', 'dirb', 'gobuster', 'burp', 'metasploit', 'curl', 'wget', 'python-requests']
        return 1 if any(bot in ua.lower() for bot in bots) else 0
    
    def _header_anomaly(self, headers: Dict) -> int:
        standard = ['host', 'connection', 'accept', 'user-agent']
        has_standard = sum(1 for h in standard if any(k.lower() == h for k in headers.keys()))
        return 1 if has_standard < 3 else 0
    
    def _calculate_anomaly(self, url: str, payload: str, headers: Dict) -> float:
        score = 0.0
        if len(payload) > 1000:
            score += 0.2
        if self._entropy(payload) > 6:
            score += 0.3
        if self._count_special(url + payload) > 20:
            score += 0.2
        if not headers.get('User-Agent'):
            score += 0.3
        return min(score, 1.0)