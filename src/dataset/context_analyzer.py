"""
Context Analyzer - Detects endpoint type, parameters, authentication, and security context.

This is CRITICAL for realistic vulnerability detection - context changes everything.
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs


class ContextAnalyzer:
    """Analyzes endpoint context to understand what we're testing."""
    
    def __init__(self):
        """Initialize context patterns."""
        self.api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'\.json$',
            r'\.xml$',
            r'/rest/',
            r'/graphql',
        ]
        
        self.upload_patterns = [
            r'/upload',
            r'/file',
            r'/image',
            r'/media',
            r'/attachment',
        ]
        
        self.auth_patterns = [
            r'/login',
            r'/logout',
            r'/auth',
            r'/signin',
            r'/register',
            r'/password',
        ]
        
        self.admin_patterns = [
            r'/admin',
            r'/dashboard',
            r'/management',
            r'/settings',
            r'/panel',
        ]
        
        self.id_patterns = [
            r'[?&]id=',
            r'[?&]user_?id=',
            r'[?&]product_?id=',
            r'[?&]post_?id=',
            r'/\d+$',
            r'/\d+/',
        ]
        
        self.token_patterns = [
            r'token',
            r'jwt',
            r'session',
            r'csrf',
            r'code',
            r'key',
        ]
    
    def analyze_endpoint(self, url: str, method: str, headers: Dict) -> Dict:
        """
        Analyze endpoint to determine context.
        
        Returns:
            {
                'endpoint_type': 'api/web/upload/graphql/admin',
                'is_authenticated': bool,
                'auth_type': 'cookie/jwt/session/header/none',
                'role': 'guest/user/admin',
                'has_login_form': bool,
                'has_upload_form': bool,
            }
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url = url.lower()
        
        # Detect endpoint type
        endpoint_type = self._detect_endpoint_type(path)
        
        # Detect authentication
        is_authenticated, auth_type = self._detect_authentication(headers)
        
        # Detect role
        role = self._detect_role(path, is_authenticated)
        
        # Detect form types
        has_login = any(re.search(pattern, path) for pattern in self.auth_patterns)
        has_upload = any(re.search(pattern, path) for pattern in self.upload_patterns)
        
        return {
            'endpoint_type': endpoint_type,
            'is_authenticated': is_authenticated,
            'auth_type': auth_type,
            'role': role,
            'has_login_form': has_login,
            'has_upload_form': has_upload,
            'http_method': method,
        }
    
    def analyze_parameter(self, param_name: str, url: str) -> Dict:
        """
        Analyze parameter to understand its purpose.
        
        Returns:
            {
                'param_type': 'id/token/file/json/search/filter/sort',
                'is_sensitive': bool,
                'likely_value_type': 'integer/string/uuid/email',
                'bypass_difficulty': 'easy/medium/hard',
            }
        """
        param_lower = param_name.lower()
        
        # Detect parameter type
        if any(re.search(pattern, param_name) for pattern in self.id_patterns):
            param_type = 'id'
            likely_type = 'integer'
        elif any(re.search(pattern, param_name) for pattern in self.token_patterns):
            param_type = 'token'
            likely_type = 'string'
        elif 'file' in param_lower or 'upload' in param_lower:
            param_type = 'file'
            likely_type = 'file'
        elif 'search' in param_lower or 'query' in param_lower or 'q' == param_lower:
            param_type = 'search'
            likely_type = 'string'
        elif 'filter' in param_lower or 'where' in param_lower:
            param_type = 'filter'
            likely_type = 'expression'
        elif 'sort' in param_lower or 'order' in param_lower:
            param_type = 'sort'
            likely_type = 'string'
        elif 'email' in param_lower:
            param_type = 'email'
            likely_type = 'email'
        elif 'password' in param_lower or 'pwd' in param_lower:
            param_type = 'password'
            likely_type = 'string'
        else:
            param_type = 'generic'
            likely_type = 'string'
        
        # Determine sensitivity
        sensitive_params = {'password', 'token', 'jwt', 'csrf', 'secret', 'key', 'api_key'}
        is_sensitive = param_lower in sensitive_params or any(
            s in param_lower for s in sensitive_params
        )
        
        # Bypass difficulty varies by type
        difficulty_map = {
            'id': 'easy',        # Often just numbers
            'token': 'hard',     # Encrypted/signed
            'file': 'medium',    # Needs file validation
            'search': 'medium',  # May have input validation
            'filter': 'hard',    # Complex expressions
            'sort': 'easy',      # Usually just field names
        }
        
        bypass_difficulty = difficulty_map.get(param_type, 'medium')
        
        return {
            'param_type': param_type,
            'is_sensitive': is_sensitive,
            'likely_value_type': likely_type,
            'bypass_difficulty': bypass_difficulty,
        }
    
    def detect_security_context(self, headers: Dict, response_text: str) -> Dict:
        """
        Detect security mechanisms in place.
        
        Returns CSRF, CORS, WAF, rate limiting indicators.
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # CSRF Protection
        csrf_protected = (
            'csrf' in response_text.lower() or
            'csrf-token' in headers_lower or
            'x-csrf-token' in headers_lower or
            re.search(r'_token|csrf', response_text, re.I) is not None
        )
        
        # CORS Setup
        cors_enabled = 'access-control-allow-origin' in headers_lower
        cors_origin = headers_lower.get('access-control-allow-origin', 'none')
        
        # WAF Indicators
        waf_indicators = [
            'waf',
            'cloudflare',
            'imperva',
            'akamai',
            'modsecurity',
            'barracuda'
        ]
        has_waf = any(
            waf in headers_lower.get('server', '').lower() or
            waf in response_text.lower()
            for waf in waf_indicators
        )
        
        # SSL/TLS
        if headers_lower.get('strict-transport-security'):
            ssl_enforced = True
        else:
            ssl_enforced = False
        
        return {
            'csrf_protected': csrf_protected,
            'cors_enabled': cors_enabled,
            'cors_origin': cors_origin,
            'has_waf': has_waf,
            'ssl_enforced': ssl_enforced,
            'has_secure_headers': all([
                'x-frame-options' in headers_lower,
                'x-content-type-options' in headers_lower,
                'content-security-policy' in headers_lower or 'x-xss-protection' in headers_lower
            ])
        }
    
    def _detect_endpoint_type(self, path: str) -> str:
        """Determine endpoint type from path."""
        if any(re.search(pattern, path) for pattern in self.api_patterns):
            if 'graphql' in path:
                return 'graphql'
            return 'api'
        elif any(re.search(pattern, path) for pattern in self.upload_patterns):
            return 'upload'
        elif any(re.search(pattern, path) for pattern in self.admin_patterns):
            return 'admin'
        elif any(re.search(pattern, path) for pattern in self.auth_patterns):
            return 'auth'
        else:
            return 'web'
    
    def _detect_authentication(self, headers: Dict) -> Tuple[bool, str]:
        """Detect if request is authenticated and by what method."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check Authorization header
        if 'authorization' in headers_lower:
            auth_header = headers_lower['authorization'].lower()
            if 'bearer' in auth_header:
                return True, 'jwt'
            elif 'basic' in auth_header:
                return True, 'basic'
            else:
                return True, 'token'
        
        # Check for cookies
        if 'cookie' in headers_lower:
            return True, 'cookie'
        
        # Check for session
        if 'session' in headers_lower:
            return True, 'session'
        
        return False, 'none'
    
    def _detect_role(self, path: str, is_authenticated: bool) -> str:
        """Detect user role from endpoint."""
        path_lower = path.lower()
        
        if not is_authenticated:
            return 'guest'
        
        if any(re.search(pattern, path_lower) for pattern in self.admin_patterns):
            return 'admin'
        
        # Could be user or admin - assume user by default
        return 'user'
