"""
Endpoint Intelligence Engine - Understand target endpoints for smart exploitation.

Priority 1.5: Endpoint Intent Detection
- Classify endpoint type (static, api, login, search, upload, admin, dashboard, config)
- Detect sensitivity (auth_required, user_data, payment_related, public)
- Assign risk score for prioritization
- Determine attack worthiness
"""

import re
from typing import Dict, List, Tuple


class EndpointIntelligence:
    """Analyze endpoints to understand their purpose and sensitivity."""
    
    def __init__(self):
        """Initialize endpoint patterns and risk indicators."""
        self.static_patterns = [
            r'\.(js|css|png|jpg|gif|ico|woff|ttf|svg|webp|jpg)$',
            r'/static/',
            r'/assets/',
            r'/images/',
        ]
        
        self.api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'/rest/',
            r'/graphql',
            r'\.json$',
            r'\.xml$',
        ]
        
        self.login_patterns = [
            r'/login',
            r'/signin',
            r'/auth',
            r'/authenticate',
            r'/password',
            r'/forgot',
            r'/reset',
        ]
        
        self.search_patterns = [
            r'/search',
            r'/find',
            r'/query',
            r'\?q=',
            r'\?s=',
            r'\?search=',
        ]
        
        self.upload_patterns = [
            r'/upload',
            r'/file',
            r'/image',
            r'/avatar',
            r'/profile-picture',
            r'/attachment',
            r'/media',
        ]
        
        self.admin_patterns = [
            r'/admin',
            r'/dashboard',
            r'/management',
            r'/panel',
            r'/settings',
            r'/config',
        ]
        
        self.config_patterns = [
            r'\.env',
            r'config\.json',
            r'settings\.json',
            r'/config/',
            r'/configuration/',
            r'/.well-known/',
        ]
        
        self.user_data_patterns = [
            r'/user',
            r'/profile',
            r'/account',
            r'/member',
            r'/person',
            r'/customer',
        ]
        
        self.payment_patterns = [
            r'/payment',
            r'/checkout',
            r'/cart',
            r'/order',
            r'/transaction',
            r'/credit',
            r'/billing',
            r'/stripe',
            r'/paypal',
        ]
        
    def analyze_endpoint(self, url: str, method: str = 'GET', headers: Dict = None) -> Dict:
        """
        Analyze endpoint to understand its purpose and risk.
        
        Returns:
            {
                'endpoint_type': 'static/api/login/search/upload/admin/dashboard/config/other',
                'is_sensitive': bool,
                'sensitivity_level': 'public/user_data/payment/config/unknown',
                'risk_score': 0-10,  # Higher = more important
                'should_attack': bool,
                'auth_required': bool,
                'reasoning': str,
            }
        """
        headers = headers or {}
        url_lower = url.lower()
        
        # Determine endpoint type
        endpoint_type = self._classify_endpoint_type(url_lower)
        
        # Detect sensitivity
        sensitivity_level, is_sensitive = self._detect_sensitivity(url_lower)
        
        # Check if authentication required
        auth_required = self._requires_auth(url_lower, method, headers)
        
        # Calculate risk score
        risk_score, reasoning = self._calculate_risk_score(
            endpoint_type, 
            sensitivity_level, 
            auth_required,
            url_lower
        )
        
        # Decide if worth attacking
        should_attack = risk_score >= 5 and not self._is_static(url_lower)
        
        return {
            'endpoint_type': endpoint_type,
            'is_sensitive': is_sensitive,
            'sensitivity_level': sensitivity_level,
            'risk_score': risk_score,
            'should_attack': should_attack,
            'auth_required': auth_required,
            'reasoning': reasoning,
        }
    
    def _classify_endpoint_type(self, url_lower: str) -> str:
        """Classify endpoint type (static, api, login, etc.)."""
        classification_map = [
            (['static'], 'static'),
            (['api', 'v1', 'v2', 'v3', 'rest'], 'api'),
            (['login', 'signin', 'auth'], 'login'),
            (['search', 'find', 'query'], 'search'),
            (['upload', 'file', 'avatar'], 'upload'),
            (['admin', 'dashboard'], 'dashboard'),
            (['config', 'setting'], 'config'),
        ]
        
        # Check patterns in order of priority
        for keywords, etype in classification_map:
            if any(kw in url_lower for kw in keywords):
                return etype
        
        return 'other'
    
    def _detect_sensitivity(self, url_lower: str) -> Tuple[str, bool]:
        """Detect endpoint sensitivity level."""
        # Check config first (highest sensitivity)
        if any(re.search(p, url_lower) for p in self.config_patterns):
            return 'config', True
        
        # Check payment (high sensitivity)
        if any(re.search(p, url_lower) for p in self.payment_patterns):
            return 'payment', True
        
        # Check user data (medium-high sensitivity)
        if any(re.search(p, url_lower) for p in self.user_data_patterns):
            return 'user_data', True
        
        # Check if static (public, low sensitivity)
        if self._is_static(url_lower):
            return 'public', False
        
        # Everything else
        return 'unknown', False
    
    def _is_static(self, url_lower: str) -> bool:
        """Check if endpoint is static content."""
        return any(re.search(p, url_lower) for p in self.static_patterns)
    
    def _requires_auth(self, url_lower: str, method: str, headers: Dict) -> bool:
        """Determine if endpoint requires authentication."""
        # Login endpoints don't require auth (to reach login)
        if any(re.search(p, url_lower) for p in self.login_patterns):
            return False
        
        # Check for auth headers (basic indication of protected endpoint)
        has_auth_header = any(
            k.lower() in ['authorization', 'cookie', 'x-api-key', 'x-token']
            for k in headers.keys()
        )
        
        # Admin and dashboard typically require auth
        if 'admin' in url_lower or 'dashboard' in url_lower:
            return True
        
        # User/profile/account endpoints typically require auth
        if any(re.search(p, url_lower) for p in self.user_data_patterns):
            return True
        
        return has_auth_header
    
    def _calculate_risk_score(
        self, 
        endpoint_type: str, 
        sensitivity_level: str, 
        auth_required: bool,
        url: str
    ) -> Tuple[int, str]:
        """Calculate risk score (0-10) for prioritizing attacks."""
        score = 0
        reasons = []
        
        # Endpoint type scoring
        type_scores = {
            'config': 10,
            'admin': 9,
            'dashboard': 8,
            'api': 7,
            'upload': 7,
            'user_data': 6,
            'login': 5,
            'search': 6,
            'other': 3,
            'static': 0,
        }
        score += type_scores.get(endpoint_type, 3)
        reasons.append(f"endpoint_type={endpoint_type}")
        
        # Sensitivity scoring
        sensitivity_scores = {
            'config': 10,
            'payment': 9,
            'user_data': 7,
            'unknown': 2,
            'public': 1,
        }
        score += sensitivity_scores.get(sensitivity_level, 2)
        reasons.append(f"sensitivity={sensitivity_level}")
        
        # Auth requirement (protected = higher value target)
        if auth_required:
            score += 2
            reasons.append("auth_required")
        
        # Cap at 10
        score = min(score, 10)
        
        return score, " | ".join(reasons)
    
    def rank_endpoints(self, endpoints: List[Dict], limit: int = None) -> List[Dict]:
        """
        Rank endpoints by risk score.
        
        Returns list sorted by risk_score descending.
        """
        ranked = sorted(endpoints, key=lambda e: e['risk_score'], reverse=True)
        
        if limit:
            ranked = ranked[:limit]
        
        return ranked
    
    def get_attack_surface_for_endpoint(self, endpoint_type: str) -> List[str]:
        """
        Get recommended attack types based on endpoint type.
        
        Maps endpoint to most likely vulnerability types.
        """
        attack_map = {
            'login': ['sqli', 'xss', 'brute_force', 'bypass'],
            'search': ['xss', 'sqli', 'command_injection'],
            'upload': ['file_upload', 'xxe', 'zip_slip'],
            'api': ['sqli', 'json_injection', 'ssrf', 'idor'],
            'admin': ['sqli', 'xss', 'bypass', 'idor'],
            'dashboard': ['xss', 'csrf', 'idor'],
            'config': ['file_read', 'xxe', 'directory_traversal'],
            'other': ['xss', 'sqli', 'idor'],
            'static': [],
        }
        
        return attack_map.get(endpoint_type, [])
