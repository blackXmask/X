"""
Parameter Analyzer - Classify parameters and estimate attack surface.

Priority 1.6: Parameter Intelligence
- Classify parameter type (id, query, file, token, email, path, json_field)
- Detect parameter behavior (reflected, numeric, ignored, sanitized)
- Estimate attack surface score for each parameter
"""

import re
from typing import Dict, List, Tuple


class ParameterAnalyzer:
    """Analyze URL/form parameters for vulnerability testing."""
    
    def __init__(self):
        """Initialize parameter patterns."""
        self.id_patterns = [
            r'id', r'user_id', r'post_id', r'product_id', r'order_id',
            r'uid', r'pid', r'oid', r'gid', r'mid'
        ]
        
        self.query_patterns = [
            r'q', r'search', r'query', r'keyword', r's', r'term', r'text'
        ]
        
        self.file_patterns = [
            r'file', r'upload', r'image', r'avatar', r'attachment', r'document'
        ]
        
        self.token_patterns = [
            r'token', r'api_key', r'secret', r'key', r'auth', r'access_token'
        ]
        
        self.email_patterns = [
            r'email', r'address', r'mail', r'contact', r'user_email'
        ]
        
        self.path_patterns = [
            r'path', r'url', r'redirect', r'return', r'goto', r'next'
        ]
        
        self.json_field_patterns = [
            r'data\[', r'json', r'content', r'body'
        ]
        
        self.sensitive_keywords = [
            'password', 'credit', 'card', 'ssn', 'secret', 'token', 'key',
            'auth', 'admin', 'permission', 'role'
        ]
    
    def analyze_parameter(self, param_name: str, url: str) -> Dict:
        """
        Analyze a single parameter.
        
        Returns:
            {
                'param_type': 'id/query/file/token/email/path/json_field/generic',
                'param_behavior': 'reflected/numeric/ignored/sanitized/unknown',
                'attack_surface_score': 0-10,
                'is_sensitive': bool,
                'recommended_attacks': ['xss', 'sqli', ...],
                'bypass_difficulty': 'easy/medium/hard',
            }
        """
        param_lower = param_name.lower()
        
        # Classify parameter type
        param_type = self._classify_parameter_type(param_name, param_lower)
        
        # Get recommended attacks for this parameter type
        recommended = self._get_attack_recommendations(param_type)
        
        # Calculate attack surface
        attack_surface_score = self._calculate_attack_surface(
            param_name,
            param_type,
            url
        )
        
        # Check if sensitive
        is_sensitive = any(
            kw in param_lower for kw in self.sensitive_keywords
        )
        
        # Estimate bypass difficulty
        bypass_difficulty = self._estimate_difficulty(param_type, param_lower)
        
        return {
            'param_type': param_type,
            'param_name': param_name,
            'attack_surface_score': attack_surface_score,
            'is_sensitive': is_sensitive,
            'recommended_attacks': recommended,
            'bypass_difficulty': bypass_difficulty,
        }
    
    def analyze_parameters_batch(self, parameters: List[str], url: str) -> List[Dict]:
        """Analyze multiple parameters and rank them by attack surface."""
        results = [self.analyze_parameter(p, url) for p in parameters]
        
        # Sort by attack_surface_score descending
        results.sort(key=lambda x: x['attack_surface_score'], reverse=True)
        
        return results
    
    def _classify_parameter_type(self, param_name: str, param_lower: str) -> str:
        """Classify parameter type."""
        if any(re.search(p, param_lower) for p in self.id_patterns):
            return 'id'
        elif any(re.search(p, param_lower) for p in self.query_patterns):
            return 'query'
        elif any(re.search(p, param_lower) for p in self.file_patterns):
            return 'file'
        elif any(re.search(p, param_lower) for p in self.token_patterns):
            return 'token'
        elif any(re.search(p, param_lower) for p in self.email_patterns):
            return 'email'
        elif any(re.search(p, param_lower) for p in self.path_patterns):
            return 'path'
        elif any(re.search(p, param_lower) for p in self.json_field_patterns):
            return 'json_field'
        else:
            return 'generic'
    
    def _get_attack_recommendations(self, param_type: str) -> List[str]:
        """Get recommended attack types for parameter type."""
        recommendations = {
            'id': ['idor', 'sqli', 'enumeration'],
            'query': ['xss', 'sqli', 'command_injection'],
            'file': ['file_upload', 'xxe', 'zip_slip'],
            'token': ['bypass', 'brute_force', 'prediction'],
            'email': ['xss', 'sqli', 'enumeration'],
            'path': ['directory_traversal', 'xxe', 'ssrf'],
            'json_field': ['sqli', 'json_injection', 'xss'],
            'generic': ['xss', 'sqli'],
        }
        
        return recommendations.get(param_type, ['xss', 'sqli'])
    
    def _calculate_attack_surface(self, param_name: str, param_type: str, url: str) -> int:
        """Calculate attack surface score (0-10) for a parameter."""
        score = 0
        param_lower = param_name.lower()
        
        # Base score by parameter type
        type_scores = {
            'id': 8,
            'token': 8,
            'path': 7,
            'query': 7,
            'json_field': 7,
            'email': 5,
            'file': 6,
            'generic': 4,
        }
        score += type_scores.get(param_type, 3)
        
        # Sensitive parameters get boost
        if any(kw in param_lower for kw in self.sensitive_keywords):
            score += 2
        
        # Parameters in query string get slight boost (more visible)
        if '?' in url and param_type in ['query', 'id', 'generic']:
            score += 1
        
        # Parameters that appear multiple times indicate importance
        if score > 0:
            score = min(score, 10)
        
        return score
    
    def _estimate_difficulty(self, param_type: str, param_lower: str) -> str:
        """Estimate how difficult it is to bypass/exploit this parameter."""
        # ID parameters are often protected
        if param_type == 'id':
            if 'user' in param_lower:
                return 'medium'  # User ID might be enumerable
            return 'hard'  # Auto-increment IDs blocked
        
        # Tokens are designed to be hard to bypass
        if param_type == 'token':
            return 'hard'
        
        # Query/search parameters usually easy
        if param_type in ['query', 'generic']:
            return 'easy'
        
        # File uploads are medium
        if param_type == 'file':
            return 'medium'
        
        # Path parameters often checked
        if param_type == 'path':
            return 'medium'
        
        # Emails can be checked
        if param_type == 'email':
            return 'medium'
        
        return 'medium'
    
    def get_priority_parameters(
        self,
        parameters: List[str],
        url: str,
        limit: int = 5
    ) -> List[Dict]:
        """Get highest-priority parameters to test."""
        analyzed = self.analyze_parameters_batch(parameters, url)
        return analyzed[:limit]
