"""
Prioritization Engine - Focus on High-Value Targets First

Transforms the scanner from "analyze everything equally" to "focus on 
high-value targets first like real hackers do."

Real-world behavior:
- /admin → HIGH priority (likely sensitive, restricted access)
- /api → HIGH priority (structured endpoints, data-rich)
- /login → MEDIUM priority (business logic bypass)
- style.css → LOW priority (unlikely vulnerable)
- robots.txt → LOW priority (metadata only)

Architecture:
- Priority Score: 0-10 rating for each endpoint
- Attack Order: Which endpoints to test first
- Value Assessment: Data sensitivity, access controls, business impact
"""

from typing import Dict, List, Tuple, Any
from enum import Enum


class TargetValueEnum(Enum):
    """Categorizes endpoint value for targeting."""
    CRITICAL = 10      # Admin panels, config endpoints
    HIGH = 8           # APIs, user management, payment
    MEDIUM = 5         # Forms, search, public features
    LOW = 2            # Static assets, public info
    IGNORE = 0         # robots.txt, sitemap.xml


class PrioritizationEngine:
    """
    Intelligent prioritization system that ranks targets by value.
    
    Focuses scanner effort on high-value endpoints where real bugs exist.
    Learns to ignore low-value targets and prioritize critical infrastructure.
    
    Attributes:
        priority_scores: Dict mapping endpoint → priority_score (0-10)
        attack_order: Ordered list of endpoints by attack priority
        value_map: Cached mapping of endpoint patterns to value ratings
    """
    
    def __init__(self):
        """Initialize the prioritization engine."""
        self.priority_scores: Dict[str, float] = {}
        self.attack_order: List[Tuple[str, float]] = []
        
        # Pattern-based value assessment
        self.critical_indicators = {
            '/admin': 10,
            '/api/admin': 10,
            '.env': 10,
            'config': 9,
            'setting': 8,
            '/api': 8,
            'internal': 8,
            'management': 7,
        }
        
        self.high_value_indicators = {
            '/user': 8,
            '/profile': 8,
            '/account': 8,
            'payment': 8,
            'cart': 7,
            'transaction': 7,
            '/api/v': 8,
            'auth': 7,
        }
        
        self.medium_value_indicators = {
            '/login': 5,
            '/search': 5,
            '/form': 5,
            '/contact': 4,
            'comment': 5,
        }
        
        self.low_value_patterns = {
            '.js': 1,
            '.css': 0,
            '.png': 0,
            '.jpg': 0,
            '.gif': 0,
            'robots.txt': 0,
            'sitemap': 1,
            'manifest': 1,
            'favicon': 0,
        }
        
        # Security control indicators (increase priority if missing)
        self.security_control_bonuses = {
            'has_waf': -2,           # Reduce priority if WAF detected
            'requires_auth': +1,     # Slight boost for auth requirements
            'https_only': -1,        # Slight reduction (more protected)
            'rate_limited': -1,      # Reduce if rate limited
        }
    
    def calculate_priority_score(self, endpoint: str, 
                                 param_count: int = 0,
                                 is_authenticated_only: bool = False,
                                 method: str = 'GET',
                                 sensitivity_level: str = 'public',
                                 security_controls: List[str] = None) -> float:
        """
        Calculate priority score (0-10) for an endpoint.
        
        Higher score = higher priority for testing.
        
        Args:
            endpoint: URL path (e.g., '/api/users')
            param_count: Number of parameters
            is_authenticated_only: Whether endpoint requires auth
            method: HTTP method (GET, POST, PUT, DELETE)
            sensitivity_level: Data sensitivity (public, user_data, payment, config)
            security_controls: List of detected security controls
            
        Returns:
            Priority score 0-10
        """
        score = 5.0  # Base score
        
        # 1. Pattern-based scoring
        url_lower = endpoint.lower()
        
        # Check critical patterns
        for pattern, value in self.critical_indicators.items():
            if pattern.lower() in url_lower:
                score = max(score, float(value))
        
        # Check high-value patterns
        if score < 8:
            for pattern, value in self.high_value_indicators.items():
                if pattern.lower() in url_lower:
                    score = max(score, float(value))
        
        # Check medium-value patterns
        if score < 6:
            for pattern, value in self.medium_value_indicators.items():
                if pattern.lower() in url_lower:
                    score = max(score, float(value))
        
        # Check low-value patterns
        for pattern, value in self.low_value_patterns.items():
            if pattern.lower() in url_lower:
                score = min(score, float(value))
        
        # 2. Sensitivity-based scoring
        sensitivity_boost = {
            'config': 3.0,
            'payment': 3.0,
            'user_data': 2.0,
            'public': 0.0,
        }
        score += sensitivity_boost.get(sensitivity_level, 0)
        
        # 3. Parameter count boost
        # More parameters = more attack surface
        param_bonus = min(param_count * 0.3, 2.0)
        score += param_bonus
        
        # 4. HTTP method boost
        # POST/PUT/DELETE more dangerous than GET
        method_bonus = {
            'DELETE': 2.0,
            'PUT': 1.5,
            'POST': 1.0,
            'GET': 0.0,
            'HEAD': -1.0,
            'OPTIONS': -1.0,
        }
        score += method_bonus.get(method, 0)
        
        # 5. Authentication context
        if is_authenticated_only:
            score += 0.5  # Slightly higher priority for restricted endpoints
        
        # 6. Security controls adjustment
        if security_controls:
            for control in security_controls:
                adjustment = self.security_control_bonuses.get(control, 0)
                score += adjustment
        
        # Cap at 0-10
        return max(0, min(10, score))
    
    def prioritize_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[Tuple[str, float, int]]:
        """
        Prioritize a list of endpoints for testing.
        
        Args:
            endpoints: List of endpoint dicts with keys:
                - endpoint: URL path
                - param_count: Number of parameters
                - is_authenticated_only: Bool
                - method: HTTP method
                - sensitivity_level: Data sensitivity
                - security_controls: List of controls
                
        Returns:
            List of (endpoint, priority_score, attack_order_rank) tuples
        """
        scored_endpoints = []
        
        for ep in endpoints:
            score = self.calculate_priority_score(
                endpoint=ep.get('endpoint', ''),
                param_count=ep.get('param_count', 0),
                is_authenticated_only=ep.get('is_authenticated_only', False),
                method=ep.get('method', 'GET'),
                sensitivity_level=ep.get('sensitivity_level', 'public'),
                security_controls=ep.get('security_controls', [])
            )
            scored_endpoints.append((ep.get('endpoint', ''), score))
        
        # Sort by score descending
        scored_endpoints.sort(key=lambda x: x[1], reverse=True)
        
        # Add attack order rank
        result = []
        for rank, (endpoint, score) in enumerate(scored_endpoints, 1):
            result.append((endpoint, score, rank))
        
        self.attack_order = result
        return result
    
    def should_skip_target(self, endpoint: str, score: float, 
                          budget_remaining: int = 100) -> bool:
        """
        Decide if a target should be skipped (not analyzed).
        
        Skips low-value targets to preserve budget.
        
        Args:
            endpoint: URL path
            score: Priority score calculated
            budget_remaining: Number of requests remaining
            
        Returns:
            True if should skip this endpoint
        """
        # Always skip if priority too low
        if score < 1.5:
            return True
        
        # Skip medium/low if budget tight
        if budget_remaining < 20 and score < 3.0:
            return True
        
        # Skip if static assets
        static_extensions = {'.js', '.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf'}
        for ext in static_extensions:
            if endpoint.endswith(ext):
                return True
        
        return False
    
    def get_attack_focus(self, endpoint: str) -> str:
        """
        Get recommended attack focus for an endpoint based on its characteristics.
        
        Args:
            endpoint: URL path
            
        Returns:
            Focus area: 'api_data', 'auth_bypass', 'admin_access', 'financial', 'rce'
        """
        url_lower = endpoint.lower()
        
        # API endpoints: focus on data extraction
        if '/api' in url_lower or url_lower.startswith('api'):
            return 'api_data'
        
        # Admin areas: focus on privilege escalation
        if 'admin' in url_lower or 'management' in url_lower:
            return 'admin_access'
        
        # Auth endpoints: focus on bypass
        if 'login' in url_lower or 'auth' in url_lower:
            return 'auth_bypass'
        
        # Payment/transaction: focus on financial impact
        if 'payment' in url_lower or 'transaction' in url_lower or 'cart' in url_lower:
            return 'financial'
        
        # Upload/file: focus on RCE
        if 'upload' in url_lower or 'file' in url_lower:
            return 'rce'
        
        return 'data_extraction'
    
    def calculate_budget_allocation(self, endpoints: List[Dict[str, Any]], 
                                    total_budget: int = 1000) -> Dict[str, int]:
        """
        Allocate request budget across endpoints by priority.
        
        Args:
            endpoints: List of endpoint dicts
            total_budget: Total requests available
            
        Returns:
            Dict mapping endpoint → allocated requests
        """
        prioritized = self.prioritize_endpoints(endpoints)
        
        # Calculate total score
        total_score = sum(score for _, score, _ in prioritized)
        
        if total_score == 0:
            # Equal allocation if no scoring
            allocation = total_budget // len(prioritized)
            return {ep: allocation for ep, _, _ in prioritized}
        
        # Allocate proportional to score
        allocation = {}
        allocated = 0
        
        for endpoint, score, _ in prioritized:
            # At least 1 request per endpoint
            request_count = max(1, int((score / total_score) * total_budget))
            allocation[endpoint] = request_count
            allocated += request_count
        
        # Distribute remainder to highest priority
        if allocated < total_budget:
            remainder = total_budget - allocated
            if prioritized:
                top_endpoint = prioritized[0][0]
                allocation[top_endpoint] += remainder
        
        return allocation
    
    def get_priority_summary(self) -> Dict[str, Any]:
        """
        Get summary of priority calculations.
        
        Returns:
            Summary including top targets and scoring breakdown
        """
        if not self.attack_order:
            return {'message': 'No endpoints prioritized yet'}
        
        top_5 = self.attack_order[:5]
        
        return {
            'total_endpoints': len(self.attack_order),
            'top_5_targets': [
                {
                    'endpoint': ep,
                    'priority_score': round(score, 2),
                    'rank': rank
                }
                for ep, score, rank in top_5
            ],
            'critical_count': sum(1 for _, s, _ in self.attack_order if s >= 9),
            'high_value_count': sum(1 for _, s, _ in self.attack_order if 7 <= s < 9),
            'medium_value_count': sum(1 for _, s, _ in self.attack_order if 4 <= s < 7),
            'low_value_count': sum(1 for _, s, _ in self.attack_order if s < 4),
        }
