"""
Strategy Layer - Adaptive Attack Strategies

Transforms from "try payloads" to "understanding endpoint → selecting strategy 
→ executing deep with adaptive depth."

Real hacker behavior:
- API endpoint? → Focus IDOR (strategy_depth=3, test 3 variation levels)
- Admin panel? → Focus privilege escalation (strategy_depth=5)
- File upload? → Focus RCE (strategy_depth=4, test command execution chains)

Each strategy has:
- strategy_name: What we're targeting
- strategy_depth: How many levels deep (1-5)
- success_indicators: What signals indicate this strategy is working
- next_action: What to do if current strategy succeeds
- pivot_point: When to switch to different strategy
"""

from typing import Dict, List, Any, Tuple
from enum import Enum


class StrategyTypeEnum(Enum):
    """Types of attack strategies."""
    FOCUS_IDOR = "focus_idor"
    FOCUS_SQLI = "focus_sqli"
    FOCUS_XSS = "focus_xss"
    FOCUS_RCE = "focus_rce"
    FOCUS_AUTH_BYPASS = "focus_auth_bypass"
    FOCUS_PRIVILEGE_ESCALATION = "focus_privilege_escalation"
    FOCUS_MASS_ASSIGNMENT = "focus_mass_assignment"
    MULTI_ENDPOINT_CHAIN = "multi_endpoint_chain"


class StrategyLayer:
    """
    Selects and executes adaptive attack strategies.
    
    Instead of "try all attacks equally," focuses deeply on the most
    promising attack vectors based on endpoint characteristics.
    
    Attributes:
        current_strategy: Currently active strategy
        strategy_history: History of strategies tried
        success_rates: Success rate for each strategy
    """
    
    def __init__(self):
        """Initialize strategy layer."""
        self.current_strategy: Dict[str, Any] = {}
        self.strategy_history: List[Dict[str, Any]] = []
        
        # Success rate for each strategy type
        self.success_rates: Dict[str, Tuple[int, int]] = {
            'focus_idor': (0, 0),
            'focus_sqli': (0, 0),
            'focus_xss': (0, 0),
            'focus_rce': (0, 0),
            'focus_auth_bypass': (0, 0),
        }
        
        # Strategy configurations
        self.strategy_configs = {
            'focus_idor': {
                'depth_max': 4,
                'payloads_per_depth': 5,
                'success_indicators': ['different_user_data', 'id_enumeration', 'permission_bypass'],
                'next_action': 'escalate_to_write',
                'pivot_threshold': 0.3,  # Pivot if success < 30%
            },
            'focus_sqli': {
                'depth_max': 5,
                'payloads_per_depth': 6,
                'success_indicators': ['sql_error', 'query_manipulation', 'data_extraction'],
                'next_action': 'escalate_to_rce',
                'pivot_threshold': 0.25,
            },
            'focus_xss': {
                'depth_max': 4,
                'payloads_per_depth': 5,
                'success_indicators': ['script_execution', 'storage_xss', 'admin_session_steal'],
                'next_action': 'escalate_to_account_takeover',
                'pivot_threshold': 0.35,
            },
            'focus_rce': {
                'depth_max': 5,
                'payloads_per_depth': 6,
                'success_indicators': ['command_execution', 'shell_access', 'system_compromise'],
                'next_action': 'lateral_movement',
                'pivot_threshold': 0.20,
            },
            'focus_auth_bypass': {
                'depth_max': 3,
                'payloads_per_depth': 7,
                'success_indicators': ['auth_bypass', 'token_prediction', 'session_fixation'],
                'next_action': 'privilege_escalation',
                'pivot_threshold': 0.25,
            },
            'focus_privilege_escalation': {
                'depth_max': 4,
                'payloads_per_depth': 6,
                'success_indicators': ['id_manipulation', 'role_elevation', 'admin_access'],
                'next_action': 'lateral_movement',
                'pivot_threshold': 0.30,
            },
        }
    
    def select_strategy_for_endpoint(self, endpoint: str, endpoint_type: str,
                                    parameters: List[Dict[str, Any]],
                                    detected_attacks: List[str] = None) -> Dict[str, Any]:
        """
        Select optimal strategy for endpoint based on characteristics.
        
        Args:
            endpoint: URL path
            endpoint_type: Type (api, admin, login, upload, etc.)
            parameters: List of parameter dicts
            detected_attacks: Previously detected vulnerable parameters
            
        Returns:
            Strategy configuration with depth and tactics
        """
        if detected_attacks is None:
            detected_attacks = []
        
        # Decide strategy based on endpoint type and detected vulnerabilities
        if endpoint_type == 'api' or '/api' in endpoint.lower():
            strategy = self._create_strategy('focus_idor', depth=3)
        
        elif endpoint_type == 'admin' or 'admin' in endpoint.lower():
            strategy = self._create_strategy('focus_privilege_escalation', depth=4)
        
        elif endpoint_type == 'upload' or 'upload' in endpoint.lower():
            strategy = self._create_strategy('focus_rce', depth=4)
        
        elif endpoint_type == 'login' or 'auth' in endpoint.lower():
            strategy = self._create_strategy('focus_auth_bypass', depth=3)
        
        elif 'search' in endpoint.lower() or 'query' in endpoint.lower():
            strategy = self._create_strategy('focus_xss', depth=3)
        
        else:
            # Default: focus on most common vulnerability
            strategy = self._create_strategy('focus_idor', depth=2)
        
        # Boost depth if already detected signs
        if detected_attacks:
            strategy['depth'] += 1
            strategy['reason'] += f". Boosted due to {len(detected_attacks)} detected attacks"
        
        # Analyze parameters for opportunities
        id_params = [p for p in parameters if 'id' in p.get('name', '').lower()]
        if id_params:
            strategy['focus_parameters'] = id_params
        
        # Store as current strategy
        self.current_strategy = strategy
        self.strategy_history.append(strategy)
        
        return strategy
    
    def _create_strategy(self, strategy_type: str, depth: int = 2) -> Dict[str, Any]:
        """Create a strategy configuration."""
        config = self.strategy_configs.get(strategy_type, {})
        
        return {
            'strategy_name': strategy_type,
            'strategy_type': strategy_type,
            'depth': min(depth, config.get('depth_max', 3)),
            'depth_max': config.get('depth_max', 3),
            'payloads_per_depth': config.get('payloads_per_depth', 5),
            'success_indicators': config.get('success_indicators', []),
            'next_action': config.get('next_action'),
            'pivot_threshold': config.get('pivot_threshold', 0.3),
            'success_rate': 0.0,
            'reason': f"Selected: {strategy_type}",
            'tactics': self._get_tactics_for_strategy(strategy_type, depth),
        }
    
    def _get_tactics_for_strategy(self, strategy_type: str, depth: int) -> List[str]:
        """Get tactical steps for a strategy."""
        tactics_map = {
            'focus_idor': [
                'Enumerate IDs (1-100)',
                'Access different user resources',
                'Modify other user data with IDOR',
                'Chains: read IDOR → write IDOR',
                'Cross-endpoint IDOR',
            ],
            'focus_sqli': [
                'Basic SQL injection detection',
                'Query enumeration (databases, tables)',
                'Data extraction from tables',
                'Escalate to command execution',
                'System file reading',
            ],
            'focus_xss': [
                'Reflected XSS detection',
                'Persistent XSS detection',
                'Admin credential harvesting',
                'Session prediction',
                'Cookie theft chains',
            ],
            'focus_rce': [
                'Command injection testing',
                'Reverse shell establishment',
                'Shell upgrade (TTY shell)',
                'Persistence mechanisms',
                'Lateral movement in network',
            ],
            'focus_auth_bypass': [
                'Authentication bypass attempts',
                'Token prediction/prediction',
                'Session fixation',
                'JWT manipulation',
                'Privilege escalation chain',
            ],
            'focus_privilege_escalation': [
                'Horizontal privilege escalation',
                'Vertical privilege escalation',
                'Role manipulation attacks',
                'Admin functionality bypass',
                'Full admin access achieve',
            ],
        }
        
        tactics = tactics_map.get(strategy_type, [])
        return tactics[:depth] if depth else tactics
    
    def execute_strategy(self, endpoint: str, parameters: List[str]) -> Dict[str, Any]:
        """
        Execute current strategy against endpoint.
        
        Args:
            endpoint: URL to test
            parameters: Parameters to test
            
        Returns:
            Execution plan with payloads and depth levels
        """
        if not self.current_strategy:
            return {'error': 'No strategy selected'}
        
        strategy = self.current_strategy
        depth = strategy['depth']
        payloads_per_depth = strategy['payloads_per_depth']
        
        execution_plan = {
            'strategy': strategy['strategy_name'],
            'endpoint': endpoint,
            'target_parameters': parameters,
            'depth': depth,
            'total_payloads': depth * payloads_per_depth,
            'depth_levels': [],
        }
        
        for d in range(1, depth + 1):
            depth_level = {
                'depth': d,
                'payloads_count': payloads_per_depth,
                'tactics': strategy['tactics'][:d] if d < len(strategy['tactics']) else strategy['tactics'],
                'success_threshold': 0.5 if d == 1 else 0.3,
                'adapt_if_success': d < depth,
            }
            execution_plan['depth_levels'].append(depth_level)
        
        return execution_plan
    
    def record_strategy_result(self, strategy_type: str, successful: bool,
                              signals_found: int = 0) -> None:
        """
        Record result of strategy execution.
        
        Args:
            strategy_type: The strategy that was executed
            successful: Whether strategy found vulnerability
            signals_found: Number of positive signals
        """
        if strategy_type in self.success_rates:
            success, failed = self.success_rates[strategy_type]
            if successful:
                self.success_rates[strategy_type] = (success + 1, failed)
            else:
                self.success_rates[strategy_type] = (success, failed + 1)
    
    def should_pivot_strategy(self, current_strategy: str,
                             signals_found: int = 0,
                             attempts: int = 0,
                             max_attempts: int = 10) -> Tuple[bool, str]:
        """
        Decide if we should switch to different strategy.
        
        Args:
            current_strategy: Current strategy name
            signals_found: Number of positive signals so far
            attempts: Attempts made so far
            max_attempts: Maximum attempts before pivot
            
        Returns:
            (should_pivot, recommended_strategy)
        """
        config = self.strategy_configs.get(current_strategy, {})
        pivot_threshold = config.get('pivot_threshold', 0.3)
        
        # If success rate above threshold, continue
        if signals_found > 0:
            success_rate = signals_found / max(1, attempts)
            if success_rate >= pivot_threshold:
                return False, current_strategy
        
        # If exceeded max attempts, pivot
        if attempts >= max_attempts:
            return True, self._get_pivot_strategy(current_strategy)
        
        # Default: continue current strategy
        return False, current_strategy
    
    def _get_pivot_strategy(self, current_strategy: str) -> str:
        """
        Get alternative strategy if current one fails.
        
        Args:
            current_strategy: Current strategy name
            
        Returns:
            Alternative strategy name
        """
        strategy_fallbacks = {
            'focus_idor': 'focus_sqli',
            'focus_sqli': 'focus_xss',
            'focus_xss': 'focus_auth_bypass',
            'focus_auth_bypass': 'focus_privilege_escalation',
            'focus_privilege_escalation': 'focus_idor',
            'focus_rce': 'focus_sqli',
        }
        
        return strategy_fallbacks.get(current_strategy, 'focus_idor')
    
    def get_strategy_effectiveness(self) -> Dict[str, Any]:
        """
        Get effectiveness metrics for strategies.
        
        Returns:
            Success rates and recommendations
        """
        effectiveness = {}
        
        for strategy, (successes, failures) in self.success_rates.items():
            total = successes + failures
            if total > 0:
                success_rate = successes / total
            else:
                success_rate = 0.0
            
            effectiveness[strategy] = {
                'successes': successes,
                'failures': failures,
                'total_attempts': total,
                'success_rate': round(success_rate, 2),
                'effectiveness_rank': self._rank_effectiveness(success_rate),
            }
        
        return effectiveness
    
    def _rank_effectiveness(self, success_rate: float) -> str:
        """Rank strategy effectiveness."""
        if success_rate >= 0.7:
            return 'HIGHLY_EFFECTIVE'
        elif success_rate >= 0.5:
            return 'EFFECTIVE'
        elif success_rate >= 0.3:
            return 'MODERATELY_EFFECTIVE'
        elif success_rate > 0:
            return 'OCCASIONALLY_EFFECTIVE'
        else:
            return 'NOT_EFFECTIVE'
    
    def get_strategy_summary(self) -> Dict[str, Any]:
        """
        Get overall summary of strategy execution.
        
        Returns:
            Summary of strategies used and effectiveness
        """
        if not self.strategy_history:
            return {'message': 'No strategies executed yet'}
        
        strategy_usage = {}
        for strategy in self.strategy_history:
            strat_name = strategy['strategy_name']
            strategy_usage[strat_name] = strategy_usage.get(strat_name, 0) + 1
        
        return {
            'total_strategies_executed': len(self.strategy_history),
            'unique_strategies': len(strategy_usage),
            'strategy_usage': strategy_usage,
            'current_strategy': self.current_strategy.get('strategy_name', 'None'),
            'effectiveness': self.get_strategy_effectiveness(),
        }
