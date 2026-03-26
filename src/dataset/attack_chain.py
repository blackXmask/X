"""
Enhanced Attack Chain Engine - Multi-step attack tracking with decision trees.

Priority 5: Attack Chain Simulation
- Track multi-step attacks: detect → enumerate → extract → exfiltrate
- Decision trees: if success, escalate; if blocked, mutate
- Behavioral features: decision_path, attempt_count, strategy_shift
- Discovery source tracking: crawl vs JS parsing vs brute force

Priority 6: Discovery Source Tracking
- Track how endpoints were discovered (crawl/js/brute)
- Use discovery method to inform attack strategy

Priority 7: Behavioral Features for ML
- decision_path: string representation of attack flow
- attempt_count: total number of attempts on target
- strategy_shift: whether attacker changed approach
- escalation_depth: how many stages successfully achieved
"""

from typing import Dict, List, Optional
from datetime import datetime


class EnhancedAttackChainEngine:
    """Tracks realistic multi-step attack sequences."""
    
    def __init__(self):
        """Initialize attack chain tracking."""
        self.chains = {}
        self.discovery_sources = {}
        
        # Attack stage definitions
        self.stage_progression = {
            'xss': ['inject', 'detect', 'confirm', 'escalate', 'steal_data'],
            'sqli': ['detect', 'enumerate', 'extract', 'dump', 'exfiltrate'],
            'command': ['test', 'execute', 'shell_upgrade', 'persist', 'escalate'],
            'idor': ['enumerate', 'access', 'extract', 'iterate', 'lateral_move'],
            'auth_bypass': ['detect', 'bypass', 'obtain_access', 'escalate', 'admin_access'],
            'file_upload': ['upload', 'confirm', 'execute', 'upgrade', 'persist'],
        }
    
    def track_attack(self,
                    scan_id: str,
                    target_url: str,
                    payload_type: str,
                    payload: str,
                    exploit_success: bool,
                    execution_signals: List[str],
                    response_time: float = 0,
                    response_size: int = 0,
                    discovery_source: str = 'crawl') -> Dict:
        """
        Track an attack with full context and behavioral data.
        
        Returns comprehensive attack state including:
        - chain progression
        - decision path taken
        - behavioral features
        - suggested next step
        """
        chain_key = f"{target_url}:{payload_type}"
        
        # Initialize chain if new
        if chain_key not in self.chains:
            self.chains[chain_key] = {
                'created_at': datetime.now().isoformat(),
                'attempts': [],
                'successful_stages': [],
                'failed_stages': [],
                'decision_path': [],
                'discovery_source': discovery_source,
                'strategy_shifts': 0,
                'current_strategy': payload_type,
            }
        
        # Record discovery source
        if discovery_source not in self.discovery_sources:
            self.discovery_sources[discovery_source] = 0
        self.discovery_sources[discovery_source] += 1
        
        # Determine current stage
        current_stage = self._determine_stage(payload_type, payload, exploit_success)
        
        # Record attempt
        attempt = {
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'stage': current_stage,
            'payload': payload,
            'success': exploit_success,
            'signals': execution_signals,
            'response_time_ms': response_time,
            'response_size_bytes': response_size,
        }
        self.chains[chain_key]['attempts'].append(attempt)
        
        # Track successful/failed stages
        if exploit_success:
            self.chains[chain_key]['successful_stages'].append(current_stage)
        else:
            self.chains[chain_key]['failed_stages'].append(current_stage)
        
        # Determine next action
        next_action, next_stage = self._decide_next_action(
            chain_key,
            exploit_success,
            current_stage,
            payload_type
        )
        
        # Build decision path
        decision_node = {
            'stage': current_stage,
            'outcome': 'success' if exploit_success else 'failure',
            'decision': next_action,
            'next_stage': next_stage,
        }
        self.chains[chain_key]['decision_path'].append(decision_node)
        
        # Calculate chain metrics
        chain_depth = len(set(self.chains[chain_key]['successful_stages']))
        total_attempts = len(self.chains[chain_key]['attempts'])
        success_rate = len(self.chains[chain_key]['successful_stages']) / max(total_attempts, 1)
        
        # Determine compromise confidence
        compromise_confidence = self._calculate_compromise_confidence(
            chain_key,
            execution_signals
        )
        
        return {
            'chain_id': chain_key,
            'attack_stage': current_stage,
            'chain_depth': chain_depth,
            'chain_success': exploit_success,
            'progression_percent': int((chain_depth / len(self.stage_progression.get(payload_type, [])) * 100) if self.stage_progression.get(payload_type) else 0),
            'attempt_count': total_attempts,
            'success_rate': round(success_rate, 2),
            'successful_stages': self.chains[chain_key]['successful_stages'],
            'failed_stages': self.chains[chain_key]['failed_stages'],
            'discovery_source': self.chains[chain_key]['discovery_source'],
            'decision_path': decision_node['decision'],
            'next_suggested_stage': next_stage,
            'compromise_confidence': compromise_confidence,
            'strategy_shifts': self.chains[chain_key]['strategy_shifts'],
        }
    
    def _determine_stage(self, 
                        payload_type: str,
                        payload: str,
                        exploit_success: bool) -> str:
        """Determine attack stage based on payload type and success."""
        
        if not exploit_success:
            return 'reconnaissance'
        
        payload_lower = payload.lower()
        
        # XSS progression
        if payload_type == 'xss':
            if 'document.cookie' in payload or 'sessionStorage' in payload:
                return 'steal_data'
            elif any(x in payload for x in ['fetch(', 'XMLHttpRequest', 'axios']):
                return 'exfiltrate'
            elif '<img' in payload or '<svg' in payload or 'onerror' in payload:
                return 'confirm'
            else:
                return 'inject'
        
        # SQLi progression
        elif payload_type == 'sqli':
            if any(x in payload_lower for x in ['union', 'select', 'from']):
                return 'enumerate'
            elif any(x in payload_lower for x in ['information_schema', 'sysobjects', 'tables']):
                return 'extract'
            elif any(x in payload_lower for x in ['into outfile', 'into dumpfile']):
                return 'exfiltrate'
            else:
                return 'detect'
        
        # Command injection
        elif payload_type == 'command':
            if any(x in payload_lower for x in ['bash', 'sh -', '/bin/sh']):
                return 'shell_upgrade'
            elif any(x in payload for x in ['nc ', 'ncat', 'bash -i']):
                return 'reverse_shell'
            elif '>' in payload and any(x in payload for x in ['.sh', '.txt', '.conf']):
                return 'persist'
            else:
                return 'execute'
        
        # IDOR
        elif payload_type == 'idor':
            return 'iterate' if any(str(i) in payload for i in range(100, 110)) else 'enumerate'
        
        # Auth bypass
        elif payload_type in ['bypass', 'auth_bypass']:
            return 'escalate' if exploit_success else 'detect'
        
        # File upload
        elif payload_type == 'file_upload':
            if any(x in payload_lower for x in ['.php', '.jsp', '.aspx', '.exe']):
                return 'execute'
            else:
                return 'upload'
        
        return 'exploit'
    
    def _decide_next_action(
        self,
        chain_key: str,
        exploit_success: bool,
        current_stage: str,
        payload_type: str
    ) -> tuple:
        """Decide next action in attack chain."""
        
        if not exploit_success:
            # Failed attempt
            stages = self.stage_progression.get(payload_type, [])
            if current_stage in stages:
                idx = stages.index(current_stage)
                # Advance or try different approach
                if idx + 1 < len(stages):
                    return 'escalate', stages[idx + 1]
                else:
                    return 'switch_approach', None
            return 'retry_with_mutation', current_stage
        
        # Successful exploit - escalate
        stages = self.stage_progression.get(payload_type, [])
        if current_stage in stages:
            idx = stages.index(current_stage)
            if idx + 1 < len(stages):
                return 'escalate', stages[idx + 1]
        
        return 'maximize_impact', None
    
    def _calculate_compromise_confidence(
        self,
        chain_key: str,
        execution_signals: List[str]
    ) -> float:
        """
        Calculate confidence that target is compromised (0-1).
        
        Based on:
        - Execution signals (proof of code execution)
        - Chain depth (how far into attack succeeded)
        - Success rate
        """
        chain = self.chains[chain_key]
        
        # Base: number of successful stages
        confidence = min(len(chain['successful_stages']) / 5.0, 0.7)  # Max 70% from stages
        
        # Boost for execution signals (proves real compromise)
        if 'command_executed' in execution_signals or 'file_read' in execution_signals:
            confidence = min(confidence + 0.25, 1.0)
        elif 'js_executed' in execution_signals or 'sql_executed' in execution_signals:
            confidence = min(confidence + 0.15, 1.0)
        
        # Boost for multiple successful stages
        if len(chain['successful_stages']) >= 3:
            confidence = min(confidence + 0.15, 1.0)
        
        return round(confidence, 2)
    
    def get_chain_stats(self, target_url: str, payload_type: str) -> Dict:
        """Get comprehensive statistics for an attack chain."""
        chain_key = f"{target_url}:{payload_type}"
        
        if chain_key not in self.chains:
            return {
                'total_attempts': 0,
                'success_rate': 0.0,
                'chain_depth': 0,
                'stages_achieved': [],
                'compromise_confidence': 0.0,
            }
        
        chain = self.chains[chain_key]
        total = len(chain['attempts'])
        successes = len(chain['successful_stages'])
        
        return {
            'total_attempts': total,
            'successful_attempts': successes,
            'success_rate': round(successes / max(total, 1), 2),
            'chain_depth': len(set(chain['successful_stages'])),
            'successful_stages': list(set(chain['successful_stages'])),
            'failed_stages': list(set(chain['failed_stages'])),
            'discovery_source': chain.get('discovery_source', 'unknown'),
            'strategy_shifts': chain.get('strategy_shifts', 0),
            'decision_path_length': len(chain['decision_path']),
        }
    
    def get_behavioral_features(self, target_url: str, payload_type: str) -> Dict:
        """
        Extract behavioral features for ML models.
        
        Priority 7: Behavioral Features
        - decision_path: sequence of decisions made
        - attempt_count: how many times was this endpoint attacked
        - strategy_shift: did attacker try different approaches?
        - escalation_depth: how many stages deep did attack go?
        """
        chain_key = f"{target_url}:{payload_type}"
        
        if chain_key not in self.chains:
            return {
                'decision_path_str': '',
                'attempt_count': 0,
                'strategy_shift': False,
                'escalation_depth': 0,
                'discovery_method': 'unknown',
            }
        
        chain = self.chains[chain_key]
        
        # Build decision path string
        decision_path = ' → '.join([d['outcome'] for d in chain['decision_path'][:5]])
        
        # Count strategy shifts
        strategy_shifts = chain.get('strategy_shifts', 0)
        
        # Escalation depth
        successful_count = len(chain['successful_stages'])
        
        return {
            'decision_path': decision_path,
            'decision_path_length': len(chain['decision_path']),
            'attempt_count': len(chain['attempts']),
            'strategy_shifts': strategy_shifts,
            'escalation_depth': successful_count,
            'discovery_source': chain['discovery_source'],
            'has_adaptive_learning': len(chain['decision_path']) > 2,
        }
    
    def get_discovery_stats(self) -> Dict:
        """Priority 6: Discovery source tracking."""
        return {
            'discovered_via_crawl': self.discovery_sources.get('crawl', 0),
            'discovered_via_js': self.discovery_sources.get('js_parsing', 0),
            'discovered_via_brute': self.discovery_sources.get('brute_force', 0),
            'total_discovered': sum(self.discovery_sources.values()),
            'discovery_distribution': self.discovery_sources.copy(),
        }


# Keep backward compatibility
AttackChainEngine = EnhancedAttackChainEngine

