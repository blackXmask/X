"""
Impact Simulator - Realistic Consequence Scoring

Transforms from "label=1 (vulnerable)" to "label=1 (vulnerable) with 
real-world consequences like data exfiltration, account takeover, financial loss."

Real-world impact assessment:
- SQL Injection on users table → data_exfiltration=True, account_takeover_possible=True
- IDOR on admin settings → service_disruption=True, configuration_compromise=True
- File Upload RCE → rce_possible=True, full_system_compromise=True
- XSS on admin panel → account_takeover_possible=True

This teaches the ML model what actually matters for bug bounty, not just
"vulnerability exists" but "what can an attacker actually DO."
"""

from typing import Dict, List, Any, Tuple
from enum import Enum


class ImpactTypeEnum(Enum):
    """Types of real-world impacts."""
    DATA_EXFILTRATION = "data_exfiltration"
    ACCOUNT_TAKEOVER = "account_takeover"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SERVICE_DISRUPTION = "service_disruption"
    FINANCIAL_LOSS = "financial_loss"
    REPUTATION_DAMAGE = "reputation_damage"
    CONFIGURATION_COMPROMISE = "configuration_compromise"
    RCE = "rce"
    MASS_ASSIGNMENT = "mass_assignment"


class ImpactSimulator:
    """
    Simulates real-world consequences of vulnerabilities.
    
    Not just "is it vulnerable?" but "what are the consequences?"
    
    Attributes:
        impact_profiles: Pre-built impact models for different vuln types
        endpoint_risk_map: Maps endpoint type to max exploitable impact
    """
    
    def __init__(self):
        """Initialize impact simulator."""
        # Impact models for each vulnerability type
        self.impact_profiles: Dict[str, Dict[str, Any]] = {
            'idor': {
                'attack_type': 'IDOR',
                'possible_impacts': [
                    ImpactTypeEnum.DATA_EXFILTRATION.value,
                    ImpactTypeEnum.ACCOUNT_TAKEOVER.value,
                    ImpactTypeEnum.PRIVILEGE_ESCALATION.value,
                ],
                'data_exfiltration': 0.9,
                'account_takeover': 0.7,
                'privilege_escalation': 0.6,
                'severity': 'CRITICAL',
            },
            'sqli': {
                'attack_type': 'SQL Injection',
                'possible_impacts': [
                    ImpactTypeEnum.DATA_EXFILTRATION.value,
                    ImpactTypeEnum.CONFIGURATION_COMPROMISE.value,
                    ImpactTypeEnum.RCE.value,
                ],
                'data_exfiltration': 0.95,
                'rce': 0.5,
                'configuration_compromise': 0.8,
                'severity': 'CRITICAL',
            },
            'xss': {
                'attack_type': 'XSS',
                'possible_impacts': [
                    ImpactTypeEnum.ACCOUNT_TAKEOVER.value,
                    ImpactTypeEnum.PRIVILEGE_ESCALATION.value,
                    ImpactTypeEnum.DATA_EXFILTRATION.value,
                ],
                'account_takeover': 0.8,
                'privilege_escalation': 0.4,
                'data_exfiltration': 0.7,
                'severity': 'HIGH',
            },
            'auth_bypass': {
                'attack_type': 'Authentication Bypass',
                'possible_impacts': [
                    ImpactTypeEnum.ACCOUNT_TAKEOVER.value,
                    ImpactTypeEnum.PRIVILEGE_ESCALATION.value,
                    ImpactTypeEnum.DATA_EXFILTRATION.value,
                ],
                'account_takeover': 0.95,
                'privilege_escalation': 0.85,
                'data_exfiltration': 0.9,
                'severity': 'CRITICAL',
            },
            'file_upload': {
                'attack_type': 'File Upload',
                'possible_impacts': [
                    ImpactTypeEnum.RCE.value,
                    ImpactTypeEnum.SERVICE_DISRUPTION.value,
                ],
                'rce': 0.85,
                'service_disruption': 0.6,
                'severity': 'CRITICAL',
            },
            'rce': {
                'attack_type': 'Remote Code Execution',
                'possible_impacts': [
                    ImpactTypeEnum.RCE.value,
                    ImpactTypeEnum.DATA_EXFILTRATION.value,
                    ImpactTypeEnum.SERVICE_DISRUPTION.value,
                    ImpactTypeEnum.CONFIGURATION_COMPROMISE.value,
                ],
                'rce': 1.0,
                'data_exfiltration': 1.0,
                'service_disruption': 0.9,
                'configuration_compromise': 1.0,
                'severity': 'CRITICAL',
            },
            'mass_assignment': {
                'attack_type': 'Mass Assignment',
                'possible_impacts': [
                    ImpactTypeEnum.PRIVILEGE_ESCALATION.value,
                    ImpactTypeEnum.ACCOUNT_TAKEOVER.value,
                ],
                'privilege_escalation': 0.8,
                'account_takeover': 0.6,
                'severity': 'HIGH',
            },
            'logic_bug': {
                'attack_type': 'Business Logic Bug',
                'possible_impacts': [
                    ImpactTypeEnum.FINANCIAL_LOSS.value,
                    ImpactTypeEnum.SERVICE_DISRUPTION.value,
                ],
                'financial_loss': 0.7,
                'service_disruption': 0.5,
                'severity': 'HIGH',
            },
        }
        
        # Endpoint multipliers for impact
        self.endpoint_sensitivity = {
            'admin': 2.0,
            'payment': 2.5,
            'user_data': 1.8,
            'auth': 2.0,
            'config': 2.0,
            'public': 0.5,
        }
    
    def simulate_impact(self, attack_type: str, endpoint: str = '',
                       endpoint_type: str = 'public',
                       affected_users: int = 1,
                       data_sensitivity: str = 'public',
                       is_authenticated: bool = False) -> Dict[str, Any]:
        """
        Simulate real-world impact of a vulnerability.
        
        Args:
            attack_type: Type of attack (idor, sqli, xss, etc.)
            endpoint: The vulnerable endpoint
            endpoint_type: Type of endpoint (admin, payment, user_data, etc.)
            affected_users: Estimated number of affected users
            data_sensitivity: Sensitivity of data at risk
            is_authenticated: Whether exploit requires authentication
            
        Returns:
            Impact simulation including probabilities and consequences
        """
        # Get base impact profile
        vuln_type = attack_type.lower()
        if vuln_type not in self.impact_profiles:
            vuln_type = 'logic_bug'  # Default
        
        profile = self.impact_profiles[vuln_type]
        
        # Build impact result
        impact = {
            'attack_type': profile['attack_type'],
            'severity': profile['severity'],
            'base_profile': vuln_type,
            'endpoint': endpoint,
            'endpoint_type': endpoint_type,
            'affects_users': affected_users,
            'data_sensitivity': data_sensitivity,
            'requires_auth': is_authenticated,
        }
        
        # Calculate multipliers
        sensitivity_multiplier = self.endpoint_sensitivity.get(endpoint_type, 1.0)
        user_multiplier = min(affected_users / 100, 2.0)  # Cap at 2x
        
        # Simulate each impact type
        data_exfiltration_prob = profile.get('data_exfiltration', 0.0)
        account_takeover_prob = profile.get('account_takeover', 0.0)
        privilege_escalation_prob = profile.get('privilege_escalation', 0.0)
        rce_prob = profile.get('rce', 0.0)
        config_compromise_prob = profile.get('configuration_compromise', 0.0)
        service_disruption_prob = profile.get('service_disruption', 0.0)
        financial_loss_prob = profile.get('financial_loss', 0.0)
        
        # Apply multipliers
        data_exfiltration_prob *= sensitivity_multiplier * user_multiplier
        account_takeover_prob *= sensitivity_multiplier
        privilege_escalation_prob *= sensitivity_multiplier
        rce_prob *= sensitivity_multiplier
        config_compromise_prob *= sensitivity_multiplier
        service_disruption_prob *= sensitivity_multiplier
        financial_loss_prob *= sensitivity_multiplier * user_multiplier
        
        # Cap at 1.0
        def cap_prob(p):
            return min(1.0, max(0.0, p))
        
        impact['data_exfiltration_possible'] = cap_prob(data_exfiltration_prob) >= 0.5
        impact['data_exfiltration_probability'] = cap_prob(data_exfiltration_prob)
        
        impact['account_takeover_possible'] = cap_prob(account_takeover_prob) >= 0.5
        impact['account_takeover_probability'] = cap_prob(account_takeover_prob)
        
        impact['privilege_escalation_possible'] = cap_prob(privilege_escalation_prob) >= 0.5
        impact['privilege_escalation_probability'] = cap_prob(privilege_escalation_prob)
        
        impact['rce_possible'] = cap_prob(rce_prob) >= 0.5
        impact['rce_probability'] = cap_prob(rce_prob)
        
        impact['configuration_compromise_possible'] = cap_prob(config_compromise_prob) >= 0.5
        impact['configuration_compromise_probability'] = cap_prob(config_compromise_prob)
        
        impact['service_disruption_possible'] = cap_prob(service_disruption_prob) >= 0.5
        impact['service_disruption_probability'] = cap_prob(service_disruption_prob)
        
        impact['financial_impact'] = cap_prob(financial_loss_prob) >= 0.5
        impact['financial_impact_probability'] = cap_prob(financial_loss_prob)
        
        # Calculate overall exploitability score (0-1)
        exploitability = self._calculate_exploitability(
            attack_type, endpoint_type, is_authenticated, affected_users
        )
        impact['exploitability_score'] = exploitability
        
        # Determine if this is "real bug bounty material"
        impact['bounty_worthy'] = self._is_bounty_worthy(impact)
        
        # Estimated financial impact
        impact['estimated_financial_impact'] = self._estimate_financial_damage(
            attack_type, affected_users, data_sensitivity
        )
        
        return impact
    
    def _calculate_exploitability(self, attack_type: str, endpoint_type: str,
                                  requires_auth: bool, affected_users: int) -> float:
        """
        Calculate how easily this vulnerability can be exploited.
        
        Returns 0-1 score (1 = fully exploitable, 0 = theoretical only).
        """
        score = 0.5  # Base
        
        # Attack type impact
        easy_attacks = {'idor', 'xss', 'file_upload', 'auth_bypass'}
        if attack_type.lower() in easy_attacks:
            score += 0.25
        
        # Endpoint type impact
        high_value_endpoints = {'admin', 'payment', 'user_data', 'auth'}
        if endpoint_type in high_value_endpoints:
            score += 0.15
        
        # Authentication requirement
        if not requires_auth:
            score += 0.15
        
        # Affected user count
        if affected_users > 10:
            score += 0.1
        
        return min(1.0, score)
    
    def _is_bounty_worthy(self, impact: Dict[str, Any]) -> bool:
        """
        Determine if this vulnerability qualifies as bug bounty material.
        
        Bug bounty = real impact, not theoretical or false positive.
        """
        # Must have at least one significant impact
        significant_impacts = [
            impact.get('data_exfiltration_possible', False),
            impact.get('account_takeover_possible', False),
            impact.get('privilege_escalation_possible', False),
            impact.get('rce_possible', False),
            impact.get('financial_impact', False),
        ]
        
        if not any(significant_impacts):
            return False
        
        # Must have reasonable exploitability
        if impact.get('exploitability_score', 0) < 0.4:
            return False
        
        # Severity must be HIGH or CRITICAL
        severity = impact.get('severity', 'LOW')
        if severity not in ['HIGH', 'CRITICAL']:
            return False
        
        return True
    
    def _estimate_financial_damage(self, attack_type: str, affected_users: int,
                                   data_sensitivity: str) -> Dict[str, Any]:
        """
        Estimate financial damage from this vulnerability.
        
        Returns:
            Dict with damage estimates in USD
        """
        # Base damage per user
        damage_per_user = {
            'public': 0,
            'user_data': 50,
            'payment': 500,
            'config': 10000,
        }
        
        base = damage_per_user.get(data_sensitivity, 10)
        total_damage = base * affected_users
        
        # Attack type multiplier
        multiplier = {
            'idor': 1.0,
            'sqli': 2.0,
            'xss': 0.5,
            'auth_bypass': 3.0,
            'file_upload': 2.0,
            'rce': 5.0,
        }
        
        mult = multiplier.get(attack_type.lower(), 1.0)
        total_damage *= mult
        
        return {
            'direct_cost': int(total_damage),
            'estimated_recovery_cost': int(total_damage * 0.5),
            'estimated_reputation_damage': int(total_damage * 0.3),
            'total_estimated_impact': int(total_damage * 1.8),
        }
    
    def get_impact_summary(self, impacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get summary of impact simulations.
        
        Args:
            impacts: List of impact dictionaries from simulate_impact()
            
        Returns:
            Summary statistics
        """
        if not impacts:
            return {'message': 'No impacts to summarize', 'count': 0}
        
        bounty_worthy = sum(1 for i in impacts if i.get('bounty_worthy', False))
        critical = sum(1 for i in impacts if i.get('severity') == 'CRITICAL')
        high = sum(1 for i in impacts if i.get('severity') == 'HIGH')
        
        # Calculate total estimated financial impact
        total_financial = sum(
            i.get('estimated_financial_impact', {}).get('total_estimated_impact', 0)
            for i in impacts
        )
        
        # Attack type breakdown
        attack_types = {}
        for impact in impacts:
            atype = impact.get('attack_type', 'Unknown')
            attack_types[atype] = attack_types.get(atype, 0) + 1
        
        return {
            'total_impacts': len(impacts),
            'bounty_worthy_count': bounty_worthy,
            'critical_count': critical,
            'high_count': high,
            'total_financial_impact': total_financial,
            'attack_type_breakdown': attack_types,
            'average_exploitability': sum(i.get('exploitability_score', 0) for i in impacts) / len(impacts),
        }
