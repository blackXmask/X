"""
Cross-Endpoint Logic Layer - Multi-Endpoint Attack Chains

Real vulnerabilities often happen BETWEEN endpoints, not within a single one.

Example Chain:
1. GET /user?id=123 → Leak: user_id=456 (IDOR, but "just info")
2. POST /update?id=456 → Modify all users (Critical when combined)

Actual Bug = (1) + (2) = Account Modification via IDOR

This module detects these multi-endpoint attack chains and assigns
"cross_endpoint_attack": true to distinguish from single-endpoint finds.
"""

from typing import Dict, List, Set, Tuple, Any
from enum import Enum
import re


class AttackChainTypeEnum(Enum):
    """Types of multi-endpoint attack chains."""
    INFO_LEAK_TO_MODIFY = "info_leak_then_modify"  # Read IDOR → Write IDOR
    LAZY_BINDING = "lazy_binding"                    # Compare two resources
    PRIVILEGE_ESCALATION_CHAIN = "priv_escalation"  # Low priv → high priv
    CHAINED_AUTH_BYPASS = "chained_auth_bypass"      # Bypass A enables bypass B
    DATA_CORRELATION = "data_correlation"            # Combine leaks from 2 endpoints


class CrossEndpointAnalyzer:
    """
    Detects relationships between endpoints and identifies multi-endpoint bugs.
    
    Focuses on finding the REAL bugs that span resources, not false-positive
    single-endpoint detections.
    
    Attributes:
        endpoint_graph: Graph of endpoint relationships
        identified_chains: List of identified attack chains
        parameter_sharing: Which parameters appear across endpoints
    """
    
    def __init__(self):
        """Initialize cross-endpoint analyzer."""
        # Endpoint relationship graph
        self.endpoint_graph: Dict[str, Set[str]] = {}
        
        # Identified chains: chain_type → list of (endpoint_pair, chain_type, risk)
        self.identified_chains: List[Dict[str, Any]] = []
        
        # Parameter sharing: parameter_name → set of endpoints using it
        self.parameter_sharing: Dict[str, Set[str]] = {}
        
        # Common chain patterns
        self.chain_patterns = {
            'read_write': {
                'read_patterns': ['/read', '/get', '?id=', '/info', '/details'],
                'write_patterns': ['/update', '/modify', '/edit', '/change', '/set'],
            },
            'privilege_escalation': {
                'low_priv': ['/user', '/profile', '/account'],
                'admin_patterns': ['/admin', '/management', '/settings'],
            },
            'authentication': {
                'token_sources': ['/login', '/auth', '/token', '/session'],
                'token_users': ['/api', '/dashboard', '/protected'],
            },
        }
    
    def register_endpoint(self, endpoint: str, method: str, 
                         parameters: List[str]) -> None:
        """
        Register an endpoint in the graph.
        
        Args:
            endpoint: URL path
            method: HTTP method
            parameters: List of parameter names
        """
        # Add to graph
        if endpoint not in self.endpoint_graph:
            self.endpoint_graph[endpoint] = set()
        
        # Track parameter sharing
        for param in parameters:
            if param not in self.parameter_sharing:
                self.parameter_sharing[param] = set()
            self.parameter_sharing[param].add(endpoint)
    
    def find_related_endpoints(self, endpoint: str) -> List[Tuple[str, str]]:
        """
        Find endpoints that could be part of an attack chain with this one.
        
        Args:
            endpoint: URL path
            
        Returns:
            List of (related_endpoint, relationship_type) tuples
        """
        related = []
        
        # Extract base path: /api/users/123 → /api/users
        base_path = self._extract_base_path(endpoint)
        
        # Find endpoints sharing base path
        for other_ep in self.endpoint_graph.keys():
            if other_ep == endpoint:
                continue
            
            other_base = self._extract_base_path(other_ep)
            
            if base_path == other_base:
                relationship = self._determine_relationship(endpoint, other_ep)
                related.append((other_ep, relationship))
        
        # Find endpoints sharing parameters
        params = self._extract_parameters_from_endpoint(endpoint)
        for param in params:
            if param in self.parameter_sharing:
                for other_ep in self.parameter_sharing[param]:
                    if other_ep != endpoint:
                        relationship = f"shares_param_{param}"
                        related.append((other_ep, relationship))
        
        return related
    
    def detect_read_write_pair(self, read_endpoint: str, 
                              write_endpoint: str) -> Dict[str, Any]:
        """
        Detect if two endpoints form a read-then-write chain.
        
        This is a classic IDOR chain: read data with IDOR, use it to write with IDOR.
        
        Args:
            read_endpoint: GET endpoint that might leak data
            write_endpoint: POST/PUT endpoint that might modify data
            
        Returns:
            Chain details including confidence score
        """
        rw_base = self._extract_base_path(read_endpoint)
        ww_base = self._extract_base_path(write_endpoint)
        
        # Must share base path
        if rw_base != ww_base:
            return None
        
        read_params = self._extract_parameters_from_endpoint(read_endpoint)
        write_params = self._extract_parameters_from_endpoint(write_endpoint)
        
        # Must share ID parameter
        shared_id_params = set(read_params) & set(write_params)
        if not shared_id_params:
            return None
        
        # Check methods
        read_methods = {'GET', 'HEAD'}
        write_methods = {'POST', 'PUT', 'DELETE'}
        
        chain = {
            'chain_type': AttackChainTypeEnum.INFO_LEAK_TO_MODIFY.value,
            'read_endpoint': read_endpoint,
            'write_endpoint': write_endpoint,
            'shared_parameters': list(shared_id_params),
            'scenario': f"1. Read from {read_endpoint} with attacker-controlled param\n"
                       f"2. Leak sensitive data\n"
                       f"3. Modify using {write_endpoint} with leaked param\n"
                       f"Impact: Full unauthorized modification",
            'criticality': 'CRITICAL',
            'confidence': 0.9,
            'cross_endpoint_attack': True,
        }
        
        return chain
    
    def detect_privilege_escalation_chain(self, low_priv_endpoint: str,
                                         admin_endpoint: str) -> Dict[str, Any]:
        """
        Detect privilege escalation chains.
        
        Example: User can access /user endpoint, but can modify /admin settings.
        
        Args:
            low_priv_endpoint: Endpoint accessible with low privileges
            admin_endpoint: Endpoint requiring high privileges
            
        Returns:
            Chain details including escalation vector
        """
        low_params = self._extract_parameters_from_endpoint(low_priv_endpoint)
        admin_params = self._extract_parameters_from_endpoint(admin_endpoint)
        
        # Check if low-privilege endpoint leaks admin identifiers
        shared_params = set(low_params) & set(admin_params)
        
        if not shared_params:
            return None
        
        chain = {
            'chain_type': AttackChainTypeEnum.PRIVILEGE_ESCALATION_CHAIN.value,
            'low_priv_endpoint': low_priv_endpoint,
            'admin_endpoint': admin_endpoint,
            'escalation_vector': 'ID enumeration from low-priv endpoint used against high-priv endpoint',
            'scenario': f"1. Access {low_priv_endpoint} as regular user → leak admin IDs\n"
                       f"2. Use leaked IDs with {admin_endpoint}\n"
                       f"Impact: Privilege escalation",
            'criticality': 'CRITICAL',
            'confidence': 0.85,
            'cross_endpoint_attack': True,
        }
        
        return chain
    
    def detect_data_correlation(self, endpoint_1: str, endpoint_2: str,
                               correlated_param: str) -> Dict[str, Any]:
        """
        Detect data correlation attacks across endpoints.
        
        Example: Endpoint A returns order IDs, Endpoint B returns order details.
        Correlation attack: Use leaked IDs from A to access B.
        
        Args:
            endpoint_1: First endpoint
            endpoint_2: Second endpoint
            correlated_param: Parameter that correlates them
            
        Returns:
            Chain details
        """
        chain = {
            'chain_type': AttackChainTypeEnum.DATA_CORRELATION.value,
            'endpoint_1': endpoint_1,
            'endpoint_2': endpoint_2,
            'correlated_parameter': correlated_param,
            'scenario': f"1. Trigger IDOR/enumeration on {endpoint_1}\n"
                       f"2. Leak {correlated_param} values\n"
                       f"3. Use leaked values to access {endpoint_2}\n"
                       f"Impact: Broader data access via correlation",
            'criticality': 'HIGH',
            'confidence': 0.75,
            'cross_endpoint_attack': True,
        }
        
        return chain
    
    def find_all_chains_for_endpoint(self, endpoint: str) -> List[Dict[str, Any]]:
        """
        Find all possible attack chains involving this endpoint.
        
        Args:
            endpoint: The endpoint to analyze
            
        Returns:
            List of potential attack chains
        """
        chains = []
        
        # Get related endpoints
        related = self.find_related_endpoints(endpoint)
        
        for related_ep, relationship in related:
            # Try read-write pair
            rw_chain = self.detect_read_write_pair(endpoint, related_ep)
            if rw_chain:
                chains.append(rw_chain)
            
            # Try reverse read-write
            rw_chain_reverse = self.detect_read_write_pair(related_ep, endpoint)
            if rw_chain_reverse:
                chains.append(rw_chain_reverse)
            
            # Try privilege escalation
            priv_chain = self.detect_privilege_escalation_chain(endpoint, related_ep)
            if priv_chain:
                chains.append(priv_chain)
            
            # Try data correlation
            params = self._extract_parameters_from_endpoint(endpoint)
            for param in params[:3]:  # Check first 3 params
                corr_chain = self.detect_data_correlation(endpoint, related_ep, param)
                if corr_chain:
                    chains.append(corr_chain)
        
        return chains
    
    def _extract_base_path(self, endpoint: str) -> str:
        """
        Extract base path from endpoint.
        
        /api/users/123?id=456 → /api/users
        """
        # Remove query string
        base = endpoint.split('?')[0]
        
        # Remove trailing ID-like segments
        parts = base.split('/')
        
        # Remove numeric IDs from end
        while parts and (parts[-1].isdigit() or parts[-1] == ''):
            parts.pop()
        
        return '/'.join(parts)
    
    def _extract_parameters_from_endpoint(self, endpoint: str) -> List[str]:
        """Extract parameter names from endpoint."""
        params = []
        
        # Extract from query string
        if '?' in endpoint:
            query = endpoint.split('?')[1]
            param_pairs = query.split('&')
            for pair in param_pairs:
                if '=' in pair:
                    param_name = pair.split('=')[0]
                    params.append(param_name)
        
        # Extract from path patterns like {id} or :id or /123
        path_part = endpoint.split('?')[0]
        
        # {param} style
        bracket_params = re.findall(r'\{(\w+)\}', path_part)
        params.extend(bracket_params)
        
        # :param style
        colon_params = re.findall(r':(\w+)', path_part)
        params.extend(colon_params)
        
        return list(set(params))  # Remove duplicates
    
    def _determine_relationship(self, ep1: str, ep2: str) -> str:
        """Determine relationship between two endpoints."""
        base1 = self._extract_base_path(ep1)
        base2 = self._extract_base_path(ep2)
        
        if base1 == base2:
            # Same base path
            if 'GET' in ep1.upper() and 'POST' in ep2.upper():
                return 'read_write_pair'
            elif 'POST' in ep1.upper() and 'GET' in ep2.upper():
                return 'write_read_pair'
            else:
                return 'same_resource'
        
        return 'related_resource'
    
    def get_chain_summary(self) -> Dict[str, Any]:
        """
        Get summary of detected chains.
        
        Returns:
            Summary statistics on chains
        """
        if not self.identified_chains:
            return {'message': 'No chains identified yet', 'chain_count': 0}
        
        critical_chains = [c for c in self.identified_chains 
                          if c.get('criticality') == 'CRITICAL']
        
        chain_types = {}
        for chain in self.identified_chains:
            ctype = chain.get('chain_type', 'unknown')
            chain_types[ctype] = chain_types.get(ctype, 0) + 1
        
        return {
            'total_chains': len(self.identified_chains),
            'critical_chains': len(critical_chains),
            'chain_types': chain_types,
            'endpoints_count': len(self.endpoint_graph),
            'parameter_sharing_count': len(self.parameter_sharing),
        }
