"""
Authentication Context Handler - Support multiple auth levels for realistic testing.

Priority 2: Authentication Support
- guest requests (no auth)
- logged-in user (basic auth)
- admin user (elevated privileges)
- Proper cookie/header management
"""

from typing import Dict, List, Optional, Tuple


class AuthContextHandler:
    """Manage authentication contexts for multi-level testing."""
    
    def __init__(self):
        """Initialize auth contexts."""
        self.contexts = {
            'guest': {
                'role': 'guest',
                'is_authenticated': False,
                'headers': {},
                'cookies': {},
                'description': 'Unauthenticated user'
            },
            'user': {
                'role': 'user',
                'is_authenticated': True,
                'user_id': None,
                'headers': {},
                'cookies': {},
                'description': 'Regular authenticated user'
            },
            'admin': {
                'role': 'admin',
                'is_authenticated': True,
                'user_id': None,
                'headers': {},
                'cookies': {},
                'description': 'Administrator user'
            }
        }
    
    def set_user_context(
        self,
        role: str = 'user',
        user_id: str = 'test_user',
        cookies: Dict = None,
        headers: Dict = None
    ) -> Dict:
        """
        Set up authentication context for a specific role.
        
        Args:
            role: 'guest', 'user', or 'admin'
            user_id: User identifier
            cookies: Session/auth cookies
            headers: Auth headers (Authorization, X-API-Key, etc.)
        
        Returns:
            Context dict with all auth info
        """
        if role not in self.contexts:
            return self.contexts['guest']
        
        context = self.contexts[role].copy()
        
        if role != 'guest':
            context['user_id'] = user_id or f'user_{role}'
        
        if cookies:
            context['cookies'] = cookies
        
        if headers:
            context['headers'] = headers
        
        context['request_headers'] = self._build_request_headers(context)
        
        return context
    
    def add_bearer_token(
        self,
        context: Dict,
        token: str = None
    ) -> Dict:
        """Add JWT/Bearer token to context."""
        if not token:
            token = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InRlc3RfdXNlciIsImlhdCI6MTUxNjIzOTAyMn0.test"
        
        context = context.copy()
        context['headers'] = context.get('headers', {})
        context['headers']['Authorization'] = f'Bearer {token}'
        context['token'] = token
        context['request_headers'] = self._build_request_headers(context)
        
        return context
    
    def add_api_key(
        self,
        context: Dict,
        api_key: str = None
    ) -> Dict:
        """Add API key to context."""
        if not api_key:
            api_key = f"sk_{context.get('user_id', 'test')[:8]}_secret"
        
        context = context.copy()
        context['headers'] = context.get('headers', {})
        context['headers']['X-API-Key'] = api_key
        context['api_key'] = api_key
        context['request_headers'] = self._build_request_headers(context)
        
        return context
    
    def add_session_cookie(
        self,
        context: Dict,
        session_id: str = None
    ) -> Dict:
        """Add session cookie to context."""
        if not session_id:
            session_id = f"sess_{context.get('user_id', 'test')[:8]}"
        
        context = context.copy()
        context['cookies'] = context.get('cookies', {})
        context['cookies']['SESSIONID'] = session_id
        context['session_id'] = session_id
        context['request_headers'] = self._build_request_headers(context)
        
        return context
    
    def get_guest_context(self) -> Dict:
        """Get unauthenticated guest context."""
        return self.set_user_context('guest')
    
    def get_user_context(self, user_id: str = 'user_123') -> Dict:
        """Get authenticated user context."""
        context = self.set_user_context('user', user_id)
        context = self.add_session_cookie(context)
        return context
    
    def get_admin_context(self, user_id: str = 'admin_1') -> Dict:
        """Get admin context."""
        context = self.set_user_context('admin', user_id)
        context = self.add_session_cookie(context)
        return context
    
    def test_idor(self, context: Dict, target_user_id: str) -> Dict:
        """
        Test IDOR by switching user_id while keeping auth.
        
        Useful for IDOR/Insecure Direct Object Reference testing.
        """
        test_context = context.copy()
        test_context['target_user_id'] = target_user_id
        test_context['is_idor_test'] = True
        
        return test_context
    
    def _build_request_headers(self, context: Dict) -> Dict:
        """Build complete request headers from context."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Test Agent)',
            'Accept': 'application/json,text/html',
        }
        
        # Add auth headers
        if context.get('headers'):
            headers.update(context['headers'])
        
        # Add role indicator for server-side testing
        if context.get('role') != 'guest':
            headers['X-Test-Role'] = context['role']
        
        return headers
    
    def get_all_auth_variants(self) -> List[Dict]:
        """Get all authentication variants for comprehensive testing."""
        return [
            self.get_guest_context(),
            self.get_user_context('user_123'),
            self.get_user_context('user_456'),  # Different user for IDOR
            self.get_admin_context(),
        ]
    
    def should_test_endpoint_with_auth(
        self,
        endpoint_type: str,
        auth_required: bool
    ) -> Tuple[bool, List[str]]:
        """
        Determine which auth levels to test an endpoint with.
        
        Returns:
            (should_test, [list of roles to test])
        """
        if endpoint_type in ['login', 'register', 'forgot']:
            # Public endpoints, don't test with auth
            return True, ['guest']
        
        if auth_required:
            # Protected endpoints, test both auth and enhanced privs
            return True, ['user', 'admin']
        
        # Most endpoints test with guest first, then user for IDOR
        return True, ['guest', 'user']
    
    def create_idor_test_pair(
        self,
        user1_id: str = 'user_123',
        user2_id: str = 'user_456'
    ) -> Tuple[Dict, Dict]:
        """Create two authenticated contexts for IDOR testing."""
        context1 = self.get_user_context(user1_id)
        context2 = self.get_user_context(user2_id)
        
        return context1, context2
