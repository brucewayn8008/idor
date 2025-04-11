"""
Request handler module for making HTTP requests with different user sessions
"""

import requests
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse
from .session_loader import Session

class RequestHandler:
    """Handles making HTTP requests with different user sessions."""
    
    def __init__(self, timeout: int = 10):
        """
        Initialize RequestHandler.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
    
    def make_request(
        self,
        url: str,
        method: str = 'GET',
        user_session: Optional[Session] = None,
        data: Optional[Dict] = None
    ) -> Tuple[requests.Response, Optional[Exception]]:
        """
        Make an HTTP request with optional session authentication.
        
        Args:
            url: Target URL
            method: HTTP method to use
            user_session: Optional Session object for authentication
            data: Optional data for POST/PUT requests
            
        Returns:
            Tuple of (Response, Exception if any)
        """
        try:
            headers = {}
            cookies = None
            
            if user_session:
                headers = user_session.get_headers()
                cookies = user_session.get_cookies()
            
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                cookies=cookies,
                json=data if method.upper() in ['POST', 'PUT'] else None,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False  # Allow self-signed certs for testing
            )
            
            return response, None
            
        except requests.exceptions.RequestException as e:
            return None, e
    
    def test_endpoint(
        self,
        url: str,
        sessions: Dict[str, Session],
        methods: list = ['GET']
    ) -> Dict[str, Dict]:
        """
        Test an endpoint with multiple user sessions and methods.
        
        Args:
            url: Target URL to test
            sessions: Dict of user_id -> Session objects
            methods: List of HTTP methods to test
            
        Returns:
            Dict of results per user/method combination
        """
        results = {}
        
        for user_id, session in sessions.items():
            results[user_id] = {}
            
            for method in methods:
                response, error = self.make_request(
                    url=url,
                    method=method,
                    user_session=session
                )
                
                results[user_id][method] = {
                    'status_code': response.status_code if response else None,
                    'content_length': len(response.content) if response else 0,
                    'error': str(error) if error else None
                }
        
        return results 