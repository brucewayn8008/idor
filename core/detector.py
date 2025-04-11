"""
IDOR vulnerability detector module
"""

from typing import Dict, List, Set, Tuple
import json
from .session_loader import Session, SessionManager
from .request_handler import RequestHandler

class IdorDetector:
    """Detects IDOR vulnerabilities by comparing responses across sessions"""
    
    def __init__(self, session_manager: SessionManager, request_handler: RequestHandler):
        self.session_manager = session_manager
        self.request_handler = request_handler
        self.findings = []

    def analyze_response_similarity(
        self,
        url: str,
        responses: Dict[str, Dict]
    ) -> List[Dict]:
        """
        Analyze if different users get similar responses (potential IDOR).
        
        Args:
            url: The endpoint being tested
            responses: Dict of user_id -> response data
            
        Returns:
            List of potential IDOR findings
        """
        findings = []
        
        # Group responses by content length and status code
        response_groups = {}
        for user_id, data in responses.items():
            if 'GET' not in data:  # We mainly care about GET requests for now
                continue
                
            response_data = data['GET']
            if response_data['error']:
                continue
                
            key = (response_data['status_code'], response_data['content_length'])
            if key not in response_groups:
                response_groups[key] = []
            response_groups[key].append(user_id)
        
        # If different users get same response, might be IDOR
        for (status_code, content_length), users in response_groups.items():
            if len(users) > 1 and status_code == 200:  # Multiple users got same successful response
                findings.append({
                    'type': 'IDOR',
                    'endpoint': url,
                    'status_code': status_code,
                    'content_length': content_length,
                    'affected_users': users,
                    'description': f"Multiple users ({', '.join(users)}) received identical responses"
                })
                
        return findings

    def test_endpoint(self, url: str) -> List[Dict]:
        """
        Test an endpoint for IDOR vulnerabilities.
        
        Args:
            url: The endpoint to test
            
        Returns:
            List of potential IDOR findings
        """
        # Get responses from all users
        responses = {}
        for user_id in self.session_manager.list_users():
            session = self.session_manager.get_session(user_id)
            response, error = self.request_handler.make_request(url, user_session=session)
            
            responses[user_id] = {
                'GET': {
                    'status_code': response.status_code if response else None,
                    'content_length': len(response.content) if response else 0,
                    'error': str(error) if error else None
                }
            }
        
        # Analyze responses for potential IDOR
        findings = self.analyze_response_similarity(url, responses)
        self.findings.extend(findings)
        return findings

    def scan_urls(self, urls: List[str], verbose: bool = False) -> List[Dict]:
        """
        Scan multiple URLs for IDOR vulnerabilities.
        
        Args:
            urls: List of URLs to test
            verbose: Whether to print progress
            
        Returns:
            List of all findings
        """
        self.findings = []  # Reset findings
        
        for url in urls:
            if verbose:
                print(f"\nTesting: {url}")
            
            findings = self.test_endpoint(url)
            
            if verbose and findings:
                print("Potential IDOR found!")
                for finding in findings:
                    print(f"- Status: {finding['status_code']}")
                    print(f"- Users: {', '.join(finding['affected_users'])}")
                    print(f"- Content Length: {finding['content_length']}")
        
        return self.findings

    def save_findings(self, output_file: str):
        """Save findings to a JSON file"""
        with open(output_file, 'w') as f:
            json.dump({
                'total_findings': len(self.findings),
                'findings': self.findings
            }, f, indent=2) 