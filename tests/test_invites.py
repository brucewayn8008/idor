"""
Test invite URL vulnerabilities
"""

import unittest
from urllib.parse import urlparse, parse_qs
from core.session_loader import SessionManager
from core.request_handler import RequestHandler

class TestInviteUrls(unittest.TestCase):
    """Test suite for organization invite URL vulnerabilities"""
    
    def setUp(self):
        self.config_path = "config/sessions.json"
        self.session_manager = SessionManager(self.config_path)
        self.handler = RequestHandler(timeout=5)
        
        # Track organizations and their invite tokens
        self.org_invites = {}
        
        # Load and parse sitemap
        with open("input/sitemap.txt", "r") as f:
            for line in f:
                if "/verify/invite" in line:
                    url = line.strip()
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    
                    org_id = params.get('organization', [None])[0]
                    invite_token = params.get('v', [None])[0]
                    
                    if org_id and invite_token:
                        if org_id not in self.org_invites:
                            self.org_invites[org_id] = set()
                        self.org_invites[org_id].add(invite_token)
    
    def test_cross_org_access(self):
        """Test if users can access invites from other organizations"""
        # Get a sample invite from each organization
        for org_id, tokens in self.org_invites.items():
            invite_token = next(iter(tokens))
            url = f"https://console.aiven.io/verify/invite?v={invite_token}&organization={org_id}"
            
            # Try with each user
            for user_id in self.session_manager.list_users():
                session = self.session_manager.get_session(user_id)
                response, error = self.handler.make_request(url, user_session=session)
                
                print(f"\nTesting {user_id} accessing {org_id}")
                print(f"Status: {response.status_code if response else 'Error'}")
                if response and response.status_code == 200:
                    print("WARNING: Possible IDOR - User can access other org's invite")
    
    def test_token_enumeration(self):
        """Test if invite tokens can be enumerated"""
        # Get a valid token for reference
        sample_org = next(iter(self.org_invites.keys()))
        valid_token = next(iter(self.org_invites[sample_org]))
        
        # Try slight modifications of the token
        modified_tokens = [
            valid_token[:-1] + "a",  # Change last char
            valid_token[:-2] + "aa",  # Change last 2 chars
            valid_token[1:],          # Remove first char
            "a" + valid_token[1:],    # Change first char
        ]
        
        for token in modified_tokens:
            url = f"https://console.aiven.io/verify/invite?v={token}&organization={sample_org}"
            response, error = self.handler.make_request(
                url, 
                user_session=self.session_manager.get_session("admin")
            )
            
            print(f"\nTesting modified token: {token[:10]}...")
            print(f"Status: {response.status_code if response else 'Error'}")
            if response and response.status_code == 200:
                print("WARNING: Possible token enumeration vulnerability")
    
    def test_token_reuse(self):
        """Test if invite tokens can be reused with different organizations"""
        # Get a valid token from one org and try it with another
        orgs = list(self.org_invites.keys())
        if len(orgs) >= 2:
            token = next(iter(self.org_invites[orgs[0]]))
            target_org = orgs[1]
            
            url = f"https://console.aiven.io/verify/invite?v={token}&organization={target_org}"
            response, error = self.handler.make_request(
                url,
                user_session=self.session_manager.get_session("admin")
            )
            
            print(f"\nTesting token reuse across organizations")
            print(f"Status: {response.status_code if response else 'Error'}")
            if response and response.status_code == 200:
                print("WARNING: Possible token reuse vulnerability")

if __name__ == '__main__':
    unittest.main() 