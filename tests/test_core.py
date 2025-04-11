"""
Test core functionality of IDOR-BAC Hunter
"""

import unittest
from pathlib import Path
from core.session_loader import SessionManager, Session
from core.request_handler import RequestHandler
from core.utils.logger import ScanLogger

class TestSessionLoader(unittest.TestCase):
    """Test session loading and management"""
    
    def setUp(self):
        self.config_path = "config/sessions.json"
        
    def test_session_loading(self):
        """Test loading sessions from config file"""
        session_manager = SessionManager(self.config_path)
        self.assertEqual(len(session_manager), 3)  # admin, user1, user2
        
        # Test admin session
        admin = session_manager.get_session("admin")
        self.assertIsNotNone(admin)
        self.assertEqual(admin.user_id, "admin")
        self.assertIsNotNone(admin.cookie)
        self.assertIsNone(admin.token)
        
        # Test user2 (token auth)
        user2 = session_manager.get_session("user2")
        self.assertIsNotNone(user2)
        self.assertEqual(user2.user_id, "user2")
        self.assertIsNone(user2.cookie)
        self.assertIsNotNone(user2.token)
        
    def test_session_headers(self):
        """Test header generation for different auth types"""
        session_manager = SessionManager(self.config_path)
        
        # Test cookie session headers
        admin = session_manager.get_session("admin")
        headers = admin.get_headers()
        self.assertIn('User-Agent', headers)
        self.assertNotIn('Authorization', headers)
        
        # Test token session headers
        user2 = session_manager.get_session("user2")
        headers = user2.get_headers()
        self.assertIn('Authorization', headers)
        self.assertEqual(headers['Authorization'], user2.token)

class TestRequestHandler(unittest.TestCase):
    """Test HTTP request handling"""
    
    def setUp(self):
        self.handler = RequestHandler(timeout=5)
        self.session = Session(
            user_id="test",
            cookie="sessionid=test123"
        )
    
    def test_request_formation(self):
        """Test request formation with different methods"""
        # Test GET request
        response, error = self.handler.make_request(
            "https://httpbin.org/get",
            method="GET",
            user_session=self.session
        )
        self.assertIsNone(error)
        self.assertEqual(response.status_code, 200)
        
        # Test POST request
        data = {"test": "data"}
        response, error = self.handler.make_request(
            "https://httpbin.org/post",
            method="POST",
            user_session=self.session,
            data=data
        )
        self.assertIsNone(error)
        self.assertEqual(response.status_code, 200)

class TestLogger(unittest.TestCase):
    """Test logging functionality"""
    
    def setUp(self):
        self.output_dir = "output/test"
        self.logger = ScanLogger(self.output_dir, verbose=True)
        
    def tearDown(self):
        # Clean up test output
        import shutil
        if Path(self.output_dir).exists():
            shutil.rmtree(self.output_dir)
    
    def test_finding_logging(self):
        """Test logging security findings"""
        self.logger.log_finding(
            endpoint="/api/users/1001",
            vulnerability_type="IDOR",
            details={
                "description": "User2 can access User1's data",
                "evidence": {
                    "status_code": 200,
                    "unauthorized_access": True
                }
            }
        )
        
        self.assertEqual(len(self.logger.findings), 1)
        finding = self.logger.findings[0]
        self.assertEqual(finding["type"], "IDOR")
        self.assertEqual(finding["endpoint"], "/api/users/1001")
        
        # Test saving results
        self.logger.save_results()
        result_files = list(Path(self.output_dir).glob("findings_*.json"))
        self.assertEqual(len(result_files), 1)

if __name__ == '__main__':
    unittest.main() 