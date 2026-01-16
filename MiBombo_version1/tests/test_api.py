
import unittest
import os
import sys
import json
from unittest.mock import MagicMock, patch

# Add root dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock core modules before importing api
sys.modules['core.sniffer'] = MagicMock()
sys.modules['core.analyser'] = MagicMock()
sys.modules['core.SQLiteDB'] = MagicMock()
sys.modules['core.anomaly_detector'] = MagicMock()
# sys.modules['core.auth'] = MagicMock() # We want real auth

from api.api import create_app

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.app, _ = create_app(enable_auth=True)
        self.client = self.app.test_client()
        
        # Reset rate limits
        from core import security
        security._limiter_storage = {}
        
    def test_status(self):
        response = self.client.get('/api/status')
        self.assertEqual(response.status_code, 200)
        
    def test_register_flow(self):
        """Test registration flow."""
        import uuid
        uid = str(uuid.uuid4())[:8]
        data = {
            "username": f"user_{uid}",
            "password": "apipassword",
            "email": f"user_{uid}@test.com",
            "full_name": "API User"
        }
        
        # Register
        with patch('core.mailer.send_email_async') as mock_send:
            response = self.client.post('/api/auth/register', 
                                      data=json.dumps(data),
                                      content_type='application/json')
            if response.status_code != 200:
                print(f"DEBUG REGISTER FAIL: {response.json}")
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json['success'])
            
            # Verify emails sent (admin + user)
            self.assertEqual(mock_send.call_count, 2)

    def test_login_rate_limit(self):
        """Test rate limiting on login."""
        data = {"username": "admin", "password": "wrongpassword"}
        
        # 5 allowed attempts
        for _ in range(5):
             self.client.post('/api/auth/login', 
                            data=json.dumps(data),
                            content_type='application/json')
                            
        # 6th attempt should block
        response = self.client.post('/api/auth/login', 
                                  data=json.dumps(data),
                                  content_type='application/json')
                                  
        self.assertEqual(response.status_code, 429)

if __name__ == '__main__':
    unittest.main()
