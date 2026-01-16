
import unittest
import os
import sys
import shutil

# Add root dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.authentication import AuthenticationManager

class TestAuthManager(unittest.TestCase):
    def setUp(self):
        self.db_path = "tests/test_users.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.auth = AuthenticationManager(db_file=self.db_path)
        
    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            
    def test_default_admin(self):
        """Test si l'admin par défaut est créé."""
        success, msg, user = self.auth.login("admin", "admin")
        self.assertTrue(success)
        self.assertEqual(user["username"], "admin")
        self.assertEqual(user["role"], "admin")
        
    def test_register_user(self):
        """Test inscription publique."""
        username = "newuser"
        password = "newpassword123"
        email = "test@example.com"
        
        success, msg = self.auth.register_user(username, password, email)
        self.assertTrue(success)
        
        # Test login (should fail because inactive)
        success, msg, user = self.auth.login(username, password)
        self.assertFalse(success)
        self.assertIn("désactivé", msg)
        
    def test_create_user_admin(self):
        """Test création utilisateur par admin."""
        # Login admin first
        self.auth.login("admin", "admin")
        
        success, msg = self.auth.create_user("operator1", "operatorpass", role="operator")
        self.assertTrue(success)
        
        # Verify creation
        success, msg, user = self.auth.login("operator1", "operatorpass")
        self.assertTrue(success)
        self.assertEqual(user["role"], "operator")

if __name__ == '__main__':
    unittest.main()
