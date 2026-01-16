import sys
import os
sys.path.append(os.getcwd())
from core.secure_authentication import SecureAuthenticationManager

def test_email_validation():
    auth = SecureAuthenticationManager()
    
    valid_emails = [
        "test@example.com",
        "user.name@domain.co.uk",
        "valid-email@sub.domain.org"
    ]
    
    invalid_emails = [
        "tartenfion@gmail?com",
        "invalid.email",
        "user@domain",
        "@domain.com",
        "user@.com"
    ]
    
    print("--- Testing Valid Emails ---")
    for email in valid_emails:
        is_valid = auth._is_valid_email(email)
        print(f"'{email}': {'PASS' if is_valid else 'FAIL'}")
        
    print("\n--- Testing Invalid Emails ---")
    for email in invalid_emails:
        is_valid = auth._is_valid_email(email)
        print(f"'{email}': {'PASS' if not is_valid else 'FAIL'} (Expected Invalid)")

if __name__ == "__main__":
    test_email_validation()
