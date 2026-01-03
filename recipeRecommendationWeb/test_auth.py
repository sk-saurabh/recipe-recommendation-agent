#!/usr/bin/env python3
"""Test script for Cognito authentication functionality."""

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import authenticate_user_cognito, register_user_cognito, COGNITO_CLIENT_ID

def test_registration():
    """Test user registration with Cognito."""
    print("Testing user registration...")
    
    # Test data
    test_username = "testuser123"
    test_email = "test@example.com"
    test_password = ""
    
    result = register_user_cognito(test_username, test_email, test_password)
    
    if result:
        print(f"✅ Registration successful: {result}")
        return True
    else:
        print("❌ Registration failed")
        return False

def test_authentication():
    """Test user authentication with Cognito."""
    print("Testing user authentication...")
    
    # Test with existing user credentials
    test_username = "testuser"  # Use existing test user
    test_password = "MyPassword123!"
    
    result = authenticate_user_cognito(test_username, test_password)
    
    if result:
        print(f"✅ Authentication successful:")
        print(f"   Username: {result['username']}")
        print(f"   Email: {result['email']}")
        print(f"   User ID: {result['user_id']}")
        print(f"   Token length: {len(result['bearer_token'])}")
        return True
    else:
        print("❌ Authentication failed")
        return False

if __name__ == "__main__":
    print(f"Using Cognito Client ID: {COGNITO_CLIENT_ID}")
    print("-" * 50)
    
    # Test authentication with existing user
    auth_success = test_authentication()
    
    print("-" * 50)
    print(f"Authentication test: {'PASSED' if auth_success else 'FAILED'}")