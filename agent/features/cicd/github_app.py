# agent/github_app.py
"""
GitHub App OAuth Handler
Manages GitHub App authentication and installation tokens
"""
import os
try:
    import jwt
except ImportError:
    # PyJWT is the package name, but it's imported as 'jwt'
    # Install with: pip install PyJWT
    raise ImportError(
        "PyJWT not installed. Please install it with: pip install PyJWT\n"
        "Or install all requirements: pip install -r requirements.txt"
    )
import time
import requests
import logging
from typing import Dict, Optional
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)


class GitHubApp:
    """Handle GitHub App authentication and token management"""
    
    def __init__(self):
        # Get from environment variables (set these after registering GitHub App)
        self.app_id = os.getenv('GITHUB_APP_ID', '')
        self.private_key = os.getenv('GITHUB_PRIVATE_KEY', '').replace('\\n', '\n')
        self.webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET', '')
        
        # In-memory storage for installations (in production, use database)
        self.installations = {}  # {installation_id: {token, expires_at, account}}
        
        # OAuth client ID/secret (for user-level OAuth, if needed)
        self.client_id = os.getenv('GITHUB_CLIENT_ID', '')
        self.client_secret = os.getenv('GITHUB_CLIENT_SECRET', '')
    
    def generate_jwt(self) -> str:
        """
        Generate JWT token for GitHub App authentication
        Valid for 10 minutes
        """
        if not self.app_id or not self.private_key:
            raise ValueError("GITHUB_APP_ID and GITHUB_PRIVATE_KEY must be set")
        
        now = int(time.time())
        payload = {
            'iat': now - 60,  # Issued at (1 minute ago to account for clock skew)
            'exp': now + (10 * 60),  # Expires in 10 minutes
            'iss': self.app_id  # Issuer (App ID)
        }
        
        try:
            token = jwt.encode(payload, self.private_key, algorithm='RS256')
            return token
        except Exception as e:
            logging.error(f"❌ Failed to generate JWT: {e}")
            raise
    
    def get_installation_token(self, installation_id: int) -> Optional[str]:
        """
        Get or refresh installation access token
        Tokens are valid for 1 hour
        """
        # Check if we have a valid token cached
        if installation_id in self.installations:
            installation = self.installations[installation_id]
            if installation['expires_at'] > datetime.now():
                return installation['token']
        
        # Generate new token
        jwt_token = self.generate_jwt()
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            token = data['token']
            expires_at = datetime.fromisoformat(data['expires_at'].replace('Z', '+00:00'))
            
            # Cache the token
            self.installations[installation_id] = {
                'token': token,
                'expires_at': expires_at,
                'account': data.get('account', {})
            }
            
            logging.info(f"✅ Generated installation token for installation {installation_id}")
            return token
            
        except Exception as e:
            logging.error(f"❌ Failed to get installation token: {e}")
            return None
    
    def get_installation_id(self, owner: str, repo: str) -> Optional[int]:
        """
        Get installation ID for a repository
        """
        jwt_token = self.generate_jwt()
        url = f"https://api.github.com/repos/{owner}/{repo}/installation"
        
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 404:
                return None  # App not installed
            response.raise_for_status()
            data = response.json()
            return data.get('id')
        except Exception as e:
            logging.error(f"❌ Failed to get installation ID: {e}")
            return None
    
    def verify_webhook_signature(self, payload_body: bytes, signature: str) -> bool:
        """
        Verify GitHub webhook signature using HMAC
        """
        if not self.webhook_secret:
            logging.warning("⚠️ GITHUB_WEBHOOK_SECRET not set, skipping signature verification")
            return True  # Allow if secret not set (for development)
        
        import hmac
        import hashlib
        
        expected_signature = hmac.new(
            self.webhook_secret.encode(),
            msg=payload_body,
            digestmod=hashlib.sha256
        ).hexdigest()
        
        # GitHub sends signature as "sha256=<hash>"
        if signature.startswith('sha256='):
            signature = signature[7:]
        
        return hmac.compare_digest(expected_signature, signature)
    
    def get_oauth_url(self, redirect_uri: str, state: Optional[str] = None) -> str:
        """
        Generate GitHub OAuth URL for user authentication
        """
        if not self.client_id:
            raise ValueError("GITHUB_CLIENT_ID must be set")
        
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': 'read:org read:user',
            'state': state or 'default'
        }
        
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"https://github.com/login/oauth/authorize?{query_string}"
    
    def exchange_code_for_token(self, code: str) -> Optional[Dict]:
        """
        Exchange OAuth code for access token
        """
        if not self.client_id or not self.client_secret:
            raise ValueError("GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set")
        
        url = "https://github.com/login/oauth/access_token"
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code
        }
        headers = {'Accept': 'application/json'}
        
        try:
            response = requests.post(url, data=data, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logging.error(f"❌ Failed to exchange code for token: {e}")
            return None


# Global instance
github_app = GitHubApp()

