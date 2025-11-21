# agent/webhook_manager.py
"""
Webhook Manager
Generates secure webhook URLs for CI/CD integration
No YAML files, no secrets - just add webhook URL
"""
import secrets
import hashlib
from typing import Dict, Optional
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)


class WebhookManager:
    """Manage webhook URLs for CI/CD integration"""
    
    def __init__(self):
        # In production, use database (Redis/PostgreSQL)
        # For now, in-memory (will be replaced)
        self.webhooks = {}  # {webhook_id: {token, user_id, created_at, repos}}
    
    def generate_webhook(self, user_id: str, repository: Optional[str] = None) -> Dict[str, str]:
        """
        Generate a secure webhook URL for a user/repository
        
        Returns:
            {
                'webhook_id': str,
                'webhook_url': str,
                'token': str,  # For verification
                'expires_at': str
            }
        """
        # Generate cryptographically secure tokens (64 bytes = 86 chars base64)
        # This ensures uniqueness and security
        webhook_id = secrets.token_urlsafe(48)  # 48 bytes = 64 chars, very secure
        token = secrets.token_urlsafe(64)  # 64 bytes = 86 chars, extremely secure
        
        # Ensure uniqueness (check if exists, regenerate if needed)
        max_attempts = 10
        attempts = 0
        while webhook_id in self.webhooks and attempts < max_attempts:
            webhook_id = secrets.token_urlsafe(48)
            attempts += 1
        
        if attempts >= max_attempts:
            raise ValueError("Failed to generate unique webhook ID")
        
        # Store webhook info
        self.webhooks[webhook_id] = {
            'token': hashlib.sha256(token.encode()).hexdigest(),  # Store hash
            'user_id': user_id,
            'repository': repository,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(days=365),  # 1 year
            'active': True
        }
        
        # Generate webhook URL with secure ID
        # In production, use your actual domain from environment variable
        import os
        api_domain = os.getenv('AEGIS_API_DOMAIN', 'https://api.aegis-iam.com')
        webhook_url = f"{api_domain}/api/cicd/webhook/{webhook_id}"
        
        return {
            'webhook_id': webhook_id,
            'webhook_url': webhook_url,
            'token': token,  # Only shown once - 86 characters, cryptographically secure
            'expires_at': self.webhooks[webhook_id]['expires_at'].isoformat()
        }
    
    def verify_webhook(self, webhook_id: str, token: str) -> bool:
        """Verify webhook token"""
        if webhook_id not in self.webhooks:
            return False
        
        webhook = self.webhooks[webhook_id]
        
        # Check if expired
        if datetime.now() > webhook['expires_at']:
            return False
        
        # Check if active
        if not webhook['active']:
            return False
        
        # Verify token
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token_hash == webhook['token']
    
    def revoke_webhook(self, webhook_id: str) -> bool:
        """Revoke a webhook"""
        if webhook_id not in self.webhooks:
            return False
        
        self.webhooks[webhook_id]['active'] = False
        return True
    
    def get_webhook_info(self, webhook_id: str) -> Optional[Dict]:
        """Get webhook information"""
        return self.webhooks.get(webhook_id)


# Global instance
webhook_manager = WebhookManager()

