"""
Secure AWS Credentials Handler

SECURITY PRINCIPLES:
1. NEVER store user credentials in database or logs
2. Validate credentials before use
3. Pass directly to AWS SDK (boto3/bedrock)
4. Clear from memory after use
5. Rate limit to prevent abuse
"""

import re
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

# Configure logging to NEVER log credentials
logging.basicConfig(level=logging.INFO)


class SecureCredentials:
    """Handle user AWS credentials securely"""
    
    @staticmethod
    def validate_access_key_id(access_key_id: str) -> bool:
        """
        Validate AWS Access Key ID format
        Format: AKIA followed by 16 alphanumeric characters
        """
        if not access_key_id:
            return False
        # AWS Access Key ID format
        pattern = r'^AKIA[A-Z0-9]{16}$'
        return bool(re.match(pattern, access_key_id))
    
    @staticmethod
    def validate_secret_access_key(secret_access_key: str) -> bool:
        """
        Validate AWS Secret Access Key format
        Format: 40 base64-like characters
        """
        if not secret_access_key:
            return False
        # AWS Secret Access Key is 40 characters
        return len(secret_access_key) == 40 and bool(re.match(r'^[A-Za-z0-9+/]+$', secret_access_key))
    
    @staticmethod
    def validate_region(region: str) -> bool:
        """Validate AWS region"""
        valid_regions = [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-central-1', 'eu-north-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
            'ap-south-1', 'sa-east-1', 'ca-central-1'
        ]
        return region in valid_regions
    
    @staticmethod
    def validate_credentials(credentials: Dict[str, str]) -> tuple[bool, Optional[str]]:
        """
        Validate complete AWS credentials
        
        Returns:
            (valid, error_message)
        """
        if not credentials:
            return False, "No credentials provided"
        
        access_key_id = credentials.get('access_key_id', '')
        secret_access_key = credentials.get('secret_access_key', '')
        region = credentials.get('region', '')
        
        if not access_key_id or not secret_access_key or not region:
            return False, "Missing required credential fields"
        
        if not SecureCredentials.validate_access_key_id(access_key_id):
            return False, "Invalid Access Key ID format"
        
        if not SecureCredentials.validate_secret_access_key(secret_access_key):
            return False, "Invalid Secret Access Key format"
        
        if not SecureCredentials.validate_region(region):
            return False, "Invalid AWS region"
        
        return True, None
    
    @staticmethod
    def sanitize_for_logging(credentials: Dict[str, str]) -> Dict[str, str]:
        """
        Sanitize credentials for logging
        NEVER log actual credentials!
        """
        access_key_id = credentials.get('access_key_id', '')
        if access_key_id and len(access_key_id) > 8:
            masked_key = f"{access_key_id[:4]}...{access_key_id[-4:]}"
        else:
            masked_key = "INVALID"
        
        return {
            'access_key_id': masked_key,
            'secret_access_key': '***REDACTED***',
            'region': credentials.get('region', 'UNKNOWN')
        }
    
    @staticmethod
    def create_boto3_session(credentials: Dict[str, str]):
        """
        Create boto3 session with user credentials
        
        SECURITY: Credentials passed directly to boto3, not stored
        """
        import boto3
        
        return boto3.Session(
            aws_access_key_id=credentials['access_key_id'],
            aws_secret_access_key=credentials['secret_access_key'],
            region_name=credentials['region']
        )
    
    @staticmethod
    def create_bedrock_client(credentials: Dict[str, str]):
        """
        Create Bedrock client with user credentials
        
        SECURITY: Credentials used only for this client instance
        """
        session = SecureCredentials.create_boto3_session(credentials)
        return session.client('bedrock-runtime')


# Rate limiting (in-memory, resets on restart)
rate_limit_store: Dict[str, Dict[str, Any]] = {}
MAX_REQUESTS_PER_IP_PER_HOUR = 100  # Prevent abuse


class RateLimiter:
    """Rate limit requests to prevent abuse"""
    
    @staticmethod
    def check_rate_limit(ip_address: str) -> tuple[bool, Optional[str]]:
        """
        Check if IP address has exceeded rate limit
        
        Returns:
            (allowed, error_message)
        """
        now = datetime.now()
        
        if ip_address not in rate_limit_store:
            rate_limit_store[ip_address] = {
                'count': 1,
                'reset_time': now + timedelta(hours=1)
            }
            return True, None
        
        rate_data = rate_limit_store[ip_address]
        
        # Check if reset time has passed
        if now > rate_data['reset_time']:
            rate_limit_store[ip_address] = {
                'count': 1,
                'reset_time': now + timedelta(hours=1)
            }
            return True, None
        
        # Check if under limit
        if rate_data['count'] >= MAX_REQUESTS_PER_IP_PER_HOUR:
            reset_in = int((rate_data['reset_time'] - now).total_seconds() / 60)
            return False, f"Rate limit exceeded. Resets in {reset_in} minutes. Consider self-hosting for unlimited usage."
        
        # Increment count
        rate_data['count'] += 1
        return True, None
    
    @staticmethod
    def get_remaining_requests(ip_address: str) -> int:
        """Get remaining requests for IP address"""
        if ip_address not in rate_limit_store:
            return MAX_REQUESTS_PER_IP_PER_HOUR
        
        rate_data = rate_limit_store[ip_address]
        now = datetime.now()
        
        if now > rate_data['reset_time']:
            return MAX_REQUESTS_PER_IP_PER_HOUR
        
        return MAX_REQUESTS_PER_IP_PER_HOUR - rate_data['count']

