#!/usr/bin/env python3
"""
GitHub App Setup Helper
Generates webhook secret and helps you set up .env file
"""
import secrets
import os

def generate_webhook_secret():
    """Generate a secure webhook secret"""
    return secrets.token_hex(20)

def create_env_template():
    """Create .env file template"""
    webhook_secret = generate_webhook_secret()
    
    template = f"""# GitHub App Configuration
# Get these values from: https://github.com/settings/apps/new

# Your GitHub App ID (number, e.g., 123456)
GITHUB_APP_ID=

# Your GitHub App Private Key (from the .pem file you download)
# Option 1: Single line with \\n (recommended)
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----"

# Option 2: Multi-line (remove quotes and use actual newlines)
# GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
# MIIEpAIBAAKCAQEA...
# (paste all lines here)
# ...
# -----END RSA PRIVATE KEY-----"

# Webhook Secret (generated below - copy this!)
GITHUB_WEBHOOK_SECRET={webhook_secret}

# Optional: For user-level OAuth (if needed later)
# GITHUB_CLIENT_ID=
# GITHUB_CLIENT_SECRET=
"""
    
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    
    if os.path.exists(env_path):
        print(f"WARNING: .env file already exists at: {env_path}")
        response = input("Do you want to overwrite it? (yes/no): ")
        if response.lower() != 'yes':
            print("Cancelled. Keeping existing .env file.")
            return
    
    with open(env_path, 'w') as f:
        f.write(template)
    
    print("SUCCESS: Created .env file template!")
    print(f"\nLocation: {env_path}")
    print(f"\nGenerated Webhook Secret: {webhook_secret}")
    print("\nNext Steps:")
    print("1. Go to: https://github.com/settings/apps/new")
    print("2. Create your GitHub App")
    print("3. Use the webhook secret above when setting up the app")
    print("4. Copy your App ID and Private Key to .env file")
    print("5. Restart your backend server")

if __name__ == "__main__":
    print("GitHub App Setup Helper\n")
    create_env_template()

