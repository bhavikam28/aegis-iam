"""
AWS Input Validation Utility
Validates AWS account IDs, regions, resource names, etc.
"""
import re
import logging

# Valid AWS regions (as of 2024)
VALID_AWS_REGIONS = {
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
    'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ca-central-1', 'sa-east-1',
    'af-south-1', 'me-south-1', 'eu-south-1',
    'ap-east-1', 'me-central-1'
}

def validate_aws_region(region: str) -> tuple[bool, str]:
    """
    Validate AWS region format.
    Returns: (is_valid, error_message)
    """
    if not region or not isinstance(region, str):
        return False, "Region cannot be empty"
    
    region = region.strip().lower()
    
    # Check if it's a valid AWS region
    if region in VALID_AWS_REGIONS:
        return True, ""
    
    # Check format pattern
    pattern = r'^[a-z]+-[a-z]+-\d+$'
    if not re.match(pattern, region):
        return False, f"Invalid region format: '{region}'. AWS regions follow the pattern: [geographic-area]-[direction]-[number] (e.g., us-east-1, eu-central-1)"
    
    # Format is correct but not in our list (might be newer region)
    # Still validate the pattern
    return True, ""  # Accept if pattern matches, even if not in our list

def validate_account_id(account_id: str) -> tuple[bool, str]:
    """
    Validate AWS account ID.
    AWS account IDs are exactly 12 numeric digits.
    Returns: (is_valid, error_message)
    """
    if not account_id or not isinstance(account_id, str):
        return False, "Account ID cannot be empty"
    
    account_id = account_id.strip()
    
    # Remove common formatting (spaces, hyphens, dots)
    account_id_clean = re.sub(r'[\s\-\.]', '', account_id)
    
    # Must be exactly 12 digits
    if not re.match(r'^\d{12}$', account_id_clean):
        return False, f"Invalid account ID: '{account_id}'. AWS account IDs must be exactly 12 numeric digits (e.g., 123456789012)"
    
    return True, ""

def validate_org_id(org_id: str) -> tuple[bool, str]:
    """
    Validate AWS Organization ID.
    Format: o- followed by 10-12 lowercase alphanumeric characters
    Returns: (is_valid, error_message)
    """
    if not org_id or not isinstance(org_id, str):
        return False, "Organization ID cannot be empty"
    
    org_id = org_id.strip()
    
    # Pattern: o- followed by 10-12 alphanumeric (lowercase)
    pattern = r'^o-[a-z0-9]{10,12}$'
    if not re.match(pattern, org_id):
        return False, f"Invalid Organization ID: '{org_id}'. Format: o- followed by 10-12 lowercase alphanumeric characters (e.g., o-a1b2c3d4e5)"
    
    return True, ""

def validate_ou_id(ou_id: str) -> tuple[bool, str]:
    """
    Validate Organizational Unit ID.
    Format: ou- followed by alphanumeric characters
    Returns: (is_valid, error_message)
    """
    if not ou_id or not isinstance(ou_id, str):
        return False, "OU ID cannot be empty"
    
    ou_id = ou_id.strip()
    
    # Pattern: ou- followed by alphanumeric with hyphens
    pattern = r'^ou-[a-z0-9-]+$'
    if not re.match(pattern, ou_id):
        return False, f"Invalid OU ID: '{ou_id}'. Format: ou- followed by alphanumeric characters and hyphens (e.g., ou-ab12-cdefghij)"
    
    return True, ""

def validate_s3_bucket_name(bucket_name: str) -> tuple[bool, str]:
    """
    Validate S3 bucket name.
    Rules: 3-63 characters, lowercase, numbers, hyphens, dots
    Returns: (is_valid, error_message)
    """
    if not bucket_name or not isinstance(bucket_name, str):
        return False, "Bucket name cannot be empty"
    
    bucket_name = bucket_name.strip()
    
    # Length check
    if len(bucket_name) < 3 or len(bucket_name) > 63:
        return False, f"Invalid bucket name: '{bucket_name}'. Must be 3-63 characters"
    
    # Pattern check: lowercase, numbers, hyphens, dots
    pattern = r'^[a-z0-9.-]+$'
    if not re.match(pattern, bucket_name):
        return False, f"Invalid bucket name: '{bucket_name}'. Must contain only lowercase letters, numbers, hyphens, and dots. No underscores or uppercase letters."
    
    # Cannot start/end with hyphen or dot
    if bucket_name.startswith('-') or bucket_name.startswith('.') or \
       bucket_name.endswith('-') or bucket_name.endswith('.'):
        return False, f"Invalid bucket name: '{bucket_name}'. Cannot start or end with hyphen or dot"
    
    return True, ""

def extract_and_validate_aws_values(text: str) -> dict:
    """
    Extract AWS account ID, region, etc. from user text and validate them.
    Returns dict with validated values and any errors.
    """
    result = {
        'account_id': None,
        'region': None,
        'errors': [],
        'warnings': []
    }
    
    # Extract account ID (12 digits)
    account_id_match = re.search(r'\b(\d{12})\b', text)
    if account_id_match:
        account_id = account_id_match.group(1)
        is_valid, error = validate_account_id(account_id)
        if is_valid:
            result['account_id'] = account_id
        else:
            result['errors'].append(error)
    
    # Extract region (common patterns)
    region_patterns = [
        r'\b(us|eu|ap|ca|sa|af|me)-(east|west|central|south|north|southeast|southwest|northeast|northwest)-\d+\b',
        r'\bregion[:\s]+([a-z]+-[a-z]+-\d+)\b',
    ]
    
    for pattern in region_patterns:
        region_match = re.search(pattern, text, re.IGNORECASE)
        if region_match:
            region = region_match.group(1).lower() if len(region_match.groups()) > 0 else region_match.group(0).lower()
            is_valid, error = validate_aws_region(region)
            if is_valid:
                result['region'] = region
                break
            else:
                result['errors'].append(error)
    
    return result

