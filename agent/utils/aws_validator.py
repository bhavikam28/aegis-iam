"""
Comprehensive AWS Input Validation Utility
Validates ALL AWS resource types, identifiers, ARNs, and formats dynamically.
Uses pattern matching to handle new AWS services and resources automatically.
"""
import re
import logging
from utils.aws_constants import KNOWN_AWS_REGIONS, VALID_REGION_PREFIXES, validate_region_hybrid

# Valid AWS regions (as of 2025) - Complete official list
# AWS has 38 geographic regions. This list must be kept up-to-date.
# NOTE: This is now imported from aws_constants.py for consistency
VALID_AWS_REGIONS = KNOWN_AWS_REGIONS

def validate_aws_region(region: str, strict: bool = True) -> tuple[bool, str]:
    """
    Validate AWS region using hybrid approach.
    
    Hybrid validation strategy:
    1. First checks against known AWS regions list (fast, accurate for existing regions)
    2. If not found, validates format pattern (handles new AWS regions)
    3. If format is valid but not in list:
       - strict=True: Rejects with helpful error (default - production mode)
       - strict=False: Accepts with warning (development/testing mode for new regions)
    
    This approach ensures:
    - Fast validation for known regions
    - Future-proof for new AWS regions (format validation)
    - Prevents invalid regions (format check)
    - Can be updated easily when AWS announces new regions
    
    Args:
        region: Region string to validate
        strict: If True (default), only accept known regions. If False, accept format-valid regions.
    
    Returns:
        (is_valid, error_message)
    """
    is_valid, error_msg, is_known = validate_region_hybrid(region, strict=strict)
    
    if is_valid and not is_known:
        # Format-valid but not in known list - return warning as error message
        # In production, we want to be strict, but the message helps identify new regions
        if strict:
            # Extract the actual error from the warning
            return False, error_msg
        else:
            # Lenient mode: accept but log warning
            logging.warning(f"⚠️ Region '{region}' accepted but not in known list: {error_msg}")
            return True, ""
    
    return is_valid, error_msg

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

def validate_vpc_endpoint(vpc_endpoint: str) -> tuple[bool, str]:
    """
    Validate VPC endpoint ID format.
    Format: vpce- followed by 17 alphanumeric characters
    Returns: (is_valid, error_message)
    """
    if not vpc_endpoint or not isinstance(vpc_endpoint, str):
        return False, "VPC endpoint cannot be empty"
    
    vpc_endpoint = vpc_endpoint.strip().lower()
    
    # Pattern: vpce- followed by 17 alphanumeric characters
    pattern = r'^vpce-[a-z0-9]{17}$'
    if not re.match(pattern, vpc_endpoint):
        return False, f"Invalid VPC endpoint: '{vpc_endpoint}'. Format: vpce- followed by 17 alphanumeric characters (e.g., vpce-1234567890abcdef)"
    
    return True, ""

def validate_arn(arn: str) -> tuple[bool, str]:
    """
    Validate AWS ARN format dynamically.
    Format: arn:partition:service:region:account-id:resource-type/resource-name
    Returns: (is_valid, error_message)
    """
    if not arn or not isinstance(arn, str):
        return False, "ARN cannot be empty"
    
    arn = arn.strip()
    
    # Comprehensive ARN pattern - handles all AWS services
    # Pattern: arn:partition:service:region:account-id:resource
    # Some services don't require region/account (e.g., S3, IAM)
    pattern = r'^arn:aws[a-z0-9-]*:[a-z0-9-]+(:[a-z0-9-]*)?(:[0-9]{0,12})?(:[a-z0-9\-_/\.*]+)?$'
    if not re.match(pattern, arn):
        return False, f"Invalid ARN format: '{arn}'. ARNs follow: arn:partition:service:region:account-id:resource-type/resource-name"
    
    return True, ""

# ============================================================================
# EC2 RESOURCE VALIDATION
# ============================================================================

def validate_ec2_instance_id(instance_id: str) -> tuple[bool, str]:
    """Validate EC2 instance ID: i- followed by 17 alphanumeric characters"""
    if not instance_id or not isinstance(instance_id, str):
        return False, "EC2 instance ID cannot be empty"
    instance_id = instance_id.strip().lower()
    pattern = r'^i-[a-z0-9]{17}$'
    if not re.match(pattern, instance_id):
        return False, f"Invalid EC2 instance ID: '{instance_id}'. Format: i- followed by 17 alphanumeric characters (e.g., i-1234567890abcdef0)"
    return True, ""

def validate_security_group_id(sg_id: str) -> tuple[bool, str]:
    """Validate Security Group ID: sg- followed by 17 alphanumeric characters"""
    if not sg_id or not isinstance(sg_id, str):
        return False, "Security Group ID cannot be empty"
    sg_id = sg_id.strip().lower()
    pattern = r'^sg-[a-z0-9]{17}$'
    if not re.match(pattern, sg_id):
        return False, f"Invalid Security Group ID: '{sg_id}'. Format: sg- followed by 17 alphanumeric characters (e.g., sg-1234567890abcdef0)"
    return True, ""

def validate_vpc_id(vpc_id: str) -> tuple[bool, str]:
    """Validate VPC ID: vpc- followed by 17 alphanumeric characters"""
    if not vpc_id or not isinstance(vpc_id, str):
        return False, "VPC ID cannot be empty"
    vpc_id = vpc_id.strip().lower()
    pattern = r'^vpc-[a-z0-9]{17}$'
    if not re.match(pattern, vpc_id):
        return False, f"Invalid VPC ID: '{vpc_id}'. Format: vpc- followed by 17 alphanumeric characters (e.g., vpc-1234567890abcdef0)"
    return True, ""

def validate_subnet_id(subnet_id: str) -> tuple[bool, str]:
    """Validate Subnet ID: subnet- followed by 17 alphanumeric characters"""
    if not subnet_id or not isinstance(subnet_id, str):
        return False, "Subnet ID cannot be empty"
    subnet_id = subnet_id.strip().lower()
    pattern = r'^subnet-[a-z0-9]{17}$'
    if not re.match(pattern, subnet_id):
        return False, f"Invalid Subnet ID: '{subnet_id}'. Format: subnet- followed by 17 alphanumeric characters (e.g., subnet-1234567890abcdef0)"
    return True, ""

def validate_route_table_id(rt_id: str) -> tuple[bool, str]:
    """Validate Route Table ID: rtb- followed by 17 alphanumeric characters"""
    if not rt_id or not isinstance(rt_id, str):
        return False, "Route Table ID cannot be empty"
    rt_id = rt_id.strip().lower()
    pattern = r'^rtb-[a-z0-9]{17}$'
    if not re.match(pattern, rt_id):
        return False, f"Invalid Route Table ID: '{rt_id}'. Format: rtb- followed by 17 alphanumeric characters (e.g., rtb-1234567890abcdef0)"
    return True, ""

def validate_internet_gateway_id(igw_id: str) -> tuple[bool, str]:
    """Validate Internet Gateway ID: igw- followed by 17 alphanumeric characters"""
    if not igw_id or not isinstance(igw_id, str):
        return False, "Internet Gateway ID cannot be empty"
    igw_id = igw_id.strip().lower()
    pattern = r'^igw-[a-z0-9]{17}$'
    if not re.match(pattern, igw_id):
        return False, f"Invalid Internet Gateway ID: '{igw_id}'. Format: igw- followed by 17 alphanumeric characters (e.g., igw-1234567890abcdef0)"
    return True, ""

def validate_nat_gateway_id(nat_id: str) -> tuple[bool, str]:
    """Validate NAT Gateway ID: nat- followed by 17 alphanumeric characters"""
    if not nat_id or not isinstance(nat_id, str):
        return False, "NAT Gateway ID cannot be empty"
    nat_id = nat_id.strip().lower()
    pattern = r'^nat-[a-z0-9]{17}$'
    if not re.match(pattern, nat_id):
        return False, f"Invalid NAT Gateway ID: '{nat_id}'. Format: nat- followed by 17 alphanumeric characters (e.g., nat-1234567890abcdef0)"
    return True, ""

# ============================================================================
# LAMBDA VALIDATION
# ============================================================================

def validate_lambda_function_name(function_name: str) -> tuple[bool, str]:
    """Validate Lambda function name: 1-64 characters, alphanumeric, hyphens, underscores"""
    if not function_name or not isinstance(function_name, str):
        return False, "Lambda function name cannot be empty"
    function_name = function_name.strip()
    if len(function_name) < 1 or len(function_name) > 64:
        return False, f"Invalid Lambda function name: '{function_name}'. Must be 1-64 characters"
    pattern = r'^[a-zA-Z0-9-_]+$'
    if not re.match(pattern, function_name):
        return False, f"Invalid Lambda function name: '{function_name}'. Must contain only alphanumeric characters, hyphens, and underscores"
    return True, ""

# ============================================================================
# DYNAMODB VALIDATION
# ============================================================================

def validate_dynamodb_table_name(table_name: str) -> tuple[bool, str]:
    """Validate DynamoDB table name: 3-255 characters, alphanumeric, hyphens, underscores, dots"""
    if not table_name or not isinstance(table_name, str):
        return False, "DynamoDB table name cannot be empty"
    table_name = table_name.strip()
    if len(table_name) < 3 or len(table_name) > 255:
        return False, f"Invalid DynamoDB table name: '{table_name}'. Must be 3-255 characters"
    pattern = r'^[a-zA-Z0-9_.-]+$'
    if not re.match(pattern, table_name):
        return False, f"Invalid DynamoDB table name: '{table_name}'. Must contain only alphanumeric characters, hyphens, underscores, and dots"
    return True, ""

# ============================================================================
# RDS VALIDATION
# ============================================================================

def validate_rds_instance_identifier(identifier: str) -> tuple[bool, str]:
    """Validate RDS instance identifier: 1-63 characters, alphanumeric, hyphens"""
    if not identifier or not isinstance(identifier, str):
        return False, "RDS instance identifier cannot be empty"
    identifier = identifier.strip()
    if len(identifier) < 1 or len(identifier) > 63:
        return False, f"Invalid RDS instance identifier: '{identifier}'. Must be 1-63 characters"
    pattern = r'^[a-z][a-z0-9-]*$'
    if not re.match(pattern, identifier.lower()):
        return False, f"Invalid RDS instance identifier: '{identifier}'. Must start with a letter, contain only lowercase letters, numbers, and hyphens"
    if identifier.endswith('-'):
        return False, f"Invalid RDS instance identifier: '{identifier}'. Cannot end with a hyphen"
    return True, ""

# ============================================================================
# ECS VALIDATION
# ============================================================================

def validate_ecs_cluster_name(cluster_name: str) -> tuple[bool, str]:
    """Validate ECS cluster name: 1-255 characters, alphanumeric, hyphens, underscores"""
    if not cluster_name or not isinstance(cluster_name, str):
        return False, "ECS cluster name cannot be empty"
    cluster_name = cluster_name.strip()
    if len(cluster_name) < 1 or len(cluster_name) > 255:
        return False, f"Invalid ECS cluster name: '{cluster_name}'. Must be 1-255 characters"
    pattern = r'^[a-zA-Z0-9_-]+$'
    if not re.match(pattern, cluster_name):
        return False, f"Invalid ECS cluster name: '{cluster_name}'. Must contain only alphanumeric characters, hyphens, and underscores"
    return True, ""

def validate_ecs_service_name(service_name: str) -> tuple[bool, str]:
    """Validate ECS service name: 1-255 characters, alphanumeric, hyphens, underscores"""
    if not service_name or not isinstance(service_name, str):
        return False, "ECS service name cannot be empty"
    service_name = service_name.strip()
    if len(service_name) < 1 or len(service_name) > 255:
        return False, f"Invalid ECS service name: '{service_name}'. Must be 1-255 characters"
    pattern = r'^[a-zA-Z0-9_-]+$'
    if not re.match(pattern, service_name):
        return False, f"Invalid ECS service name: '{service_name}'. Must contain only alphanumeric characters, hyphens, and underscores"
    return True, ""

# ============================================================================
# EKS VALIDATION
# ============================================================================

def validate_eks_cluster_name(cluster_name: str) -> tuple[bool, str]:
    """Validate EKS cluster name: 1-100 characters, alphanumeric, hyphens"""
    if not cluster_name or not isinstance(cluster_name, str):
        return False, "EKS cluster name cannot be empty"
    cluster_name = cluster_name.strip()
    if len(cluster_name) < 1 or len(cluster_name) > 100:
        return False, f"Invalid EKS cluster name: '{cluster_name}'. Must be 1-100 characters"
    pattern = r'^[a-zA-Z0-9-]+$'
    if not re.match(pattern, cluster_name):
        return False, f"Invalid EKS cluster name: '{cluster_name}'. Must contain only alphanumeric characters and hyphens"
    return True, ""

# ============================================================================
# SNS VALIDATION
# ============================================================================

def validate_sns_topic_name(topic_name: str) -> tuple[bool, str]:
    """Validate SNS topic name: 1-256 characters, alphanumeric, hyphens, underscores"""
    if not topic_name or not isinstance(topic_name, str):
        return False, "SNS topic name cannot be empty"
    topic_name = topic_name.strip()
    if len(topic_name) < 1 or len(topic_name) > 256:
        return False, f"Invalid SNS topic name: '{topic_name}'. Must be 1-256 characters"
    pattern = r'^[a-zA-Z0-9_-]+$'
    if not re.match(pattern, topic_name):
        return False, f"Invalid SNS topic name: '{topic_name}'. Must contain only alphanumeric characters, hyphens, and underscores"
    return True, ""

# ============================================================================
# SQS VALIDATION
# ============================================================================

def validate_sqs_queue_name(queue_name: str) -> tuple[bool, str]:
    """Validate SQS queue name: 1-80 characters, alphanumeric, hyphens, underscores"""
    if not queue_name or not isinstance(queue_name, str):
        return False, "SQS queue name cannot be empty"
    queue_name = queue_name.strip()
    if len(queue_name) < 1 or len(queue_name) > 80:
        return False, f"Invalid SQS queue name: '{queue_name}'. Must be 1-80 characters"
    pattern = r'^[a-zA-Z0-9_-]+$'
    if not re.match(pattern, queue_name):
        return False, f"Invalid SQS queue name: '{queue_name}'. Must contain only alphanumeric characters, hyphens, and underscores"
    return True, ""

# ============================================================================
# KMS VALIDATION
# ============================================================================

def validate_kms_key_id(key_id: str) -> tuple[bool, str]:
    """Validate KMS key ID: Can be key ID (1-256 chars), key ARN, or alias (alias/name)"""
    if not key_id or not isinstance(key_id, str):
        return False, "KMS key ID cannot be empty"
    key_id = key_id.strip()
    
    # Check if it's an ARN
    if key_id.startswith('arn:aws:kms:'):
        is_valid, error = validate_arn(key_id)
        if is_valid:
            return True, ""
        return False, f"Invalid KMS key ARN: {error}"
    
    # Check if it's an alias
    if key_id.startswith('alias/'):
        alias_name = key_id[6:]  # Remove 'alias/' prefix
        if len(alias_name) < 1 or len(alias_name) > 256:
            return False, f"Invalid KMS alias: '{key_id}'. Alias name must be 1-256 characters after 'alias/'"
        pattern = r'^[a-zA-Z0-9:/_-]+$'
        if not re.match(pattern, alias_name):
            return False, f"Invalid KMS alias: '{key_id}'. Alias name must contain only alphanumeric characters, colons, slashes, hyphens, and underscores"
        return True, ""
    
    # Check if it's a key ID (UUID format)
    key_id_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    if re.match(key_id_pattern, key_id.lower()):
        return True, ""
    
    # Generic key ID (1-256 characters)
    if len(key_id) < 1 or len(key_id) > 256:
        return False, f"Invalid KMS key ID: '{key_id}'. Must be 1-256 characters, a UUID, an ARN, or alias/name format"
    
    return True, ""

# ============================================================================
# SECRETS MANAGER VALIDATION
# ============================================================================

def validate_secrets_manager_secret_name(secret_name: str) -> tuple[bool, str]:
    """Validate Secrets Manager secret name: 1-512 characters, alphanumeric, /_+=.@-"""
    if not secret_name or not isinstance(secret_name, str):
        return False, "Secrets Manager secret name cannot be empty"
    secret_name = secret_name.strip()
    if len(secret_name) < 1 or len(secret_name) > 512:
        return False, f"Invalid Secrets Manager secret name: '{secret_name}'. Must be 1-512 characters"
    pattern = r'^[a-zA-Z0-9/_+=.@-]+$'
    if not re.match(pattern, secret_name):
        return False, f"Invalid Secrets Manager secret name: '{secret_name}'. Must contain only alphanumeric characters, /, _, +, =, ., @, and hyphens"
    return True, ""

# ============================================================================
# CLOUDWATCH VALIDATION
# ============================================================================

def validate_cloudwatch_log_group_name(log_group: str) -> tuple[bool, str]:
    """Validate CloudWatch Log Group name: 1-512 characters, alphanumeric, hyphens, underscores, forward slashes, dots"""
    if not log_group or not isinstance(log_group, str):
        return False, "CloudWatch Log Group name cannot be empty"
    log_group = log_group.strip()
    if len(log_group) < 1 or len(log_group) > 512:
        return False, f"Invalid CloudWatch Log Group name: '{log_group}'. Must be 1-512 characters"
    pattern = r'^[a-zA-Z0-9_/.-]+$'
    if not re.match(pattern, log_group):
        return False, f"Invalid CloudWatch Log Group name: '{log_group}'. Must contain only alphanumeric characters, hyphens, underscores, forward slashes, and dots"
    if log_group.startswith('/'):
        # Log groups starting with / are valid (e.g., /aws/lambda/function-name)
        return True, ""
    return True, ""

def validate_cloudwatch_log_stream_name(log_stream: str) -> tuple[bool, str]:
    """Validate CloudWatch Log Stream name: 1-512 characters, alphanumeric, hyphens, underscores"""
    if not log_stream or not isinstance(log_stream, str):
        return False, "CloudWatch Log Stream name cannot be empty"
    log_stream = log_stream.strip()
    if len(log_stream) < 1 or len(log_stream) > 512:
        return False, f"Invalid CloudWatch Log Stream name: '{log_stream}'. Must be 1-512 characters"
    pattern = r'^[a-zA-Z0-9_-]+$'
    if not re.match(pattern, log_stream):
        return False, f"Invalid CloudWatch Log Stream name: '{log_stream}'. Must contain only alphanumeric characters, hyphens, and underscores"
    return True, ""

# ============================================================================
# EVENTBRIDGE VALIDATION
# ============================================================================

def validate_eventbridge_rule_name(rule_name: str) -> tuple[bool, str]:
    """Validate EventBridge rule name: 1-64 characters, alphanumeric, hyphens, underscores"""
    if not rule_name or not isinstance(rule_name, str):
        return False, "EventBridge rule name cannot be empty"
    rule_name = rule_name.strip()
    if len(rule_name) < 1 or len(rule_name) > 64:
        return False, f"Invalid EventBridge rule name: '{rule_name}'. Must be 1-64 characters"
    pattern = r'^[a-zA-Z0-9_-]+$'
    if not re.match(pattern, rule_name):
        return False, f"Invalid EventBridge rule name: '{rule_name}'. Must contain only alphanumeric characters, hyphens, and underscores"
    return True, ""

# ============================================================================
# STEP FUNCTIONS VALIDATION
# ============================================================================

def validate_stepfunctions_state_machine_name(state_machine_name: str) -> tuple[bool, str]:
    """Validate Step Functions state machine name: 1-80 characters, alphanumeric, hyphens, underscores"""
    if not state_machine_name or not isinstance(state_machine_name, str):
        return False, "Step Functions state machine name cannot be empty"
    state_machine_name = state_machine_name.strip()
    if len(state_machine_name) < 1 or len(state_machine_name) > 80:
        return False, f"Invalid Step Functions state machine name: '{state_machine_name}'. Must be 1-80 characters"
    pattern = r'^[a-zA-Z0-9_-]+$'
    if not re.match(pattern, state_machine_name):
        return False, f"Invalid Step Functions state machine name: '{state_machine_name}'. Must contain only alphanumeric characters, hyphens, and underscores"
    return True, ""

# ============================================================================
# API GATEWAY VALIDATION
# ============================================================================

def validate_apigateway_api_id(api_id: str) -> tuple[bool, str]:
    """Validate API Gateway API ID: alphanumeric string"""
    if not api_id or not isinstance(api_id, str):
        return False, "API Gateway API ID cannot be empty"
    api_id = api_id.strip().lower()
    pattern = r'^[a-z0-9]+$'
    if not re.match(pattern, api_id):
        return False, f"Invalid API Gateway API ID: '{api_id}'. Must contain only alphanumeric characters"
    return True, ""

def validate_apigateway_stage_name(stage_name: str) -> tuple[bool, str]:
    """Validate API Gateway stage name: 1-128 characters, alphanumeric, hyphens"""
    if not stage_name or not isinstance(stage_name, str):
        return False, "API Gateway stage name cannot be empty"
    stage_name = stage_name.strip()
    if len(stage_name) < 1 or len(stage_name) > 128:
        return False, f"Invalid API Gateway stage name: '{stage_name}'. Must be 1-128 characters"
    pattern = r'^[a-zA-Z0-9-]+$'
    if not re.match(pattern, stage_name):
        return False, f"Invalid API Gateway stage name: '{stage_name}'. Must contain only alphanumeric characters and hyphens"
    return True, ""

# ============================================================================
# COGNITO VALIDATION
# ============================================================================

def validate_cognito_user_pool_id(pool_id: str) -> tuple[bool, str]:
    """Validate Cognito User Pool ID: region_ followed by alphanumeric"""
    if not pool_id or not isinstance(pool_id, str):
        return False, "Cognito User Pool ID cannot be empty"
    pool_id = pool_id.strip()
    # Format: region_XXXXXXXXX (e.g., us-east-1_XXXXXXXXX)
    pattern = r'^[a-z]+-[a-z]+-\d+_[a-zA-Z0-9]+$'
    if not re.match(pattern, pool_id.lower()):
        return False, f"Invalid Cognito User Pool ID: '{pool_id}'. Format: region_XXXXXXXXX (e.g., us-east-1_XXXXXXXXX)"
    return True, ""

def validate_cognito_identity_pool_id(pool_id: str) -> tuple[bool, str]:
    """Validate Cognito Identity Pool ID: region: followed by UUID"""
    if not pool_id or not isinstance(pool_id, str):
        return False, "Cognito Identity Pool ID cannot be empty"
    pool_id = pool_id.strip()
    # Format: region:uuid (e.g., us-east-1:12345678-1234-1234-1234-123456789012)
    pattern = r'^[a-z]+-[a-z]+-\d+:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    if not re.match(pattern, pool_id.lower()):
        return False, f"Invalid Cognito Identity Pool ID: '{pool_id}'. Format: region:uuid (e.g., us-east-1:12345678-1234-1234-1234-123456789012)"
    return True, ""

# ============================================================================
# IAM VALIDATION
# ============================================================================

def validate_iam_role_name(role_name: str) -> tuple[bool, str]:
    """Validate IAM role name: 1-64 characters, alphanumeric, +=,.@-_"""
    if not role_name or not isinstance(role_name, str):
        return False, "IAM role name cannot be empty"
    role_name = role_name.strip()
    if len(role_name) < 1 or len(role_name) > 64:
        return False, f"Invalid IAM role name: '{role_name}'. Must be 1-64 characters"
    pattern = r'^[a-zA-Z0-9+=,.@_-]+$'
    if not re.match(pattern, role_name):
        return False, f"Invalid IAM role name: '{role_name}'. Must contain only alphanumeric characters and +=,.@-_"
    return True, ""

def validate_iam_user_name(user_name: str) -> tuple[bool, str]:
    """Validate IAM user name: 1-64 characters, alphanumeric, +=,.@-_"""
    if not user_name or not isinstance(user_name, str):
        return False, "IAM user name cannot be empty"
    user_name = user_name.strip()
    if len(user_name) < 1 or len(user_name) > 64:
        return False, f"Invalid IAM user name: '{user_name}'. Must be 1-64 characters"
    pattern = r'^[a-zA-Z0-9+=,.@_-]+$'
    if not re.match(pattern, user_name):
        return False, f"Invalid IAM user name: '{user_name}'. Must contain only alphanumeric characters and +=,.@-_"
    return True, ""

def validate_iam_policy_name(policy_name: str) -> tuple[bool, str]:
    """Validate IAM policy name: 1-128 characters, alphanumeric, +=,.@-_"""
    if not policy_name or not isinstance(policy_name, str):
        return False, "IAM policy name cannot be empty"
    policy_name = policy_name.strip()
    if len(policy_name) < 1 or len(policy_name) > 128:
        return False, f"Invalid IAM policy name: '{policy_name}'. Must be 1-128 characters"
    pattern = r'^[a-zA-Z0-9+=,.@_-]+$'
    if not re.match(pattern, policy_name):
        return False, f"Invalid IAM policy name: '{policy_name}'. Must contain only alphanumeric characters and +=,.@-_"
    return True, ""

# ============================================================================
# COMPREHENSIVE EXTRACTION AND VALIDATION
# ============================================================================

def validate_aws_resource_identifier(identifier: str, resource_type: str = None) -> tuple[bool, str]:
    """
    Comprehensive validation for ANY AWS resource identifier.
    Automatically detects resource type from format and validates accordingly.
    Returns: (is_valid, error_message)
    """
    if not identifier or not isinstance(identifier, str):
        return False, "Resource identifier cannot be empty"
    
    identifier = identifier.strip()
    
    # Try to detect resource type from format
    # EC2 Resources
    if identifier.startswith('i-') and len(identifier) == 19:
        return validate_ec2_instance_id(identifier)
    elif identifier.startswith('sg-'):
        return validate_security_group_id(identifier)
    elif identifier.startswith('vpc-'):
        return validate_vpc_id(identifier)
    elif identifier.startswith('subnet-'):
        return validate_subnet_id(identifier)
    elif identifier.startswith('rtb-'):
        return validate_route_table_id(identifier)
    elif identifier.startswith('igw-'):
        return validate_internet_gateway_id(identifier)
    elif identifier.startswith('nat-'):
        return validate_nat_gateway_id(identifier)
    # VPC Endpoint
    elif identifier.startswith('vpce-'):
        return validate_vpc_endpoint(identifier)
    # ARN
    elif identifier.startswith('arn:aws'):
        return validate_arn(identifier)
    # Organization/OU
    elif identifier.startswith('o-'):
        return validate_org_id(identifier)
    elif identifier.startswith('ou-'):
        return validate_ou_id(identifier)
    # KMS (alias)
    elif identifier.startswith('alias/'):
        return validate_kms_key_id(identifier)
    # Cognito
    elif ':' in identifier and len(identifier.split(':')) == 2:
        parts = identifier.split(':')
        if len(parts[1]) == 36 and '-' in parts[1]:  # UUID format
            return validate_cognito_identity_pool_id(identifier)
    elif '_' in identifier and len(identifier.split('_')) == 2:
        return validate_cognito_user_pool_id(identifier)
    
    # If resource_type is specified, use specific validator
    if resource_type:
        validators = {
            'lambda': validate_lambda_function_name,
            'dynamodb': validate_dynamodb_table_name,
            'rds': validate_rds_instance_identifier,
            'ecs_cluster': validate_ecs_cluster_name,
            'ecs_service': validate_ecs_service_name,
            'eks': validate_eks_cluster_name,
            'sns': validate_sns_topic_name,
            'sqs': validate_sqs_queue_name,
            'kms': validate_kms_key_id,
            'secrets': validate_secrets_manager_secret_name,
            'log_group': validate_cloudwatch_log_group_name,
            'log_stream': validate_cloudwatch_log_stream_name,
            'eventbridge': validate_eventbridge_rule_name,
            'stepfunctions': validate_stepfunctions_state_machine_name,
            'apigateway': validate_apigateway_api_id,
            'apigateway_stage': validate_apigateway_stage_name,
            'iam_role': validate_iam_role_name,
            'iam_user': validate_iam_user_name,
            'iam_policy': validate_iam_policy_name,
            's3': validate_s3_bucket_name,
        }
        if resource_type.lower() in validators:
            return validators[resource_type.lower()](identifier)
    
    # Generic validation: check if it looks like a valid AWS identifier
    # Most AWS resource names allow alphanumeric, hyphens, underscores
    if len(identifier) > 0 and len(identifier) <= 512:
        # Basic pattern check
        pattern = r'^[a-zA-Z0-9_\-/.:=@+]+$'
        if re.match(pattern, identifier):
            return True, ""  # Looks valid, accept it
    
    return False, f"Invalid AWS resource identifier format: '{identifier}'. Please provide a valid AWS resource identifier, ARN, or resource name."

def extract_and_validate_aws_values(text: str) -> dict:
    """
    Extract and validate ALL AWS values from user text dynamically.
    Validates: account ID, region, org ID, OU ID, VPC endpoint, ARNs, EC2 resources,
    Lambda, DynamoDB, RDS, ECS, EKS, SNS, SQS, KMS, Secrets Manager, CloudWatch,
    EventBridge, Step Functions, API Gateway, Cognito, IAM resources, and more.
    Returns dict with validated values and any errors.
    """
    result = {
        'account_id': None,
        'region': None,
        'org_id': None,
        'ou_id': None,
        'vpc_endpoint': None,
        'ec2_instance': None,
        'security_group': None,
        'vpc': None,
        'subnet': None,
        'lambda_function': None,
        'dynamodb_table': None,
        'rds_instance': None,
        'sns_topic': None,
        'sqs_queue': None,
        'kms_key': None,
        'secrets_manager_secret': None,
        'log_group': None,
        'iam_role': None,
        'iam_user': None,
        'errors': [],
        'warnings': []
    }
    
    # Extract account ID - try multiple patterns
    # Pattern 1: Exactly 12 digits
    account_id_match = re.search(r'\b(\d{12})\b', text)
    if account_id_match:
        account_id = account_id_match.group(1)
        is_valid, error = validate_account_id(account_id)
        if is_valid:
            result['account_id'] = account_id
        else:
            result['errors'].append(error)
    else:
        # Pattern 2: Any sequence of digits (might be partial account ID)
        partial_account_match = re.search(r'\baccount[:\s]+id[:\s]+(\d+)\b', text, re.IGNORECASE)
        if partial_account_match:
            account_id = partial_account_match.group(1)
            is_valid, error = validate_account_id(account_id)
            if not is_valid:
                result['errors'].append(error)
        else:
            # Pattern 3: Just digits mentioned (could be account ID)
            digit_match = re.search(r'\baccount[:\s]+(\d+)\b', text, re.IGNORECASE)
            if digit_match:
                account_id = digit_match.group(1)
                is_valid, error = validate_account_id(account_id)
                if not is_valid:
                    result['errors'].append(error)
            else:
                # Pattern 4: Any standalone digits (4-11 digits might be partial account ID)
                # Also check for "1234" or similar short numbers
                partial_match = re.search(r'\b(\d{4,11})\b', text)
                if partial_match:
                    account_id = partial_match.group(1)
                    is_valid, error = validate_account_id(account_id)
                    if not is_valid:
                        result['errors'].append(error)
    
    # Extract region - try multiple patterns
    # Pattern 1: Standard AWS region format (any area-direction-number)
    region_match = re.search(r'\b([a-z]{2,3}-[a-z]+-\d+)\b', text, re.IGNORECASE)
    if region_match:
        region = region_match.group(1).lower()
        is_valid, error = validate_aws_region(region)
        if is_valid:
            result['region'] = region
        else:
            result['errors'].append(error)
    else:
        # Pattern 2: Explicit "region" keyword
        region_keyword_match = re.search(r'\bregion[:\s]+([a-z]+-[a-z]+-\d+)\b', text, re.IGNORECASE)
        if region_keyword_match:
            region = region_keyword_match.group(1).lower()
            is_valid, error = validate_aws_region(region)
            if is_valid:
                result['region'] = region
            else:
                result['errors'].append(error)
        else:
            # Pattern 3: Look for any region-like pattern (letters-dash-numbers)
            # This catches things like "ch-567", "ch-west-56", etc.
            # Pattern: 2-3 letters, dash, optional letters, dash, numbers OR just letters-dash-numbers
            any_region_like = re.search(r'\b([a-z]{2,3}-[a-z]*-?\d+|[a-z]{2,3}-\d+)\b', text, re.IGNORECASE)
            if any_region_like:
                region = any_region_like.group(1).lower()
                # Validate it - this will catch invalid regions like "ch-567"
                is_valid, error = validate_aws_region(region)
                if not is_valid:
                    result['errors'].append(error)
    
    # Extract Organization ID
    org_id_match = re.search(r'\b(o-[a-z0-9]{10,12})\b', text, re.IGNORECASE)
    if org_id_match:
        org_id = org_id_match.group(1).lower()
        is_valid, error = validate_org_id(org_id)
        if is_valid:
            result['org_id'] = org_id
        else:
            result['errors'].append(error)
    else:
        # Also check for "org id" or "organization id" keywords
        org_keyword_match = re.search(r'\b(?:org|organization)[:\s]+id[:\s]+(o-[a-z0-9]{10,12})\b', text, re.IGNORECASE)
        if org_keyword_match:
            org_id = org_keyword_match.group(1).lower()
            is_valid, error = validate_org_id(org_id)
            if not is_valid:
                result['errors'].append(error)
        else:
            # Check for invalid org ID patterns
            invalid_org = re.search(r'\b(?:org|organization)[:\s]+id[:\s]+([a-z0-9-]+)\b', text, re.IGNORECASE)
            if invalid_org:
                org_id = invalid_org.group(1).lower()
                if not org_id.startswith('o-'):
                    result['errors'].append(f"Invalid Organization ID: '{org_id}'. Must start with 'o-' followed by 10-12 lowercase alphanumeric characters (e.g., o-a1b2c3d4e5)")
                else:
                    is_valid, error = validate_org_id(org_id)
                    if not is_valid:
                        result['errors'].append(error)
    
    # Extract OU ID
    ou_id_match = re.search(r'\b(ou-[a-z0-9-]+)\b', text, re.IGNORECASE)
    if ou_id_match:
        ou_id = ou_id_match.group(1).lower()
        is_valid, error = validate_ou_id(ou_id)
        if is_valid:
            result['ou_id'] = ou_id
        else:
            result['errors'].append(error)
    
    # Extract VPC endpoint
    vpc_endpoint_match = re.search(r'\b(vpce-[a-z0-9]{17})\b', text, re.IGNORECASE)
    if vpc_endpoint_match:
        vpc_endpoint = vpc_endpoint_match.group(1).lower()
        is_valid, error = validate_vpc_endpoint(vpc_endpoint)
        if is_valid:
            result['vpc_endpoint'] = vpc_endpoint
        else:
            result['errors'].append(error)
    
    # Extract EC2 resources
    ec2_instance_match = re.search(r'\b(i-[a-z0-9]{17})\b', text, re.IGNORECASE)
    if ec2_instance_match:
        instance_id = ec2_instance_match.group(1).lower()
        is_valid, error = validate_ec2_instance_id(instance_id)
        if is_valid:
            result['ec2_instance'] = instance_id
        else:
            result['errors'].append(error)
    
    security_group_match = re.search(r'\b(sg-[a-z0-9]{17})\b', text, re.IGNORECASE)
    if security_group_match:
        sg_id = security_group_match.group(1).lower()
        is_valid, error = validate_security_group_id(sg_id)
        if is_valid:
            result['security_group'] = sg_id
        else:
            result['errors'].append(error)
    
    vpc_match = re.search(r'\b(vpc-[a-z0-9]{17})\b', text, re.IGNORECASE)
    if vpc_match:
        vpc_id = vpc_match.group(1).lower()
        is_valid, error = validate_vpc_id(vpc_id)
        if is_valid:
            result['vpc'] = vpc_id
        else:
            result['errors'].append(error)
    
    subnet_match = re.search(r'\b(subnet-[a-z0-9]{17})\b', text, re.IGNORECASE)
    if subnet_match:
        subnet_id = subnet_match.group(1).lower()
        is_valid, error = validate_subnet_id(subnet_id)
        if is_valid:
            result['subnet'] = subnet_id
        else:
            result['errors'].append(error)
    
    # Extract Lambda function names (with keywords)
    lambda_match = re.search(r'\b(?:lambda|function)[:\s]+([a-zA-Z0-9-_]{1,64})\b', text, re.IGNORECASE)
    if lambda_match:
        function_name = lambda_match.group(1)
        is_valid, error = validate_lambda_function_name(function_name)
        if is_valid:
            result['lambda_function'] = function_name
        else:
            result['errors'].append(error)
    
    # Extract DynamoDB table names (with keywords)
    dynamodb_match = re.search(r'\b(?:dynamodb|table)[:\s]+([a-zA-Z0-9_.-]{3,255})\b', text, re.IGNORECASE)
    if dynamodb_match:
        table_name = dynamodb_match.group(1)
        is_valid, error = validate_dynamodb_table_name(table_name)
        if is_valid:
            result['dynamodb_table'] = table_name
        else:
            result['errors'].append(error)
    
    # Extract RDS instance identifiers (with keywords)
    rds_match = re.search(r'\b(?:rds|database|instance)[:\s]+([a-z][a-z0-9-]{0,62})\b', text, re.IGNORECASE)
    if rds_match:
        instance_id = rds_match.group(1).lower()
        is_valid, error = validate_rds_instance_identifier(instance_id)
        if is_valid:
            result['rds_instance'] = instance_id
        else:
            result['errors'].append(error)
    
    # Extract SNS topic names (with keywords)
    sns_match = re.search(r'\b(?:sns|topic)[:\s]+([a-zA-Z0-9_-]{1,256})\b', text, re.IGNORECASE)
    if sns_match:
        topic_name = sns_match.group(1)
        is_valid, error = validate_sns_topic_name(topic_name)
        if is_valid:
            result['sns_topic'] = topic_name
        else:
            result['errors'].append(error)
    
    # Extract SQS queue names (with keywords)
    sqs_match = re.search(r'\b(?:sqs|queue)[:\s]+([a-zA-Z0-9_-]{1,80})\b', text, re.IGNORECASE)
    if sqs_match:
        queue_name = sqs_match.group(1)
        is_valid, error = validate_sqs_queue_name(queue_name)
        if is_valid:
            result['sqs_queue'] = queue_name
        else:
            result['errors'].append(error)
    
    # Extract KMS key IDs/ARNs/aliases (with keywords)
    kms_match = re.search(r'\b(?:kms|key)[:\s]+(alias/[a-zA-Z0-9:/_-]+|arn:aws:kms:[^\\s]+|[a-f0-9-]{36}|[a-zA-Z0-9]{1,256})\b', text, re.IGNORECASE)
    if kms_match:
        key_id = kms_match.group(1)
        is_valid, error = validate_kms_key_id(key_id)
        if is_valid:
            result['kms_key'] = key_id
        else:
            result['errors'].append(error)
    
    # Extract Secrets Manager secret names (with keywords)
    secrets_match = re.search(r'\b(?:secrets|secret)[:\s]+([a-zA-Z0-9/_+=.@-]{1,512})\b', text, re.IGNORECASE)
    if secrets_match:
        secret_name = secrets_match.group(1)
        is_valid, error = validate_secrets_manager_secret_name(secret_name)
        if is_valid:
            result['secrets_manager_secret'] = secret_name
        else:
            result['errors'].append(error)
    
    # Extract CloudWatch Log Group names (with keywords)
    log_group_match = re.search(r'\b(?:log[:\s]+group|loggroup)[:\s]+([a-zA-Z0-9_/.-]{1,512})\b', text, re.IGNORECASE)
    if log_group_match:
        log_group = log_group_match.group(1)
        is_valid, error = validate_cloudwatch_log_group_name(log_group)
        if is_valid:
            result['log_group'] = log_group
        else:
            result['errors'].append(error)
    
    # Extract IAM role names (with keywords)
    iam_role_match = re.search(r'\b(?:iam[:\s]+role|role)[:\s]+([a-zA-Z0-9+=,.@_-]{1,64})\b', text, re.IGNORECASE)
    if iam_role_match:
        role_name = iam_role_match.group(1)
        is_valid, error = validate_iam_role_name(role_name)
        if is_valid:
            result['iam_role'] = role_name
        else:
            result['errors'].append(error)
    
    # Extract IAM user names (with keywords)
    iam_user_match = re.search(r'\b(?:iam[:\s]+user|user)[:\s]+([a-zA-Z0-9+=,.@_-]{1,64})\b', text, re.IGNORECASE)
    if iam_user_match:
        user_name = iam_user_match.group(1)
        is_valid, error = validate_iam_user_name(user_name)
        if is_valid:
            result['iam_user'] = user_name
        else:
            result['errors'].append(error)
    
    # Extract any ARNs
    arn_matches = re.findall(r'\b(arn:aws[a-z0-9-]*:[^\\s]+)\b', text, re.IGNORECASE)
    for arn in arn_matches:
        is_valid, error = validate_arn(arn)
        if not is_valid:
            result['errors'].append(error)
    
    return result

