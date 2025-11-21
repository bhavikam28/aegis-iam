"""
AWS Constants and Reference Data
Comprehensive list of AWS services, principals, and fixed data for validation and policy generation.

This file should be updated when AWS adds new services or regions.
For regions, we use a hybrid approach: validate format + check against known list,
but accept format-valid regions with a warning (for new AWS regions).
"""
import re

# ============================================================================
# AWS REGIONS - Hybrid Validation Approach
# ============================================================================

# Known AWS regions (as of 2025) - Complete list of all 38 regions
# This list should be updated when AWS announces new regions
KNOWN_AWS_REGIONS = {
    # US Regions (4)
    'us-east-1',      # US East (N. Virginia)
    'us-east-2',      # US East (Ohio)
    'us-west-1',      # US West (N. California)
    'us-west-2',      # US West (Oregon)
    
    # AWS GovCloud (US) Regions (2)
    'us-gov-east-1',  # AWS GovCloud (US-East)
    'us-gov-west-1', # AWS GovCloud (US-West)
    
    # Europe Regions (8)
    'eu-west-1',      # Europe (Ireland)
    'eu-west-2',      # Europe (London)
    'eu-west-3',      # Europe (Paris)
    'eu-central-1',   # Europe (Frankfurt)
    'eu-north-1',     # Europe (Stockholm)
    'eu-south-1',     # Europe (Milan)
    'eu-south-2',     # Europe (Spain)
    'eu-central-2',   # Europe (Zurich)
    
    # Asia Pacific Regions (15)
    'ap-south-1',     # Asia Pacific (Mumbai)
    'ap-south-2',     # Asia Pacific (Hyderabad)
    'ap-southeast-1', # Asia Pacific (Singapore)
    'ap-southeast-2', # Asia Pacific (Sydney)
    'ap-southeast-3', # Asia Pacific (Jakarta)
    'ap-southeast-4', # Asia Pacific (Melbourne)
    'ap-southeast-5', # Asia Pacific (Malaysia)
    'ap-southeast-6', # Asia Pacific (New Zealand)
    'ap-southeast-7', # Asia Pacific (Thailand)
    'ap-northeast-1', # Asia Pacific (Tokyo)
    'ap-northeast-2', # Asia Pacific (Seoul)
    'ap-northeast-3', # Asia Pacific (Osaka)
    'ap-east-1',      # Asia Pacific (Hong Kong)
    'ap-east-2',      # Asia Pacific (Taipei)
    
    # Canada (2)
    'ca-central-1',   # Canada (Central)
    'ca-west-1',      # Canada West (Calgary)
    
    # South America (1)
    'sa-east-1',      # South America (São Paulo)
    
    # Africa (1)
    'af-south-1',     # Africa (Cape Town)
    
    # Middle East (3)
    'me-south-1',     # Middle East (Bahrain)
    'me-central-1',   # Middle East (UAE)
    'il-central-1',   # Israel (Tel Aviv)
    
    # Mexico (1)
    'mx-central-1',   # Mexico (Central)
    
    # China (Special regions - require separate AWS account) (2)
    'cn-north-1',     # China (Beijing)
    'cn-northwest-1', # China (Ningxia)
}

# Valid region prefixes (for format validation)
VALID_REGION_PREFIXES = {'us', 'eu', 'ap', 'ca', 'sa', 'af', 'me', 'il', 'mx', 'cn', 'us-gov'}

# ============================================================================
# AWS SERVICE PRINCIPALS (for Trust Policies)
# ============================================================================

AWS_SERVICE_PRINCIPALS = {
    # Compute Services
    'lambda': 'lambda.amazonaws.com',
    'ec2': 'ec2.amazonaws.com',
    'ecs': 'ecs-tasks.amazonaws.com',
    'fargate': 'ecs-tasks.amazonaws.com',
    'eks': 'eks.amazonaws.com',
    'batch': 'batch.amazonaws.com',
    'lightsail': 'lightsail.amazonaws.com',
    
    # Storage Services
    's3': 's3.amazonaws.com',
    'glacier': 'glacier.amazonaws.com',
    'efs': 'elasticfilesystem.amazonaws.com',
    'fsx': 'fsx.amazonaws.com',
    
    # Database Services
    'rds': 'rds.amazonaws.com',
    'dynamodb': 'dynamodb.amazonaws.com',
    'redshift': 'redshift.amazonaws.com',
    'documentdb': 'rds.amazonaws.com',
    'neptune': 'rds.amazonaws.com',
    'elasticache': 'elasticache.amazonaws.com',
    'timestream': 'timestream.amazonaws.com',
    
    # Networking Services
    'apigateway': 'apigateway.amazonaws.com',
    'elb': 'elasticloadbalancing.amazonaws.com',
    'vpc': 'vpc.amazonaws.com',
    'cloudfront': 'cloudfront.amazonaws.com',
    'route53': 'route53.amazonaws.com',
    'directconnect': 'directconnect.amazonaws.com',
    'transitgateway': 'ec2.amazonaws.com',
    
    # Application Integration
    'sns': 'sns.amazonaws.com',
    'sqs': 'sqs.amazonaws.com',
    'eventbridge': 'events.amazonaws.com',
    'stepfunctions': 'states.amazonaws.com',
    'appsync': 'appsync.amazonaws.com',
    
    # Security & Identity
    'iam': 'iam.amazonaws.com',
    'cognito': 'cognito-identity.amazonaws.com',
    'secretsmanager': 'secretsmanager.amazonaws.com',
    'kms': 'kms.amazonaws.com',
    'certificatemanager': 'acm.amazonaws.com',
    'waf': 'waf.amazonaws.com',
    'shield': 'shield.amazonaws.com',
    
    # Analytics Services
    'kinesis': 'kinesis.amazonaws.com',
    'firehose': 'firehose.amazonaws.com',
    'glue': 'glue.amazonaws.com',
    'athena': 'athena.amazonaws.com',
    'quicksight': 'quicksight.amazonaws.com',
    'emr': 'elasticmapreduce.amazonaws.com',
    'redshift': 'redshift.amazonaws.com',
    
    # Machine Learning
    'sagemaker': 'sagemaker.amazonaws.com',
    'comprehend': 'comprehend.amazonaws.com',
    'rekognition': 'rekognition.amazonaws.com',
    'polly': 'polly.amazonaws.com',
    'translate': 'translate.amazonaws.com',
    'transcribe': 'transcribe.amazonaws.com',
    
    # Management & Governance
    'cloudformation': 'cloudformation.amazonaws.com',
    'cloudwatch': 'logs.amazonaws.com',
    'cloudtrail': 'cloudtrail.amazonaws.com',
    'config': 'config.amazonaws.com',
    'systemsmanager': 'ssm.amazonaws.com',
    'organizations': 'organizations.amazonaws.com',
    'servicecatalog': 'servicecatalog.amazonaws.com',
    'trustedadvisor': 'trustedadvisor.amazonaws.com',
    
    # Developer Tools
    'codebuild': 'codebuild.amazonaws.com',
    'codedeploy': 'codedeploy.amazonaws.com',
    'codepipeline': 'codepipeline.amazonaws.com',
    'codecommit': 'codecommit.amazonaws.com',
    
    # IoT Services
    'iot': 'iot.amazonaws.com',
    'iotanalytics': 'iotanalytics.amazonaws.com',
    'greengrass': 'greengrass.amazonaws.com',
    
    # Media Services
    'mediaconvert': 'mediaconvert.amazonaws.com',
    'medialive': 'medialive.amazonaws.com',
    'mediastore': 'mediastore.amazonaws.com',
    'mediatailor': 'mediatailor.amazonaws.com',
    
    # Other Services
    's3control': 's3-control.amazonaws.com',
    's3outposts': 's3-outposts.amazonaws.com',
    'backup': 'backup.amazonaws.com',
    'datasync': 'datasync.amazonaws.com',
    'transfer': 'transfer.amazonaws.com',
    'workspaces': 'workspaces.amazonaws.com',
    'appstream': 'appstream.amazonaws.com',
}

# ============================================================================
# AWS SERVICE NAMES (for IAM Actions)
# ============================================================================

AWS_SERVICE_NAMES = {
    # Core Services
    's3', 'ec2', 'lambda', 'iam', 'rds', 'dynamodb', 'sns', 'sqs',
    'cloudwatch', 'logs', 'cloudformation', 's3control', 'sts',
    
    # Compute
    'ecs', 'eks', 'batch', 'lightsail', 'elasticbeanstalk',
    
    # Storage
    'glacier', 'efs', 'fsx', 'storagegateway',
    
    # Database
    'redshift', 'documentdb', 'neptune', 'elasticache', 'timestream', 'dax',
    
    # Networking
    'apigateway', 'elasticloadbalancing', 'vpc', 'cloudfront', 'route53',
    'directconnect', 'transitgateway', 'globalaccelerator',
    
    # Application Integration
    'events', 'states', 'appsync', 'mq',
    
    # Security
    'cognito-idp', 'cognito-identity', 'secretsmanager', 'kms', 'acm',
    'waf', 'wafv2', 'shield', 'guardduty', 'securityhub', 'inspector',
    'macie', 'artifact',
    
    # Analytics
    'kinesis', 'firehose', 'glue', 'athena', 'quicksight', 'emr',
    'dataexchange', 'datazone',
    
    # Machine Learning
    'sagemaker', 'comprehend', 'rekognition', 'polly', 'translate',
    'transcribe', 'textract', 'forecast', 'personalize',
    
    # Management
    'config', 'ssm', 'organizations', 'servicecatalog', 'trustedadvisor',
    'cloudtrail', 'systems-manager', 'resource-groups',
    
    # Developer Tools
    'codebuild', 'codedeploy', 'codepipeline', 'codecommit', 'xray',
    
    # IoT
    'iot', 'iotanalytics', 'greengrass', 'iotdeviceadvisor',
    
    # Media
    'mediaconvert', 'medialive', 'mediastore', 'mediatailor', 'elemental',
    
    # Other
    'backup', 'datasync', 'transfer', 'workspaces', 'appstream',
    'chime', 'connect', 'pinpoint', 'ses', 'workmail',
}

# ============================================================================
# AWS AVAILABILITY ZONE PATTERNS
# ============================================================================

# Availability Zones follow pattern: {region}{a-z} (e.g., us-east-1a, us-east-1b)
# We validate format, not specific AZs (as they vary by region and change)
AVAILABILITY_ZONE_PATTERN = r'^[a-z]{2,3}-[a-z]+-\d+[a-z]$'

# ============================================================================
# AWS PARTITION NAMES
# ============================================================================

AWS_PARTITIONS = {
    'aws': 'Standard AWS partition (most common)',
    'aws-cn': 'AWS China partition',
    'aws-us-gov': 'AWS GovCloud partition',
    'aws-iso': 'AWS ISO partition',
    'aws-iso-b': 'AWS ISO-B partition',
}

# ============================================================================
# COMMON IAM ACTION PATTERNS
# ============================================================================

# Common action patterns by service (for validation and suggestions)
COMMON_ACTIONS = {
    's3': ['GetObject', 'PutObject', 'DeleteObject', 'ListBucket', 'GetBucketLocation'],
    'dynamodb': ['GetItem', 'PutItem', 'UpdateItem', 'DeleteItem', 'Query', 'Scan'],
    'lambda': ['InvokeFunction', 'GetFunction', 'ListFunctions'],
    'ec2': ['RunInstances', 'TerminateInstances', 'DescribeInstances', 'StartInstances', 'StopInstances'],
    'rds': ['CreateDBInstance', 'DeleteDBInstance', 'DescribeDBInstances', 'ModifyDBInstance'],
    'sns': ['Publish', 'Subscribe', 'ListTopics', 'CreateTopic'],
    'sqs': ['SendMessage', 'ReceiveMessage', 'DeleteMessage', 'GetQueueUrl'],
    'logs': ['CreateLogGroup', 'CreateLogStream', 'PutLogEvents', 'DescribeLogGroups'],
    'iam': ['GetUser', 'ListUsers', 'CreateUser', 'DeleteUser', 'AttachUserPolicy'],
    'kms': ['Encrypt', 'Decrypt', 'GenerateDataKey', 'DescribeKey'],
}

# ============================================================================
# ARN PATTERNS BY SERVICE
# ============================================================================

# Common ARN patterns for validation
ARN_PATTERNS = {
    's3': r'arn:aws:s3:::[^/]+(/.*)?',  # Bucket or object
    'dynamodb': r'arn:aws:dynamodb:[a-z0-9-]+:\d{12}:table/[a-zA-Z0-9_.-]+',
    'lambda': r'arn:aws:lambda:[a-z0-9-]+:\d{12}:function:[a-zA-Z0-9_-]+',
    'ec2': r'arn:aws:ec2:[a-z0-9-]+:\d{12}:(instance|volume|snapshot|image|security-group)/[a-z0-9-]+',
    'rds': r'arn:aws:rds:[a-z0-9-]+:\d{12}:(db|cluster):[a-zA-Z0-9-]+',
    'iam': r'arn:aws:iam::\d{12}:(user|role|group|policy)/[a-zA-Z0-9+=,.@_-]+',
    'sns': r'arn:aws:sns:[a-z0-9-]+:\d{12}:[a-zA-Z0-9_-]+',
    'sqs': r'arn:aws:sqs:[a-z0-9-]+:\d{12}:[a-zA-Z0-9_-]+',
    'logs': r'arn:aws:logs:[a-z0-9-]+:\d{12}:log-group:[a-zA-Z0-9_/.-]+',
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_service_principal(service: str) -> str:
    """Get AWS service principal for a given service name."""
    service_lower = service.lower().replace('_', '').replace('-', '')
    return AWS_SERVICE_PRINCIPALS.get(service_lower, f'{service_lower}.amazonaws.com')

def is_valid_service_name(service: str) -> bool:
    """Check if service name is a valid AWS service."""
    service_lower = service.lower().replace('_', '').replace('-', '')
    return service_lower in AWS_SERVICE_NAMES or service_lower in AWS_SERVICE_PRINCIPALS

def get_common_actions(service: str) -> list:
    """Get common IAM actions for a service."""
    service_lower = service.lower().replace('_', '').replace('-', '')
    return COMMON_ACTIONS.get(service_lower, [])

def validate_region_format(region: str) -> tuple[bool, str]:
    """
    Validate region format (hybrid approach).
    Returns: (is_valid_format, error_message)
    """
    if not region or not isinstance(region, str):
        return False, "Region cannot be empty"
    
    region = region.strip().lower()
    
    # Check format pattern
    pattern = r'^([a-z]{2,3})-[a-z]+-\d+$'
    if not re.match(pattern, region):
        return False, f"Invalid region format: '{region}'. AWS regions follow the pattern: [geographic-area]-[direction]-[number]"
    
    # Check prefix
    prefix = region.split('-')[0]
    if prefix not in VALID_REGION_PREFIXES:
        return False, f"Invalid region prefix: '{prefix}'. Valid prefixes: {', '.join(sorted(VALID_REGION_PREFIXES))}"
    
    return True, ""

def validate_region_hybrid(region: str, strict: bool = True) -> tuple[bool, str, bool]:
    """
    Hybrid region validation: checks known list + format.
    
    Args:
        region: Region string to validate
        strict: If True, only accept known regions. If False, accept format-valid regions with warning.
    
    Returns:
        (is_valid, error_message, is_known_region)
    """
    if not region or not isinstance(region, str):
        return False, "Region cannot be empty", False
    
    region = region.strip().lower()
    
    # First check: Is it in our known list?
    if region in KNOWN_AWS_REGIONS:
        return True, "", True
    
    # Second check: Is format valid?
    is_valid_format, format_error = validate_region_format(region)
    if not is_valid_format:
        return False, format_error, False
    
    # Format is valid but not in known list
    if strict:
        # Strict mode: reject unknown regions
        examples = [r for r in KNOWN_AWS_REGIONS if r.startswith(region.split('-')[0] + '-')][:3]
        if examples:
            examples_str = ', '.join(examples)
            return False, f"Region '{region}' is not in our known AWS regions list. Valid regions with same prefix: {examples_str}. If this is a new AWS region, please update KNOWN_AWS_REGIONS in aws_constants.py", False
        else:
            return False, f"Region '{region}' is not in our known AWS regions list. Please use one of the official AWS regions.", False
    else:
        # Lenient mode: accept format-valid regions with warning
        return True, f"Warning: '{region}' matches AWS region format but is not in our known regions list. If this is a new AWS region, please update KNOWN_AWS_REGIONS.", False

