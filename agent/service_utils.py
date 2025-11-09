"""
Service Detection and Principal Mapping Utilities
Provides comprehensive AWS service detection and principal mapping
"""

import re
import logging
from typing import Optional, Dict

logging.basicConfig(level=logging.INFO)

# Comprehensive AWS Service Principal Mapping
# Based on AWS documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html
SERVICE_PRINCIPALS: Dict[str, str] = {
    # Compute Services
    'lambda': 'lambda.amazonaws.com',
    'ec2': 'ec2.amazonaws.com',
    'ecs': 'ecs-tasks.amazonaws.com',
    'fargate': 'ecs-tasks.amazonaws.com',
    'batch': 'batch.amazonaws.com',
    'lightsail': 'lightsail.amazonaws.com',
    'elasticbeanstalk': 'elasticbeanstalk.amazonaws.com',
    
    # Storage Services
    's3': 's3.amazonaws.com',
    'efs': 'elasticfilesystem.amazonaws.com',
    'fsx': 'fsx.amazonaws.com',
    'glacier': 'glacier.amazonaws.com',
    
    # Database Services
    'rds': 'rds.amazonaws.com',
    'dynamodb': 'dynamodb.amazonaws.com',
    'redshift': 'redshift.amazonaws.com',
    'aurora': 'rds.amazonaws.com',
    'documentdb': 'rds.amazonaws.com',
    'neptune': 'rds.amazonaws.com',
    'timestream': 'timestream.amazonaws.com',
    
    # Networking Services
    'vpc': 'vpc.amazonaws.com',
    'elb': 'elasticloadbalancing.amazonaws.com',
    'elbv2': 'elasticloadbalancing.amazonaws.com',
    'cloudfront': 'cloudfront.amazonaws.com',
    'route53': 'route53.amazonaws.com',
    'apigateway': 'apigateway.amazonaws.com',
    'apigatewayv2': 'apigateway.amazonaws.com',
    'directconnect': 'directconnect.amazonaws.com',
    'globalaccelerator': 'globalaccelerator.amazonaws.com',
    
    # Application Integration
    'sns': 'sns.amazonaws.com',
    'sqs': 'sqs.amazonaws.com',
    'eventbridge': 'events.amazonaws.com',
    'events': 'events.amazonaws.com',
    'stepfunctions': 'states.amazonaws.com',
    'swf': 'swf.amazonaws.com',
    
    # Analytics Services
    'kinesis': 'kinesis.amazonaws.com',
    'kinesisanalytics': 'kinesisanalytics.amazonaws.com',
    'kinesisfirehose': 'firehose.amazonaws.com',
    'quicksight': 'quicksight.amazonaws.com',
    'athena': 'athena.amazonaws.com',
    'emr': 'elasticmapreduce.amazonaws.com',
    'glue': 'glue.amazonaws.com',
    'datapipeline': 'datapipeline.amazonaws.com',
    
    # Security & Identity
    'iam': 'iam.amazonaws.com',
    'cognito': 'cognito-idp.amazonaws.com',
    'secretsmanager': 'secretsmanager.amazonaws.com',
    'kms': 'kms.amazonaws.com',
    'waf': 'waf.amazonaws.com',
    'shield': 'shield.amazonaws.com',
    'guardduty': 'guardduty.amazonaws.com',
    'securityhub': 'securityhub.amazonaws.com',
    'macie': 'macie.amazonaws.com',
    'inspector': 'inspector.amazonaws.com',
    
    # Management & Governance
    'cloudformation': 'cloudformation.amazonaws.com',
    'cloudwatch': 'logs.amazonaws.com',
    'logs': 'logs.amazonaws.com',
    'cloudtrail': 'cloudtrail.amazonaws.com',
    'config': 'config.amazonaws.com',
    'systemsmanager': 'ssm.amazonaws.com',
    'ssm': 'ssm.amazonaws.com',
    'servicecatalog': 'servicecatalog.amazonaws.com',
    'organizations': 'organizations.amazonaws.com',
    'trustedadvisor': 'trustedadvisor.amazonaws.com',
    
    # Developer Tools
    'codebuild': 'codebuild.amazonaws.com',
    'codecommit': 'codecommit.amazonaws.com',
    'codedeploy': 'codedeploy.amazonaws.com',
    'codepipeline': 'codepipeline.amazonaws.com',
    'codeartifact': 'codeartifact.amazonaws.com',
    'xray': 'xray.amazonaws.com',
    
    # Machine Learning
    'sagemaker': 'sagemaker.amazonaws.com',
    'comprehend': 'comprehend.amazonaws.com',
    'rekognition': 'rekognition.amazonaws.com',
    'translate': 'translate.amazonaws.com',
    'polly': 'polly.amazonaws.com',
    'transcribe': 'transcribe.amazonaws.com',
    'lex': 'lex.amazonaws.com',
    'personalize': 'personalize.amazonaws.com',
    'forecast': 'forecast.amazonaws.com',
    'textract': 'textract.amazonaws.com',
    
    # IoT Services
    'iot': 'iot.amazonaws.com',
    'iotcore': 'iot.amazonaws.com',
    'greengrass': 'greengrass.amazonaws.com',
    
    # Media Services
    'mediaconvert': 'mediaconvert.amazonaws.com',
    'mediapackage': 'mediapackage.amazonaws.com',
    'mediastore': 'mediastore.amazonaws.com',
    'mediatailor': 'mediatailor.amazonaws.com',
    'elemental': 'elementalmediaconvert.amazonaws.com',
    
    # Game Development
    'gamelift': 'gamelift.amazonaws.com',
    
    # AR/VR
    'sumerian': 'sumerian.amazonaws.com',
    
    # Blockchain
    'managedblockchain': 'managedblockchain.amazonaws.com',
    
    # Quantum
    'braket': 'braket.amazonaws.com',
    
    # Migration & Transfer
    'datasync': 'datasync.amazonaws.com',
    'servermigration': 'sms.amazonaws.com',
    'dms': 'dms.amazonaws.com',
    'snowball': 'snowball.amazonaws.com',
    'transfer': 'transfer.amazonaws.com',
    
    # Cost Management
    'costexplorer': 'ce.amazonaws.com',
    'costandusagereport': 'cur.amazonaws.com',
    'budgets': 'budgets.amazonaws.com',
    
    # End User Computing
    'workspaces': 'workspaces.amazonaws.com',
    'appstream': 'appstream.amazonaws.com',
    'workdocs': 'workdocs.amazonaws.com',
    'workmail': 'workmail.amazonaws.com',
    
    # Backup & Recovery
    'backup': 'backup.amazonaws.com',
    
    # Containers
    'eks': 'eks.amazonaws.com',
    'ecr': 'ecr.amazonaws.com',
    
    # Messaging
    'ses': 'ses.amazonaws.com',
    'sns': 'sns.amazonaws.com',
    'sqs': 'sqs.amazonaws.com',
    
    # Monitoring & Observability
    'cloudwatch': 'logs.amazonaws.com',
    'xray': 'xray.amazonaws.com',
    'prometheus': 'aps.amazonaws.com',
}

# Service detection patterns
SERVICE_KEYWORDS: Dict[str, list] = {
    'lambda': ['lambda', 'function', 'serverless', 'aws lambda', 'lambda function'],
    'ec2': ['ec2', 'instance', 'vm', 'virtual machine', 'ec2 instance', 'compute instance'],
    'ecs': ['ecs', 'container', 'task', 'ecs task', 'ecs service', 'docker container'],
    'fargate': ['fargate', 'aws fargate', 'ecs fargate'],
    's3': ['s3', 'bucket', 'storage', 's3 bucket', 'object storage', 'file storage'],
    'dynamodb': ['dynamodb', 'dynamo', 'table', 'dynamodb table', 'nosql'],
    'rds': ['rds', 'database', 'mysql', 'postgresql', 'aurora', 'relational database'],
    'redshift': ['redshift', 'data warehouse', 'analytics database'],
    'apigateway': ['api gateway', 'apigateway', 'rest api', 'api', 'http api'],
    'sns': ['sns', 'notification', 'topic', 'publish', 'subscribe'],
    'sqs': ['sqs', 'queue', 'message queue', 'messaging'],
    'glue': ['glue', 'etl', 'data transformation'],
    'batch': ['batch', 'batch job', 'batch processing'],
    'eks': ['eks', 'kubernetes', 'k8s', 'eks cluster'],
    'ecr': ['ecr', 'container registry', 'docker registry'],
    'kinesis': ['kinesis', 'stream', 'data stream', 'real-time data'],
    'stepfunctions': ['step functions', 'stepfunctions', 'state machine', 'workflow'],
    'eventbridge': ['eventbridge', 'event bus', 'event-driven'],
    'sagemaker': ['sagemaker', 'ml', 'machine learning', 'model training'],
    'iot': ['iot', 'internet of things', 'iot core', 'device'],
    'cloudfront': ['cloudfront', 'cdn', 'content delivery'],
    'route53': ['route53', 'dns', 'domain', 'hosted zone'],
    'vpc': ['vpc', 'virtual private cloud', 'network'],
    'elb': ['elb', 'load balancer', 'elastic load balancer'],
    'cloudformation': ['cloudformation', 'infrastructure as code', 'iac'],
    'secretsmanager': ['secrets manager', 'secretsmanager', 'secret', 'credentials'],
    'kms': ['kms', 'key management', 'encryption key'],
}


def detect_service_from_description(description: str) -> Optional[str]:
    """
    Intelligently detect AWS service from natural language description.
    
    Args:
        description: User's natural language description
        
    Returns:
        Detected service name or None if unclear
    """
    if not description or not description.strip():
        return None
    
    description_lower = description.lower()
    
    # Score each service based on keyword matches
    service_scores: Dict[str, int] = {}
    
    for service, keywords in SERVICE_KEYWORDS.items():
        score = 0
        for keyword in keywords:
            # Exact matches get higher score
            if keyword in description_lower:
                score += 2 if len(keyword) > 3 else 1
            # Word boundary matches
            if re.search(r'\b' + re.escape(keyword) + r'\b', description_lower):
                score += 3
        
        if score > 0:
            service_scores[service] = score
    
    if not service_scores:
        return None
    
    # Return service with highest score
    detected_service = max(service_scores.items(), key=lambda x: x[1])[0]
    confidence = service_scores[detected_service]
    
    logging.info(f"🔍 Service detection: '{detected_service}' (confidence: {confidence})")
    
    return detected_service


def get_service_principal(service: str) -> str:
    """
    Get AWS service principal for a given service name.
    
    Args:
        service: Service name (e.g., 'lambda', 'ec2', 's3')
        
    Returns:
        Service principal ARN (e.g., 'lambda.amazonaws.com')
    """
    if not service:
        logging.warning("⚠️ No service provided, defaulting to lambda")
        return 'lambda.amazonaws.com'
    
    service_lower = service.lower().strip()
    
    # Direct lookup
    if service_lower in SERVICE_PRINCIPALS:
        principal = SERVICE_PRINCIPALS[service_lower]
        logging.info(f"✅ Service principal: {service_lower} → {principal}")
        return principal
    
    # Try to find partial match
    for key, principal in SERVICE_PRINCIPALS.items():
        if service_lower in key or key in service_lower:
            logging.info(f"✅ Service principal (partial match): {service_lower} → {principal}")
            return principal
    
    # Intelligent fallback: construct from service name
    # Remove common prefixes/suffixes
    clean_service = service_lower.replace('aws ', '').replace(' amazon', '')
    
    # Try common patterns
    if clean_service.endswith('service'):
        clean_service = clean_service[:-7]
    
    # Construct principal
    principal = f"{clean_service}.amazonaws.com"
    logging.warning(f"⚠️ Service '{service}' not in mapping, using constructed: {principal}")
    
    return principal


def validate_service(service: str) -> bool:
    """
    Validate if service is a known AWS service.
    
    Args:
        service: Service name to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not service:
        return False
    
    service_lower = service.lower().strip()
    return service_lower in SERVICE_PRINCIPALS or service_lower in SERVICE_KEYWORDS


def get_all_services() -> list:
    """
    Get list of all supported services.
    
    Returns:
        List of service names
    """
    return sorted(set(SERVICE_PRINCIPALS.keys()) | set(SERVICE_KEYWORDS.keys()))

