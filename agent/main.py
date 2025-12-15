from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict, Any
# Feature imports
from features.policy_generation.policy_agent import PolicyAgent
from features.policy_generation.bedrock_tool import set_user_credentials, clear_user_credentials
from features.validation.validator_agent import ValidatorAgent
from features.audit.audit_agent import AuditAgent
from features.cicd.cicd_analyzer import CICDAnalyzer
from features.cicd.pr_comment_generator import PRCommentGenerator
from features.cicd.webhook_manager import webhook_manager
from features.cicd.github_app import github_app
from features.cicd.github_client import GitHubClient

# Utility imports
from utils.service_utils import validate_service, detect_service_from_description
from utils.aws_validator import extract_and_validate_aws_values, validate_aws_region, validate_account_id
from features.validation.policy_scorer import calculate_policy_scores, generate_score_breakdown, generate_security_recommendations
from utils.compliance_links import get_compliance_link
from utils.iac_exporter import export_to_cloudformation, export_to_terraform, export_to_yaml
from utils.iam_deployer import IAMDeployer
from utils.secure_credentials import SecureCredentials, RateLimiter

# Standard library imports
import uuid
import json
import re
import logging
import asyncio
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logging.basicConfig(level=logging.INFO)

# ============================================
# REQUEST MODELS WITH SECURE CREDENTIALS
# ============================================

class AWSCredentials(BaseModel):
    """
    User-provided AWS credentials
    
    SECURITY: These credentials are:
    - Never stored in database
    - Never logged
    - Used only for the current request
    - Passed directly to AWS SDK
    """
    access_key_id: str
    secret_access_key: str
    region: str = "us-east-1"
    
    @field_validator('access_key_id')
    @classmethod
    def validate_access_key(cls, v):
        if not SecureCredentials.validate_access_key_id(v):
            raise ValueError("Invalid AWS Access Key ID format")
        return v
    
    @field_validator('secret_access_key')
    @classmethod
    def validate_secret_key(cls, v):
        if not SecureCredentials.validate_secret_access_key(v):
            raise ValueError("Invalid AWS Secret Access Key format")
        return v
    
    @field_validator('region')
    @classmethod
    def validate_region(cls, v):
        if not SecureCredentials.validate_region(v):
            raise ValueError("Invalid AWS region")
        return v

def extract_score_breakdown(text: str) -> dict:
    """Extract separate score breakdowns for permissions and trust policies"""
    breakdown = {
        "permissions": {"positive": [], "improvements": []},
        "trust": {"positive": [], "improvements": []}
    }
    
    try:
        # Extract Permissions Policy breakdown - IMPROVED REGEX
        perm_analysis = re.search(
            r'##\s*Permissions Policy Security Analysis([\s\S]*?)(?=##\s*Trust Policy Security Analysis|##\s*📊|$)',
            text, 
            re.DOTALL | re.IGNORECASE
        )
        
        if perm_analysis:
            analysis_text = perm_analysis.group(1)
            
            # Extract Positive items
            positive_match = re.search(
                r'✅\s*\*\*Positive:\*\*([\s\S]*?)(?=⚠️|##|$)',
                analysis_text,
                re.DOTALL
            )
            if positive_match:
                positive_text = positive_match.group(1)
                breakdown["permissions"]["positive"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in positive_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
            
            # Extract Could Improve items
            improve_match = re.search(
                r'⚠️\s*\*\*Could Improve:\*\*([\s\S]*?)(?=##|$)',
                analysis_text,
                re.DOTALL
            )
            if improve_match:
                improve_text = improve_match.group(1)
                breakdown["permissions"]["improvements"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in improve_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
        
        # Extract Trust Policy breakdown - IMPROVED REGEX
        trust_analysis = re.search(
            r'##\s*Trust Policy Security Analysis([\s\S]*?)(?=##\s*📊|##\s*Overall|$)',
            text,
            re.DOTALL | re.IGNORECASE
        )
        
        if trust_analysis:
            analysis_text = trust_analysis.group(1)
            
            # Extract Positive items
            positive_match = re.search(
                r'✅\s*\*\*Positive:\*\*([\s\S]*?)(?=⚠️|##|$)',
                analysis_text,
                re.DOTALL
            )
            if positive_match:
                positive_text = positive_match.group(1)
                breakdown["trust"]["positive"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in positive_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
            
            # Extract Could Improve items
            improve_match = re.search(
                r'⚠️\s*\*\*Could Improve:\*\*([\s\S]*?)(?=##|$)',
                analysis_text,
                re.DOTALL
            )
            if improve_match:
                improve_text = improve_match.group(1)
                breakdown["trust"]["improvements"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in improve_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
        
        logging.debug(f"✅ Score breakdown extracted:")
        logging.debug(f"   Permissions Positive: {len(breakdown['permissions']['positive'])} items")
        logging.debug(f"   Permissions Improvements: {len(breakdown['permissions']['improvements'])} items")
        logging.debug(f"   Trust Positive: {len(breakdown['trust']['positive'])} items")
        logging.debug(f"   Trust Improvements: {len(breakdown['trust']['improvements'])} items")
            
    except Exception as e:
        logging.error(f"❌ Error extracting score breakdown: {e}")
    
    return breakdown

def generate_permissions_explanation(policy: dict) -> str:
    """Generate a well-formatted, readable text explanation of a permissions policy"""
    if not policy or 'Statement' not in policy:
        return "No permissions policy provided."
    
    explanations = []
    for idx, statement in enumerate(policy.get('Statement', []), 1):
        sid = statement.get('Sid', f'Statement{idx}')
        effect = statement.get('Effect', 'Allow')
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        conditions = statement.get('Condition', {})
        
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        
        # Format actions nicely
        if len(actions) <= 3:
            action_str = ', '.join(actions)
        else:
            action_str = ', '.join(actions[:3]) + f', and {len(actions) - 3} more action(s)'
        
        # Format resources nicely
        resource_display = []
        for r in resources[:3]:
            if isinstance(r, str):
                if 'arn:aws:' in r:
                    # Extract meaningful part
                    parts = r.split(':')
                    if len(parts) >= 6:
                        service = parts[2]
                        resource_type = parts[5].split('/')[0] if '/' in parts[5] else parts[5]
                        resource_display.append(f"{service} {resource_type}")
                    else:
                        resource_display.append(r.split('/')[-1] if '/' in r else r)
                else:
                    resource_display.append(r)
        
        if len(resources) > 3:
            resource_str = ', '.join(resource_display) + f', and {len(resources) - 3} more resource(s)'
        else:
            resource_str = ', '.join(resource_display) if resource_display else 'specified resources'
        
        # Build readable explanation
        explanation = f"""**{idx}. {sid}**

**Permissions:** {action_str}

**Resources:** {resource_str}

**Purpose:** This statement allows {effect.lower()} access to perform the specified actions on the listed resources."""
        
        if conditions:
            explanation += f"\n\n**Conditions:** Additional security conditions are applied to restrict when these permissions can be used."
        
        explanations.append(explanation)
    
    header = "## Permissions Policy Explanation\n\nThis policy defines what actions can be performed and on which resources. Here's what each statement does:\n\n"
    return header + '\n\n---\n\n'.join(explanations) if explanations else "No statements found in policy."


def generate_trust_explanation(trust_policy: dict) -> str:
    """Generate a well-formatted, readable text explanation of a trust policy"""
    if not trust_policy or 'Statement' not in trust_policy:
        return "No trust policy provided."
    
    statement = trust_policy.get('Statement', [{}])[0]
    principal = statement.get('Principal', {})
    conditions = statement.get('Condition', {})
    
    if isinstance(principal, dict):
        service = principal.get('Service', 'Unknown service')
        if isinstance(service, list):
            service = service[0] if service else 'Unknown service'
    else:
        service = str(principal)
    
    explanation = f"""## Trust Policy Explanation

**Trusted Entity:** {service}

**What This Means:** Only the {service} service can assume this IAM role and use the permissions defined in the permissions policy. This is a critical security control that prevents other AWS services, external entities, or unauthorized accounts from using these permissions.

**How It Works:** When you associate this role with a resource (like a Lambda function), AWS automatically handles the role assumption process when that resource executes. The resource receives temporary credentials with the permissions defined in the permissions policy.

**Security Benefits:** 
- Prevents unauthorized access: Even if someone obtained credentials, they cannot assume this role unless they are the {service} service
- Enforces service boundaries: Only the intended AWS service can use these permissions
- Reduces attack surface: Limits who can potentially use these permissions"""
    
    if conditions:
        explanation += f"\n\n**Additional Security Conditions:** This trust policy includes conditions that further restrict when and how the role can be assumed."
    
    return explanation


def fix_s3_statement_separation(policy: dict) -> dict:
    """
    Validate and fix S3 statement separation.
    If bucket and object ARNs are in same statement, split into two.
    """
    if not policy or 'Statement' not in policy:
        return policy
    
    fixed_statements = []
    
    for statement in policy['Statement']:
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        # Check if this statement has both bucket and object S3 ARNs
        has_bucket_arn = any('arn:aws:s3:::' in r and not r.endswith('/*') for r in resources)
        has_object_arn = any('arn:aws:s3:::' in r and r.endswith('/*') for r in resources)
        
        if has_bucket_arn and has_object_arn:
            logging.warning("⚠️ Found S3 statement with mixed bucket/object ARNs - splitting...")
            
            # Split into two statements
            bucket_resources = [r for r in resources if 'arn:aws:s3:::' in r and not r.endswith('/*')]
            object_resources = [r for r in resources if 'arn:aws:s3:::' in r and r.endswith('/*')]
            
            # Bucket statement - Preserve ALL bucket-related actions
            if bucket_resources:
                # Preserve all S3 bucket actions (ListBucket, GetBucketLocation, GetBucketVersioning, etc.)
                bucket_actions = [a for a in actions if a.startswith('s3:') and 
                                 a in ['s3:ListBucket', 's3:GetBucketLocation', 's3:GetBucketVersioning', 
                                       's3:GetBucketPolicy', 's3:GetBucketAcl', 's3:GetBucketCors',
                                       's3:GetBucketLogging', 's3:GetBucketNotification', 's3:GetBucketRequestPayment',
                                       's3:GetBucketTagging', 's3:GetBucketWebsite', 's3:GetBucketPublicAccessBlock']]
                if not bucket_actions:
                    bucket_actions = ['s3:ListBucket']  # Safe default if no bucket actions found
                
                bucket_statement = {
                    "Sid": (statement.get('Sid', 'S3Access') + 'ListBucket').replace('Access', ''),
                    "Effect": statement.get('Effect', 'Allow'),
                    "Action": bucket_actions[0] if len(bucket_actions) == 1 else bucket_actions,
                    "Resource": bucket_resources[0] if len(bucket_resources) == 1 else bucket_resources
                }
                # Preserve conditions if present
                if statement.get('Condition'):
                    bucket_statement['Condition'] = statement['Condition']
                fixed_statements.append(bucket_statement)
                logging.debug(f"✅ Created separate bucket statement: {bucket_statement['Sid']} with {len(bucket_actions)} actions")
            
            # Object statement - Preserve ALL object-related actions
            if object_resources:
                # Preserve all S3 object actions (excluding bucket actions)
                bucket_action_list = ['s3:ListBucket', 's3:GetBucketLocation', 's3:GetBucketVersioning',
                                     's3:GetBucketPolicy', 's3:GetBucketAcl', 's3:GetBucketCors',
                                     's3:GetBucketLogging', 's3:GetBucketNotification', 's3:GetBucketRequestPayment',
                                     's3:GetBucketTagging', 's3:GetBucketWebsite', 's3:GetBucketPublicAccessBlock']
                object_actions = [a for a in actions if a.startswith('s3:') and a not in bucket_action_list]
                if not object_actions:
                    object_actions = ["s3:GetObject"]  # Safe default if no object actions found
                object_statement = {
                    "Sid": (statement.get('Sid', 'S3Access') + 'Objects').replace('Access', ''),
                    "Effect": statement.get('Effect', 'Allow'),
                    "Action": object_actions[0] if len(object_actions) == 1 else object_actions,
                    "Resource": object_resources[0] if len(object_resources) == 1 else object_resources
                }
                # Preserve conditions if present
                if statement.get('Condition'):
                    object_statement['Condition'] = statement['Condition']
                fixed_statements.append(object_statement)
                logging.debug(f"✅ Created separate object statement: {object_statement['Sid']} with {len(object_actions)} actions")
        else:
            # No mixing, keep as is
            fixed_statements.append(statement)
    
    policy['Statement'] = fixed_statements
    return policy

app = FastAPI(title="Aegis IAM Agent - MCP Enabled")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://aegis-iam.vercel.app"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True
)

class GenerationRequest(BaseModel):
    description: str
    service: str
    conversation_id: Optional[str] = None
    is_followup: bool = False
    compliance: Optional[str] = 'general'
    restrictive: Optional[bool] = True
    aws_credentials: Optional[AWSCredentials] = None  # User-provided credentials
    
    @field_validator('description')
    @classmethod
    def validate_description(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Description cannot be empty")
        if len(v) > 10000:
            raise ValueError("Description too long (max 10000 characters)")
        return v.strip()
    
    @field_validator('service')
    @classmethod
    def validate_service(cls, v):
        if not v or len(v.strip()) == 0:
            # Will be auto-detected in endpoint
            return 'lambda'
        return v.lower().strip()

class ValidationRequest(BaseModel):
    policy_json: Optional[str] = None
    role_arn: Optional[str] = None
    compliance_frameworks: Optional[List[str]] = ["general"]
    mode: str = "quick"
    aws_credentials: Optional[AWSCredentials] = None  # User-provided credentials

class AuditRequest(BaseModel):
    mode: str = "full"  # full or quick
    aws_region: str = "us-east-1"
    compliance_frameworks: Optional[List[str]] = ["pci_dss", "hipaa", "sox", "gdpr", "cis"]
    aws_credentials: Optional[AWSCredentials] = None  # User-provided credentials

conversations: Dict[str, List[Dict]] = {}
conversation_cache: Dict[str, Dict[str, Any]] = {}
aegis_agent = PolicyAgent()
validator_agent = ValidatorAgent()

@app.get("/")
def health():
    return {
        "status": "healthy",
        "message": "Aegis IAM Agent with MCP Support",
        "mcp_enabled": True,
        "features": ["policy_generation", "validation", "autonomous_audit"]
    }

@app.get("/test-response")
def test_response():
    """Test endpoint to verify JSONResponse works"""
    test_data = {
        "conversation_id": "test-123",
        "final_answer": "This is a test response",
        "message_count": 1,
        "policy": None,
        "trust_policy": None
    }
    logging.info(f"🧪 Test endpoint returning: {test_data}")
    return JSONResponse(content=test_data)

@app.get("/api/test")
def api_test():
    """Test /api/ routing and GitHub config"""
    return {
        "success": True,
        "message": "API routing works",
        "github_app_id_set": bool(os.getenv('GITHUB_APP_ID')),
        "github_private_key_set": bool(os.getenv('GITHUB_PRIVATE_KEY')),
        "github_webhook_secret_set": bool(os.getenv('GITHUB_WEBHOOK_SECRET'))
    }

@app.post("/api/aws/test-credentials")
async def test_aws_credentials(request: AWSCredentials):
    """
    Test AWS credentials by calling STS GetCallerIdentity and optionally Bedrock
    Returns: { "success": bool, "account_id": str, "user_arn": str, "bedrock_available": bool, "error": str }
    """
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    
    try:
        # Test STS (identity)
        sts_client = boto3.client(
            'sts',
            aws_access_key_id=request.access_key_id,
            aws_secret_access_key=request.secret_access_key,
            region_name=request.region
        )
        
        identity = sts_client.get_caller_identity()
        account_id = identity.get('Account')
        user_arn = identity.get('Arn')
        
        # Test Bedrock availability
        # Note: bedrock-runtime doesn't have list_foundation_models, so we use bedrock service
        bedrock_available = False
        bedrock_error = None
        try:
            # Try bedrock service (for listing models)
            bedrock_service_client = boto3.client(
                'bedrock',
                aws_access_key_id=request.access_key_id,
                aws_secret_access_key=request.secret_access_key,
                region_name=request.region
            )
            # Lightweight check - just list one model
            bedrock_service_client.list_foundation_models(maxResults=1)
            bedrock_available = True
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                bedrock_error = "Missing Bedrock permissions. Please attach the policy from the setup wizard."
            elif error_code == 'ValidationException':
                # Sometimes bedrock service isn't available, but bedrock-runtime might be
                # Try bedrock-runtime client creation as a fallback
                try:
                    boto3.client(
                        'bedrock-runtime',
                        aws_access_key_id=request.access_key_id,
                        aws_secret_access_key=request.secret_access_key,
                        region_name=request.region
                    )
                    bedrock_available = True
                    bedrock_error = None
                except Exception:
                    bedrock_error = f"Bedrock not available in {request.region}. Please use us-east-1, us-west-2, or eu-west-1."
            else:
                bedrock_error = f"Bedrock not available in {request.region} or access denied: {error_code}"
        except Exception as e:
            bedrock_error = f"Bedrock check failed: {str(e)}"
        
        return {
            "success": True,
            "account_id": account_id,
            "user_arn": user_arn,
            "bedrock_available": bedrock_available,
            "bedrock_error": bedrock_error,
            "region": request.region
        }
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        if error_code == 'InvalidClientTokenId':
            return {
                "success": False,
                "error": "Invalid Access Key ID. Please check your credentials.",
                "error_code": error_code
            }
        elif error_code == 'SignatureDoesNotMatch':
            return {
                "success": False,
                "error": "Invalid Secret Access Key. Please check your credentials.",
                "error_code": error_code
            }
        else:
            return {
                "success": False,
                "error": f"AWS error: {error_message}",
                "error_code": error_code
            }
    except NoCredentialsError:
        return {
            "success": False,
            "error": "Credentials not provided or invalid format."
        }
    except Exception as e:
        logging.error(f"❌ Unexpected error testing credentials: {e}")
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}"
        }

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logging.info(f"📥 Incoming request: {request.method} {request.url}")
    try:
        response = await call_next(request)
        logging.info(f"📤 Outgoing response: status={response.status_code}, type={type(response)}")
        # Log response body size if it's a JSONResponse
        if hasattr(response, 'body'):
            try:
                body_size = len(response.body) if response.body else 0
                logging.info(f"   Response body size: {body_size} bytes")
            except:
                pass
        return response
    except Exception as e:
        logging.error(f"❌ Request failed: {str(e)}")
        logging.exception(e)
        raise

# ============================================
# POLICY GENERATION
# ============================================

@app.post("/generate")
async def generate(request: GenerationRequest):
    """Generate IAM policy with separate scoring for permissions and trust policies"""
    logging.info(f"🚀 /generate endpoint called")
    logging.info(f"   Request description length: {len(request.description)}")
    logging.info(f"   Is followup: {request.is_followup}")
    logging.info(f"   Conversation ID: {request.conversation_id}")
    logging.info(f"   User credentials provided: {request.aws_credentials is not None}")
    
    # Set user credentials in context (thread-safe)
    if request.aws_credentials:
        creds_dict = {
            'access_key_id': request.aws_credentials.access_key_id,
            'secret_access_key': request.aws_credentials.secret_access_key,
            'region': request.aws_credentials.region
        }
        set_user_credentials(creds_dict)
        logging.info(f"✅ User credentials set in context for region: {request.aws_credentials.region}")
        logging.info(f"   Access Key ID: {request.aws_credentials.access_key_id[:8]}...{request.aws_credentials.access_key_id[-4:] if len(request.aws_credentials.access_key_id) > 12 else '****'}")
        
        # Verify credentials are retrievable
        from features.policy_generation.bedrock_tool import _user_credentials as test_creds
        try:
            test_retrieved = test_creds.get()
            if test_retrieved:
                logging.info(f"✅ Verified: Credentials are retrievable from context (region: {test_retrieved.get('region')})")
            else:
                logging.error("❌ CRITICAL: Credentials not retrievable from context after setting!")
        except LookupError:
            logging.error("❌ CRITICAL: Context variable lookup failed!")
    
    try:
        # AUTO-DETECT ACTUAL AWS ACCOUNT ID from credentials
        actual_account_id = None
        try:
            import boto3
            # Use user credentials if provided, otherwise default
            if request.aws_credentials:
                sts = boto3.client(
                    'sts',
                    aws_access_key_id=request.aws_credentials.access_key_id,
                    aws_secret_access_key=request.aws_credentials.secret_access_key,
                    region_name=request.aws_credentials.region
                )
            else:
                sts = boto3.client('sts')
            
            actual_account_id = sts.get_caller_identity()['Account']
            logging.info(f"✅ Detected AWS Account ID: {actual_account_id}")
        except Exception as e:
            logging.warning(f"⚠️ Could not auto-detect AWS Account ID: {e}")
            # Continue without modification if detection fails
        
        # Replace any user-provided account ID with the ACTUAL account ID (if detected)
        if actual_account_id:
            import re
            # Match patterns like "AWS Account ID: 123456789012" or "Account ID: 123456789012"
            account_id_pattern = r'(?:AWS\s+)?Account\s+ID:\s*(\d{12})'
            
            if re.search(account_id_pattern, request.description, re.IGNORECASE):
                original_desc = request.description
                request.description = re.sub(
                    account_id_pattern,
                    f'AWS Account ID: {actual_account_id}',
                    request.description,
                    flags=re.IGNORECASE
                )
                logging.info(f"🔄 Replaced user-provided Account ID with actual Account ID: {actual_account_id}")
            else:
                # If no account ID provided, append the actual one
                request.description += f"\n\nAWS Account ID: {actual_account_id}"
                logging.info(f"➕ Added actual Account ID to description: {actual_account_id}")
    except Exception as e:
        logging.warning(f"⚠️ Could not auto-detect AWS Account ID: {e}")
        # Continue without modification if detection fails
    
    # CRITICAL: Wrap entire function to ensure we always return a response
    try:
        result = await _generate_internal(request)
        logging.info(f"✅ _generate_internal returned, type: {type(result)}")
        if isinstance(result, JSONResponse):
            logging.info(f"   JSONResponse status: {result.status_code}")
            return result
        return result
    except Exception as outer_error:
        logging.error(f"❌ CRITICAL: Outer exception handler caught error: {outer_error}")
        logging.exception(outer_error)
        # Return guaranteed minimal response as plain dict (let FastAPI serialize)
        error_response = {
            "conversation_id": str(uuid.uuid4()),
            "final_answer": f"An error occurred: {str(outer_error)[:200]}. Please try again.",
            "error": str(outer_error)[:200],
            "message_count": 1,
            "policy": None,
            "trust_policy": None
        }
        logging.info(f"⚠️ Returning error response from outer handler: {error_response}")
        return error_response  # Return dict, not JSONResponse - let FastAPI handle it
    finally:
        # SECURITY: Always clear user credentials after request
        if request.aws_credentials:
            clear_user_credentials()
            logging.info("🧹 User credentials cleared from context")

def _ensure_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _policy_has_condition(policy: Optional[Dict[str, Any]], condition_key: str) -> bool:
    if not policy:
        return False
    statements = _ensure_list(policy.get("Statement", []))
    for statement in statements:
        conditions = statement.get("Condition", {})
        if not isinstance(conditions, dict):
            continue
        for condition_type, entries in conditions.items():
            if isinstance(entries, dict):
                for key, value in entries.items():
                    if key.lower() == condition_key.lower():
                        # Treat both string and list values
                        if isinstance(value, str):
                            if value.lower() in ("true", "1", "required", "enabled"):
                                return True
                        else:
                            return True
    return False


def _policy_has_action(policy: Optional[Dict[str, Any]], service_prefix: str) -> bool:
    if not policy:
        return False
    statements = _ensure_list(policy.get("Statement", []))
    for statement in statements:
        actions = statement.get("Action")
        for action in _ensure_list(actions):
            if isinstance(action, str) and action.lower().startswith(service_prefix.lower()):
                return True
    return False


def _trust_policy_has_condition(trust_policy: Optional[Dict[str, Any]], condition_key: str) -> bool:
    if not trust_policy:
        return False
    statements = _ensure_list(trust_policy.get("Statement", []))
    for statement in statements:
        conditions = statement.get("Condition", {})
        if not isinstance(conditions, dict):
            continue
        for _, entries in conditions.items():
            if isinstance(entries, dict):
                for key, _ in entries.items():
                    if key.lower() == condition_key.lower():
                        return True
    return False


def _extract_account_id_from_policy(policy: Optional[Dict[str, Any]]) -> Optional[str]:
    if not policy:
        return None
    statements = _ensure_list(policy.get("Statement", []))
    for statement in statements:
        resources = statement.get("Resource")
        for resource in _ensure_list(resources):
            if isinstance(resource, str):
                match = re.match(r"arn:aws:[^:]+:[^:]*:(\d{12}):", resource)
                if match:
                    return match.group(1)
    return None


def _extract_region_from_policy(policy: Optional[Dict[str, Any]]) -> Optional[str]:
    if not policy:
        return None
    statements = _ensure_list(policy.get("Statement", []))
    for statement in statements:
        resources = statement.get("Resource")
        for resource in _ensure_list(resources):
            if isinstance(resource, str):
                match = re.match(r"arn:aws:[^:]+:([a-z0-9-]+):\d{12}:", resource)
                if match:
                    return match.group(1)
    return None


def generate_compliance_features(compliance_framework: str) -> List[Dict[str, str]]:
    """
    Generate compliance features with links for the selected framework
    
    Args:
        compliance_framework: Framework name (e.g., 'pci-dss', 'hipaa', 'gdpr', 'sox', 'cis')
    
    Returns:
        List of compliance features with title, description, requirement, and link
    """
    framework_map = {
        'pci-dss': [
            {
                'title': 'Least-Privilege Access (Requirement 7.1.2)',
                'subtitle': 'Policy uses specific actions instead of wildcards',
                'requirement': '7.1.2',
                'description': 'Policy uses specific actions instead of wildcards, limiting access to only necessary permissions. This ensures that even if credentials are compromised, attackers can only perform the exact operations needed for the intended function, significantly reducing the attack surface.'
            },
            {
                'title': 'Resource-Level Restrictions',
                'subtitle': 'Permissions scoped to specific resources',
                'requirement': '7.1.2',
                'description': 'Permissions are scoped to specific resources (tables, buckets, etc.) rather than using wildcards. This prevents unauthorized access to other resources in your account, ensuring cardholder data environments are properly isolated and protected.'
            },
            {
                'title': 'Access Logging Ready (Requirement 10)',
                'subtitle': 'CloudWatch Logs permissions enable audit trails',
                'requirement': '10',
                'description': 'CloudWatch Logs permissions enable comprehensive access monitoring and audit trails. All access to cardholder data can be logged and reviewed, supporting PCI DSS Requirement 10 which mandates tracking and monitoring all access to network resources and cardholder data.'
            },
            {
                'title': 'Network Segmentation Principles',
                'subtitle': 'Access limited to necessary services',
                'requirement': '1',
                'description': 'By restricting permissions to specific resources and services, this policy supports network segmentation principles. Access is limited to only the necessary services, reducing the risk of lateral movement if one component is compromised.'
            }
        ],
        'hipaa': [
            {
                'title': 'Access Controls (164.308(a)(4))',
                'subtitle': 'Least-privilege access controls to protect PHI',
                'requirement': '164.308(a)(4)',
                'description': 'Policy implements least-privilege access controls to protect PHI (Protected Health Information). HIPAA requires covered entities to implement procedures to authorize access to ePHI only when such access is appropriate based on the user\'s role. This policy ensures that only necessary permissions are granted, reducing the risk of unauthorized PHI access.'
            },
            {
                'title': 'Audit Logging (164.312(b))',
                'subtitle': 'CloudWatch Logs enable audit controls for ePHI',
                'requirement': '164.312(b)',
                'description': 'CloudWatch Logs permissions enable audit controls for access to ePHI. HIPAA requires implementation of hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI. This policy ensures all access to PHI is logged and can be audited.'
            },
            {
                'title': 'Data Protection & Encryption',
                'subtitle': 'Resource-level restrictions limit PHI exposure',
                'requirement': '164.312(a)(2)(iv)',
                'description': 'Resource-level restrictions limit access to specific data stores, reducing PHI exposure risk. HIPAA requires implementation of technical policies and procedures to allow access only to persons or software programs that have been granted access rights. This policy ensures PHI is only accessible to authorized services and processes.'
            },
            {
                'title': 'Minimum Necessary Standard',
                'subtitle': 'Access limited to minimum amount necessary',
                'requirement': '164.502(b)',
                'description': 'By using specific actions instead of wildcards, this policy implements the HIPAA "minimum necessary" standard, ensuring that access to PHI is limited to the minimum amount necessary to accomplish the intended purpose. This reduces the risk of unauthorized disclosure of PHI.'
            }
        ],
        'gdpr': [
            {
                'title': 'Data Minimization (Article 5)',
                'subtitle': 'Policy grants only necessary permissions',
                'requirement': 'Article 5',
                'description': 'Policy grants only necessary permissions, following data minimization principles. GDPR Article 5 requires that personal data be adequate, relevant, and limited to what is necessary in relation to the purposes for which they are processed. This policy ensures that access to personal data is restricted to only what\'s required for the specific function.'
            },
            {
                'title': 'Access Controls (Article 32)',
                'subtitle': 'Resource-level restrictions limit access to personal data',
                'requirement': 'Article 32',
                'description': 'Resource-level restrictions limit access to personal data, ensuring proper access controls. GDPR Article 32 requires implementation of appropriate technical and organizational measures to ensure a level of security appropriate to the risk, including the ability to ensure the ongoing confidentiality, integrity, availability, and resilience of processing systems.'
            },
            {
                'title': 'Audit Logging & Accountability',
                'subtitle': 'CloudWatch Logs enable audit trails for data access',
                'requirement': 'Article 5(2)',
                'description': 'CloudWatch Logs enable audit trails for data access, supporting data subject rights. GDPR requires organizations to demonstrate compliance (Article 5(2)) and be able to show how personal data is accessed and processed. This policy ensures all access to personal data is logged, supporting accountability requirements and enabling responses to data subject access requests.'
            },
            {
                'title': 'Purpose Limitation',
                'subtitle': 'Access limited to specified purposes',
                'requirement': 'Article 5(1)(b)',
                'description': 'By restricting permissions to specific actions and resources, this policy ensures that personal data is processed only for specified, explicit, and legitimate purposes (GDPR Article 5(1)(b)). Access is limited to what\'s necessary for the intended purpose, preventing unauthorized use of personal data.'
            }
        ],
        'sox': [
            {
                'title': 'Access Controls & Segregation of Duties',
                'subtitle': 'Specific permissions enforce access controls',
                'requirement': 'Section 404',
                'description': 'Policy uses specific permissions and resource restrictions to enforce access controls. This ensures that no single role has excessive privileges, supporting SOX Section 404 requirements for internal controls over financial reporting. Segregation of duties prevents conflicts of interest and reduces fraud risk.'
            },
            {
                'title': 'Comprehensive Audit Logging',
                'subtitle': 'CloudWatch Logs enable detailed audit trails',
                'requirement': 'Section 302',
                'description': 'CloudWatch Logs permissions enable detailed audit trails for financial data access. SOX requires organizations to maintain audit trails that track who accessed financial systems, when, and what changes were made. This policy ensures all access is logged and can be reviewed during SOX audits.'
            },
            {
                'title': 'Change Management Controls',
                'subtitle': 'Least-privilege prevents unauthorized changes',
                'requirement': 'Section 404',
                'description': 'Least-privilege design prevents unauthorized changes to financial systems. By limiting permissions to only what\'s necessary, this policy ensures that changes to financial data or systems require proper authorization and can be tracked, supporting SOX requirements for change management and preventing unauthorized modifications.'
            },
            {
                'title': 'Data Integrity Protection',
                'subtitle': 'Resource-level restrictions protect financial data',
                'requirement': 'Section 302',
                'description': 'Resource-level restrictions and specific action permissions ensure that financial data can only be accessed and modified by authorized processes. This protects the integrity of financial records and supports SOX requirements for accurate financial reporting.'
            }
        ],
        'cis': [
            {
                'title': 'Least-Privilege Access (CIS 1.1, 1.2)',
                'subtitle': 'Policy follows CIS AWS Benchmarks',
                'requirement': '1.1, 1.2',
                'description': 'Policy follows CIS AWS Benchmarks by using specific actions and resource restrictions. CIS Benchmark 1.1 and 1.2 recommend maintaining current contact details and ensuring security contact information is registered. This policy implements least-privilege principles aligned with CIS recommendations for IAM access management.'
            },
            {
                'title': 'Resource-Level Permissions',
                'subtitle': 'Permissions scoped to specific resources',
                'requirement': '1.1, 1.2',
                'description': 'Permissions are scoped to specific resources rather than using wildcards, following CIS recommendations for IAM policy best practices. This ensures that access is limited to only necessary resources, reducing the attack surface and aligning with CIS security controls.'
            }
        ]
    }
    
    features = framework_map.get(compliance_framework.lower(), [])
    
    # Add links to each feature
    for feature in features:
        framework_name = compliance_framework.upper().replace('-', ' ')
        if compliance_framework.lower() == 'pci-dss':
            framework_name = 'PCI DSS'
        elif compliance_framework.lower() == 'hipaa':
            framework_name = 'HIPAA'
        elif compliance_framework.lower() == 'gdpr':
            framework_name = 'GDPR'
        elif compliance_framework.lower() == 'sox':
            framework_name = 'SOX'
        elif compliance_framework.lower() == 'cis':
            framework_name = 'CIS'
        
        link = get_compliance_link(framework_name, feature['requirement'])
        feature['link'] = link
    
    return features


def build_compliance_help_text(
    policy: Dict[str, Any],
    trust_policy: Dict[str, Any],
    compliance_status: Dict[str, Any],
    selected_framework: Optional[str] = None,
) -> str:
    account_id = _extract_account_id_from_policy(policy) or "{{ACCOUNT_ID}}"
    region = _extract_region_from_policy(policy) or "{{REGION}}"

    secure_transport = _policy_has_condition(policy, "aws:SecureTransport")
    source_account = _trust_policy_has_condition(trust_policy, "aws:SourceAccount")
    encryption_at_rest = (
        _policy_has_condition(policy, "dynamodb:EncryptionType")
        or _policy_has_condition(policy, "kms:ViaService")
        or _policy_has_condition(policy, "kms:EncryptionContext")
    )
    region_restriction = _policy_has_condition(policy, "aws:RequestedRegion")
    audit_logging = _policy_has_action(policy, "cloudtrail:")

    improvements = [
        {
            "title": "Enforce Encryption in Transit",
            "details": (
                "Current DynamoDB and CloudWatch statements do not require TLS. "
                "Add a Bool or BoolIfExists condition such as `\"aws:SecureTransport\": \"true\"` "
                "to every statement so traffic is forced over HTTPS and aligns with PCI DSS requirement 4.2."
            )
            if not secure_transport
            else "You already enforce `aws:SecureTransport` in at least one statement. Double-check every data path, especially DynamoDB and logging APIs, to keep TLS mandatory.",
        },
        {
            "title": "Add Source Account Restriction to Trust Policy",
            "details": (
                f"The current trust policy allows ecs-tasks.amazonaws.com to assume the role without verifying the account. "
                f"Add a `StringEquals` condition for `\"aws:SourceAccount\": \"{account_id}\"` to prevent cross-account abuse and satisfy CIS controls."
            )
            if not source_account
            else f"`aws:SourceAccount` is already present. Confirm it matches `{account_id}` and consider pairing it with `aws:SourceArn` for specific ECS services.",
        },
        {
            "title": "Add Encryption at Rest Requirements",
            "details": (
                "DynamoDB access is not tied to a KMS key or encryption condition. "
                "Use `dynamodb:EncryptionType` or enforce an AWS KMS key ARN so data stored in `user-sessions` remains encrypted at rest per GDPR/HIPAA."
            )
            if not encryption_at_rest
            else "Encryption conditions are already referenced. Ensure the KMS keys are customer managed and mapped to the tables handling sensitive data.",
        },
        {
            "title": "Region Restriction for Geographical Compliance",
            "details": (
                f"Calls can be made from any region today. Add an `aws:RequestedRegion` condition locked to `{region}` (or approved regions) "
                "to satisfy residency requirements such as GDPR Article 44 and limit blast radius."
            )
            if not region_restriction
            else f"`aws:RequestedRegion` conditions exist. Review them when granting multi-region failover so they always reflect the approved footprint ({region}).",
        },
        {
            "title": "Enhance Audit Logging",
            "details": (
                "Grant read-only CloudTrail permissions (for example `cloudtrail:LookupEvents`) or send events to a dedicated logging role "
                "so you can demonstrate traceability for SOX and SOC 2. Pair this with the existing CloudWatch Logs statements."
            )
            if not audit_logging
            else "CloudTrail permissions are already scoped. Confirm trails cover DynamoDB data events and retain logs per your compliance window.",
        },
    ]

    lines = ["## Key Policy Improvements for Compliance", ""]
    for idx, item in enumerate(improvements, 1):
        lines.append(f"{idx}. {item['title']}")
        lines.append(item["details"])
        lines.append("")

    if compliance_status:
        lines.append("### Current Compliance Status Snapshot")
        lines.append(format_compliance_status(compliance_status))
        lines.append("")

    if selected_framework and selected_framework != "general":
        lines.append(
            f"These recommendations align with the {selected_framework.upper()} control set you selected. "
            "Apply them via the Refine Policy section or ask for an automatic update."
        )
    else:
        lines.append(
            "Select a framework in Quick Actions to validate these improvements against PCI DSS, HIPAA, SOX, GDPR, or CIS."
        )

    return "\n".join(line for line in lines if line is not None).strip()


def build_compliance_help_followup(
    conversation_id: str,
    cached: Dict[str, Any],
    previous_response: Optional[Dict[str, Any]],
    request: GenerationRequest,
) -> Dict[str, Any]:
    # Get policies from cache - try both cached and previous_response
    policy = None
    trust_policy = None
    if cached:
        policy = cached.get("policy")
        trust_policy = cached.get("trust_policy")
    if not policy and previous_response:
        policy = previous_response.get("policy")
    if not trust_policy and previous_response:
        trust_policy = previous_response.get("trust_policy")
    
    # Log for debugging
    logging.debug(f"🔍 Compliance help - Policy found: {policy is not None}, Trust policy found: {trust_policy is not None}")
    logging.debug(f"   Cached keys: {list(cached.keys()) if cached else 'No cache'}")
    logging.debug(f"   Previous response keys: {list(previous_response.keys()) if previous_response else 'No previous response'}")

    if not policy:
        final_text = (
            "I need a generated policy before I can map compliance controls. "
            "Please run Generate Policy first, then ask for compliance help again."
        )
    else:
        compliance_status = cached.get("compliance_status", {})
        if not compliance_status and previous_response:
            compliance_status = previous_response.get("compliance_status", {})
        selected_framework = (
            (request.compliance if hasattr(request, "compliance") else None)
            or cached.get("selected_compliance")
            or (previous_response.get("selected_compliance") if previous_response else None)
            or "general"
        )
        final_text = build_compliance_help_text(
            policy,
            trust_policy or {},
            compliance_status or {},
            selected_framework,
        )

    permissions_score = cached.get("permissions_score", 0)
    trust_score = cached.get("trust_score", 0)
    overall_score = cached.get("overall_score", 0)
    if previous_response:
        permissions_score = permissions_score or previous_response.get("permissions_score", 0)
        trust_score = trust_score or previous_response.get("trust_score", 0)
        overall_score = overall_score or previous_response.get("overall_score", 0)

    assistant_message = {
        "role": "assistant",
        "content": final_text,
        "timestamp": str(uuid.uuid4()),
    }
    conversations.setdefault(conversation_id, []).append(assistant_message)

    compliance_status_payload = cached.get("compliance_status", {})
    if not compliance_status_payload and previous_response:
        compliance_status_payload = previous_response.get("compliance_status", {})

    return {
        "conversation_id": conversation_id,
        "final_answer": final_text,
        "message_count": len(conversations.get(conversation_id, [])),
        "policy": policy,
        "trust_policy": trust_policy,
        "explanation": cached.get("explanation", previous_response.get("explanation") if previous_response else ""),
        "trust_explanation": cached.get(
            "trust_explanation",
            previous_response.get("trust_explanation") if previous_response else "",
        ),
        "permissions_score": permissions_score,
        "trust_score": trust_score,
        "overall_score": overall_score,
        "security_notes": cached.get(
            "security_notes",
            previous_response.get("security_notes", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []},
        ),
        "score_breakdown": cached.get(
            "score_breakdown",
            previous_response.get("score_breakdown", {}) if previous_response else {},
        ),
        "security_features": cached.get(
            "security_features",
            previous_response.get("security_features", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []},
        ),
        "refinement_suggestions": cached.get(
            "refinement_suggestions",
            previous_response.get("refinement_suggestions", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []},
        ),
        "is_question": False,
        "conversation_history": conversations.get(conversation_id, []),
        "compliance_status": compliance_status_payload,
    }


async def _generate_internal(request: GenerationRequest):
    """Internal generate function - actual implementation"""
    # Initialize variables to ensure they exist
    conversation_id = None
    final_message = ""
    agent_result = None
    response = None  # Initialize response variable
    is_explanation_request = False  # Initialize for non-followup requests
    has_existing_policies = False  # Initialize for non-followup requests
    
    # CRITICAL: This function MUST always return a valid dict, never None
    # If anything goes wrong, we'll return an error response
    
    # Create a default error response that will be used if anything fails
    default_error_response = {
        "conversation_id": str(uuid.uuid4()),
        "final_answer": "An unexpected error occurred. Please try again.",
        "message_count": 0,
        "policy": None,
        "trust_policy": None,
        "explanation": "An unexpected error occurred.",
        "trust_explanation": "",
        "permissions_score": 0,
        "trust_score": 0,
        "overall_score": 0,
        "security_notes": {"permissions": [], "trust": []},
        "score_breakdown": {},
        "security_features": {"permissions": [], "trust": []},
        "refinement_suggestions": {"permissions": [], "trust": []},
        "is_question": False,
        "conversation_history": [],
        "compliance_status": {},
        "error": "Internal server error"
    }
    
    try:
        conversation_id = request.conversation_id or str(uuid.uuid4())
        logging.info(
            "generate request received: conversation_id=%s service=%s followup=%s description_len=%s",
            conversation_id,
            request.service,
            request.is_followup,
            len(request.description) if request.description else 0,
        )

        previous_response = conversation_cache.get(conversation_id)
        
        # For follow-up requests, preserve the original service from cache instead of re-detecting
        if request.is_followup and previous_response:
            cached_service = previous_response.get("service")
            if cached_service and validate_service(cached_service):
                request.service = cached_service
                logging.debug("✅ Using cached service from previous request: %s", request.service)
        
        # Auto-detect service if not provided or invalid (only for new requests or if cache doesn't have service)
        if not request.service or request.service == 'lambda' or not validate_service(request.service):
            detected_service = detect_service_from_description(request.description)
            if detected_service and detected_service != request.service:
                request.service = detected_service
                logging.debug("service auto-detected as %s", request.service)
        
        if conversation_id not in conversations:
            conversations[conversation_id] = []
        
        # Store user message
        user_message = {
            "role": "user",
            "content": request.description,
            "timestamp": str(uuid.uuid4())
        }
        conversations[conversation_id].append(user_message)
        
        
        # REMOVED: "More Details" page - Always generate policies with placeholders if details are missing
        # The AI agent will automatically use {{ACCOUNT_ID}} and {{REGION}} placeholders when needed
        # This prevents user frustration and keeps the flow smooth
        logging.debug("proceeding with policy generation using placeholders when needed")
        
        # Build prompt - if followup, use conversation context
        # Let the AI agent intelligently interpret user intent (no hardcoded phrase matching!)
        prompt = request.description
        logging.debug("prompt preview: %s", prompt[:100] if prompt else "")
        logging.debug("conversation length=%s is_followup=%s", len(conversations[conversation_id]), request.is_followup)
        
        if request.is_followup and len(conversations[conversation_id]) > 1:
            logging.debug("📝 Follow-up request detected - letting agent handle dynamically")
            
            # Get cached data for context
            cached = conversation_cache.get(conversation_id, {})
            has_existing_policies = bool(cached.get("policy") or (previous_response and previous_response.get("policy")))
            conversation_history = conversations.get(conversation_id, [])

            user_intent = (request.description or "").lower()
            is_compliance_help_request = any(
                phrase in user_intent
                for phrase in [
                    "compliance help",
                    "compliance requirements",
                    "what compliance requirements",
                    "compliance considerations",
                ]
            )
            if is_compliance_help_request:
                logging.info("⚙️ Handling compliance help follow-up without invoking the agent")
                return build_compliance_help_followup(conversation_id, cached, previous_response, request)
            
            # Build conversation context for the agent
            context = "\n".join([
                f"{msg['role']}: {msg['content']}" 
                for msg in conversation_history[-10:]  # Last 10 messages
            ])
            
            # Get current policies for context - try multiple sources
            current_policy = None
            current_trust = None
            
            # First try cache
            if cached:
                current_policy = cached.get("policy")
                current_trust = cached.get("trust_policy")
            
            # Fallback to previous_response
            if not current_policy and previous_response:
                current_policy = previous_response.get("policy")
            if not current_trust and previous_response:
                current_trust = previous_response.get("trust_policy")
            
            # Log for debugging
            logging.debug(f"🔍 Follow-up request - Policy found: {current_policy is not None}, Trust policy found: {current_trust is not None}")
            logging.debug(f"   Cached exists: {cached is not None}, Previous response exists: {previous_response is not None}")
            if cached:
                logging.debug(f"   Cached keys: {list(cached.keys())}")
            if previous_response:
                logging.debug(f"   Previous response keys: {list(previous_response.keys())}")
            
            # IMPORTANT: Check if user provided a policy in their message (for explanation requests)
            # Extract policies from user's message BEFORE building prompt
            user_provided_policy = None
            user_provided_trust_policy = None
            
            # Check if user's message contains JSON policy
            user_json_blocks = re.findall(r'```json\s*([\s\S]*?)```', request.description, re.IGNORECASE)
            # Also try plain JSON (without code blocks)
            plain_json_pattern = r'\{\s*"Version"\s*:\s*"2012-10-17"[\s\S]*?\}'
            plain_json_matches = re.findall(plain_json_pattern, request.description, re.DOTALL)
            
            # Extract from code blocks first
            for json_str in user_json_blocks:
                try:
                    parsed = json.loads(json_str.strip())
                    if "Version" in parsed and "Statement" in parsed:
                        if "Principal" in str(parsed) or any("Principal" in str(stmt) for stmt in parsed.get('Statement', [])):
                            if not user_provided_trust_policy:
                                user_provided_trust_policy = parsed
                                logging.info("✅ Found trust policy in user's message")
                        else:
                            if not user_provided_policy:
                                user_provided_policy = parsed
                                logging.info("✅ Found permissions policy in user's message")
                except json.JSONDecodeError:
                    continue
            
            # If not found in code blocks, try plain JSON
            if not user_provided_policy and not user_provided_trust_policy:
                for json_str in plain_json_matches:
                    try:
                        parsed = json.loads(json_str.strip())
                        if "Version" in parsed and "Statement" in parsed:
                            if "Principal" in str(parsed) or any("Principal" in str(stmt) for stmt in parsed.get('Statement', [])):
                                if not user_provided_trust_policy:
                                    user_provided_trust_policy = parsed
                                    logging.info("✅ Found trust policy in user's message (plain JSON)")
                            else:
                                if not user_provided_policy:
                                    user_provided_policy = parsed
                                    logging.info("✅ Found permissions policy in user's message (plain JSON)")
                    except json.JSONDecodeError:
                        continue
            
            # Use user-provided policy if found, otherwise use cached
            policy_to_explain = user_provided_policy or current_policy
            trust_to_explain = user_provided_trust_policy or current_trust
            
            # Build intelligent prompt with full context - let the agent decide what to do
            if policy_to_explain:
                # Include compliance framework if specified
                compliance_note = ""
                if hasattr(request, 'compliance') and request.compliance and request.compliance != 'general':
                    compliance_note = f"\nCompliance Framework: {request.compliance.upper()}"
                
                # Detect if this is a compliance validation request
                is_compliance_validation = (
                    "validate" in request.description.lower() and "compliance" in request.description.lower()
                ) or (
                    hasattr(request, 'compliance') and request.compliance and request.compliance != 'general'
                )
                
                # Get the original service from cache or detect from trust policy
                original_service = cached.get("service") or request.service
                if current_trust:
                    # Try to detect service from trust policy principal
                    trust_str = json.dumps(current_trust)
                    if "ecs-tasks.amazonaws.com" in trust_str:
                        original_service = "ecs"
                    elif "lambda.amazonaws.com" in trust_str:
                        original_service = "lambda"
                    elif "ec2.amazonaws.com" in trust_str:
                        original_service = "ec2"
                
                # Provide full context and let agent intelligently respond
                service_context = f"\n**IMPORTANT: This is an {original_service.upper()} role policy** (not Lambda). The user's original request was for {original_service.upper()}."
                
                compliance_context = ""
                if is_compliance_validation:
                    compliance_context = f"\n\n**CRITICAL: The user wants to VALIDATE the EXISTING policies below against {request.compliance.upper() if hasattr(request, 'compliance') and request.compliance != 'general' else 'compliance'} requirements. DO NOT ask for the policy - it's already provided below. Analyze the existing policies and provide compliance validation results.**"
                
                prompt = f"""Previous conversation context:
{context}

User's current request: {request.description}{compliance_note}{service_context}{compliance_context}

Current Permissions Policy (ALREADY EXISTS - DO NOT ASK FOR IT):
{json.dumps(policy_to_explain, indent=2)}

Current Trust Policy (ALREADY EXISTS - DO NOT ASK FOR IT):
{json.dumps(trust_to_explain, indent=2) if trust_to_explain else 'None'}

Current Security Scores:
- Permissions Score: {cached.get("permissions_score", previous_response.get("permissions_score", 0) if previous_response else 0)}/100
- Trust Score: {cached.get("trust_score", previous_response.get("trust_score", 0) if previous_response else 0)}/100
- Overall Score: {cached.get("overall_score", previous_response.get("overall_score", 0) if previous_response else 0)}/100

Please respond to the user's request intelligently. Analyze what they're asking for and provide an appropriate response:
- If they want explanation → Provide clear text explanation first, then include policies
- If they want to modify → Update policies and explain changes
- If they want validation → Analyze security and compliance
- If they ask questions → Answer helpfully and relate to their policies
- Always validate any AWS values (regions, account IDs) before using them
- Always preserve existing policies unless explicitly asked to change them
- If compliance framework is specified, ensure any policy modifications maintain compliance
"""
            else:
                # No policies found in cache, but user might have provided one in their message
                if user_provided_policy:
                    # User provided a policy - use it for explanation/validation
                    logging.info("✅ User provided policy in message, using it for explanation")
                    
                    # Try to detect service from description
                    original_service = cached.get("service") if cached else request.service
                    if not original_service or original_service == 'lambda':
                        original_service = detect_service_from_description(request.description) or request.service
                    
                    # Include compliance framework if specified
                    compliance_note = ""
                    if hasattr(request, 'compliance') and request.compliance and request.compliance != 'general':
                        compliance_note = f"\nCompliance Framework: {request.compliance.upper()}"
                    
                    prompt = f"""User's request: {request.description}{compliance_note}

Permissions Policy (PROVIDED BY USER - DO NOT ASK FOR IT):
{json.dumps(user_provided_policy, indent=2)}

Trust Policy (PROVIDED BY USER - DO NOT ASK FOR IT):
{json.dumps(user_provided_trust_policy, indent=2) if user_provided_trust_policy else 'None (not provided)'}

Please respond to the user's request. If they asked to explain the policy, provide a detailed explanation of what this policy does and what permissions it grants.
"""
                else:
                    # No policies found in cache or user message - this shouldn't happen for follow-ups, but handle gracefully
                    # Try to get service from cache or detect from description
                    original_service = cached.get("service") if cached else request.service
                    if not original_service or original_service == 'lambda':
                        # Try to detect from conversation history or description
                        original_service = detect_service_from_description(request.description) or request.service
                    
                    service_context = f"\n**IMPORTANT: This is an {original_service.upper()} role policy** (not Lambda)."
                    
                    # Check if this is a compliance validation request
                    is_compliance_validation = (
                        "validate" in request.description.lower() and "compliance" in request.description.lower()
                    ) or (
                        hasattr(request, 'compliance') and request.compliance and request.compliance != 'general'
                    )
                    
                    compliance_context = ""
                    if is_compliance_validation:
                        compliance_context = f"\n\n**WARNING: You requested compliance validation, but I don't see existing policies in the conversation cache. Please ensure policies were generated first, or provide the policy JSON for validation.**"
                    
                    # Include compliance framework in prompt if specified
                    compliance_note = ""
                    if hasattr(request, 'compliance') and request.compliance and request.compliance != 'general':
                        compliance_note = f"\nCompliance Framework: {request.compliance.upper()}"
                    
                    prompt = f"{request.description}{service_context}{compliance_note}{compliance_context}"
        
        # Now call the agent with the prompt (whether followup or not)
        # The agent's system prompt already has comprehensive instructions
        # Let it handle all scenarios dynamically - no hardcoded routing!
        
        logging.debug(f"🤖 Calling agent with prompt (first 200 chars): {prompt[:200] if prompt else 'NONE'}...")
        logging.debug(f"🤖 Service: {request.service}")
        
        # Initialize variables
        final_message = ""
        agent_result = None
        
        try:
            # Call the agent - it will intelligently handle ANY request
            # Pass compliance explicitly to help agent extract it
            compliance_to_pass = request.compliance if hasattr(request, 'compliance') and request.compliance else None
            agent_result = aegis_agent.run(user_request=prompt, service=request.service, compliance=compliance_to_pass)
            logging.debug(f"✅ Agent call completed")
            
            # Extract message from agent result - handle multiple formats
            if agent_result and hasattr(agent_result, 'message'):
                agent_msg = agent_result.message
                
                # Try different extraction methods
                if isinstance(agent_msg, str):
                    final_message = agent_msg
                elif isinstance(agent_msg, dict):
                    # Try content blocks first
                    content_blocks = agent_msg.get("content", [])
                    if isinstance(content_blocks, list) and content_blocks:
                        # Extract text from all blocks
                        text_parts = []
                        for block in content_blocks:
                            if isinstance(block, dict):
                                if block.get("type") == "text" and "text" in block:
                                    text_parts.append(block["text"])
                                elif "text" in block:
                                    text_parts.append(block["text"])
                        if text_parts:
                            final_message = "\n".join(text_parts)
                        else:
                            final_message = str(agent_msg)
                    elif isinstance(content_blocks, dict) and "text" in content_blocks:
                        final_message = content_blocks["text"]
                    elif "text" in agent_msg:
                        final_message = agent_msg["text"]
                    else:
                        # Fallback: convert entire dict to string
                        final_message = str(agent_msg)
                else:
                    # Fallback: convert to string
                    final_message = str(agent_msg)
                
                # Log the extracted message for debugging
                logging.info(f"📝 Extracted final_message (length: {len(final_message) if final_message else 0})")
                if final_message:
                    logging.info(f"   First 300 chars: {final_message[:300]}")
            else:
                logging.warning("⚠️ Agent result has no message attribute")
                final_message = ""
        except Exception as e:
            logging.error(f"❌ Agent call failed: {e}")
            logging.exception(e)
            final_message = f"I apologize, but I encountered an error processing your request. Please try again or rephrase your question."
        
        # CRITICAL: Ensure final_message is set for follow-up requests
        if not final_message or (isinstance(final_message, str) and final_message.strip() == ''):
            logging.error("❌ CRITICAL: final_message is empty after agent call for follow-up request")
            logging.error(f"   agent_result type: {type(agent_result)}")
            logging.error(f"   agent_result: {str(agent_result)[:500] if agent_result else 'None'}")
            final_message = "I received your message, but I'm having trouble processing it. Please try rephrasing your question."
        
        # If we have a followup and policies exist, ensure we preserve them
        if request.is_followup and len(conversations[conversation_id]) > 1:
            cached = conversation_cache.get(conversation_id, {})
            previous_response = conversation_cache.get(conversation_id)
            
            # CRITICAL: For followup requests, we need to build and return a response
            # Add assistant message to conversation
            assistant_message = {
                "role": "assistant",
                "content": final_message,
                "timestamp": str(uuid.uuid4())
            }
            conversations[conversation_id].append(assistant_message)
            logging.debug(f"✅ Added assistant message to conversation (total messages: {len(conversations[conversation_id])})")
            
            # Extract policies from final_message if agent generated new ones
            policy = None
            trust_policy = None
            
            # Try to extract permissions policy
            permissions_patterns = [
                r'##\s*(?:🔐\s*)?(?:Updated\s+)?Permissions\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'##\s*Permissions\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'Permissions\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'```json\s*(\{[^`]*"Version"[^`]*"Statement"[^`]*\})\s*```',
            ]
            
            for pattern in permissions_patterns:
                permissions_match = re.search(pattern, final_message, re.IGNORECASE | re.DOTALL)
                if permissions_match:
                    try:
                        policy_json = permissions_match.group(1).strip()
                        policy_json = re.sub(r'\}\s*[^}]*$', '}', policy_json, flags=re.DOTALL)
                        policy_json = re.sub(r'\}\s*##', '}', policy_json)
                        policy = json.loads(policy_json)
                        logging.debug("✅ Found and parsed Permissions Policy in followup")
                        break
                    except json.JSONDecodeError:
                        continue
            
            # Try to extract trust policy
            trust_patterns = [
                r'##\s*(?:🤝\s*)?(?:Updated\s+)?Trust\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'##\s*Trust\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'Trust\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'```json\s*(\{[^`]*"Principal"[^`]*"sts:AssumeRole"[^`]*\})\s*```',
            ]
            
            for pattern in trust_patterns:
                trust_match = re.search(pattern, final_message, re.IGNORECASE | re.DOTALL)
                if trust_match:
                    try:
                        trust_json = trust_match.group(1).strip()
                        trust_json = re.sub(r'\}\s*[^}]*$', '}', trust_json, flags=re.DOTALL)
                        trust_json = re.sub(r'\}\s*##', '}', trust_json)
                        parsed_trust = json.loads(trust_json)
                        if "Principal" in str(parsed_trust) or any("Principal" in str(stmt) for stmt in parsed_trust.get('Statement', [])):
                            trust_policy = parsed_trust
                            logging.debug("✅ Found and parsed Trust Policy in followup")
                            break
                    except json.JSONDecodeError:
                        continue
            
            # CRITICAL: Check if this is an explanation-only request (not a modification)
            # If user asked to "explain", don't extract policies from response - they're just examples in the explanation
            user_lower = request.description.lower()
            is_explanation_only = any(keyword in user_lower for keyword in [
                "explain", "what does", "how does", "tell me about", "describe", "break down",
                "why", "what is", "what are", "help me understand", "show me", "can you explain",
                "i don't understand", "expalin", "explain this", "explain the"
            ])
            
            # IMPORTANT: For explanation requests, FIRST check if user provided a policy in their message
            # This allows users to paste a policy and ask "explain this policy"
            user_provided_policy = None
            user_provided_trust_policy = None
            
            if is_explanation_only:
                # Try to extract policies from user's message (they might have pasted a policy to explain)
                logging.info("📝 Explanation request detected - checking if user provided policy in message")
                
                # Extract JSON blocks from user's message
                user_json_blocks = re.findall(r'```json\s*([\s\S]*?)```', request.description, re.IGNORECASE)
                # Also try to find JSON objects not in code blocks (plain JSON)
                plain_json_pattern = r'\{\s*"Version"\s*:\s*"2012-10-17"[\s\S]*?\}'
                plain_json_matches = re.findall(plain_json_pattern, request.description, re.DOTALL)
                
                # Try to parse JSON from code blocks first
                for json_str in user_json_blocks:
                    try:
                        parsed = json.loads(json_str.strip())
                        if "Version" in parsed and "Statement" in parsed:
                            if "Principal" in str(parsed) or any("Principal" in str(stmt) for stmt in parsed.get('Statement', [])):
                                if not user_provided_trust_policy:
                                    user_provided_trust_policy = parsed
                                    logging.info("✅ Found trust policy in user's explanation request")
                            else:
                                if not user_provided_policy:
                                    user_provided_policy = parsed
                                    logging.info("✅ Found permissions policy in user's explanation request")
                    except json.JSONDecodeError:
                        continue
                
                # If not found in code blocks, try plain JSON
                if not user_provided_policy or not user_provided_trust_policy:
                    for json_str in plain_json_matches:
                        try:
                            parsed = json.loads(json_str.strip())
                            if "Version" in parsed and "Statement" in parsed:
                                if "Principal" in str(parsed) or any("Principal" in str(stmt) for stmt in parsed.get('Statement', [])):
                                    if not user_provided_trust_policy:
                                        user_provided_trust_policy = parsed
                                        logging.info("✅ Found trust policy in user's explanation request (plain JSON)")
                                else:
                                    if not user_provided_policy:
                                        user_provided_policy = parsed
                                        logging.info("✅ Found permissions policy in user's explanation request (plain JSON)")
                        except json.JSONDecodeError:
                            continue
                
                # Use user-provided policy if found, otherwise fall back to cached
                if user_provided_policy:
                    policy = user_provided_policy
                    logging.info("✅ Using policy from user's message for explanation")
                else:
                    policy = cached.get("policy") if cached else (previous_response.get("policy") if previous_response else None)
                    logging.info("📝 No policy in user's message, using cached policy for explanation")
                
                if user_provided_trust_policy:
                    trust_policy = user_provided_trust_policy
                    logging.info("✅ Using trust policy from user's message for explanation")
                else:
                    trust_policy = cached.get("trust_policy") if cached else (previous_response.get("trust_policy") if previous_response else None)
            else:
                # For modification requests, try to extract policies from response
                # Fallback: try to extract from all JSON blocks
                if not policy or not trust_policy:
                    all_json_blocks = re.findall(r'```json\s*([\s\S]*?)```', final_message, re.IGNORECASE)
                    if len(all_json_blocks) >= 1 and not policy:
                        try:
                            parsed_policy = json.loads(all_json_blocks[0].strip())
                            # Only use if it's a complete policy with Version and Statement (not just a single statement)
                            if "Version" in parsed_policy and "Statement" in parsed_policy and isinstance(parsed_policy.get("Statement"), list):
                                policy = parsed_policy
                                logging.debug("✅ Extracted Permissions Policy from first JSON block in followup")
                        except json.JSONDecodeError:
                            pass
                    
                    if len(all_json_blocks) >= 2 and not trust_policy:
                        try:
                            parsed_trust = json.loads(all_json_blocks[1].strip())
                            # Only use if it's a complete trust policy with Principal (not just a statement)
                            if "Principal" in str(parsed_trust) or any("Principal" in str(stmt) for stmt in parsed_trust.get('Statement', [])):
                                if "Version" in parsed_trust and "Statement" in parsed_trust:
                                    trust_policy = parsed_trust
                                    logging.debug("✅ Extracted Trust Policy from second JSON block in followup")
                        except json.JSONDecodeError:
                            pass
                
                # Use existing policies if agent didn't generate new ones
                if not policy:
                    policy = cached.get("policy") if cached else (previous_response.get("policy") if previous_response else None)
                if not trust_policy:
                    trust_policy = cached.get("trust_policy") if cached else (previous_response.get("trust_policy") if previous_response else None)
            
            # CRITICAL: If agent generated new policies, ALWAYS recalculate everything
            has_new_policy = policy and (not cached.get("policy") or json.dumps(policy, sort_keys=True) != json.dumps(cached.get("policy"), sort_keys=True))
            has_new_trust_policy = trust_policy and (not cached.get("trust_policy") or json.dumps(trust_policy, sort_keys=True) != json.dumps(cached.get("trust_policy"), sort_keys=True))
            
            if has_new_policy or has_new_trust_policy:
                # New policy generated - EXTRACT scores from Claude's response FIRST (FAST), only calculate if missing
                logging.info("🔄 New policy detected in followup - extracting scores from response")
                
                # FAST: Extract scores from Claude's response (no API calls needed)
                permissions_score = 0
                trust_score = 0
                overall_score = 0
                
                perm_score_match = re.search(
                    r'Permissions Policy Security Score[:\s]+(\d+)(?:/100)?',
                    final_message,
                    re.IGNORECASE
                )
                if perm_score_match:
                    permissions_score = int(perm_score_match.group(1))
                    logging.debug(f"✅ Extracted Permissions Score from response: {permissions_score}")
                
                trust_score_match = re.search(
                    r'Trust Policy Security Score[:\s]+(\d+)(?:/100)?',
                    final_message,
                    re.IGNORECASE
                )
                if trust_score_match:
                    trust_score = int(trust_score_match.group(1))
                    logging.debug(f"✅ Extracted Trust Score from response: {trust_score}")
                
                overall_score_match = re.search(
                    r'Overall Security Score[:\s]+(\d+)(?:/100)?',
                    final_message,
                    re.IGNORECASE
                )
                if overall_score_match:
                    overall_score = int(overall_score_match.group(1))
                    logging.debug(f"✅ Extracted Overall Score from response: {overall_score}")
                elif permissions_score > 0 and trust_score > 0:
                    overall_score = int((permissions_score * 0.7) + (trust_score * 0.3))
                
                # SLOW FALLBACK: Only calculate if Claude didn't provide scores
                if permissions_score == 0 or trust_score == 0:
                    logging.warning(f"⚠️ Scores not found in response, using fallback calculator (SLOW)")
                    permissions_score, trust_score, overall_score = calculate_policy_scores(policy, trust_policy)
                else:
                    logging.info(f"✅ Using extracted scores: permissions={permissions_score}, trust={trust_score}, overall={overall_score}")
                
                # FAST: Extract security features and breakdown from response
                score_breakdown = extract_score_breakdown(final_message)
                security_features = {"permissions": [], "trust": []}
                security_notes = {"permissions": [], "trust": []}
                
                # Extract security features from response
                perm_features_section = re.search(
                    r'##?\s*(?:🔧\s*)?(?:Permissions Policy )?Security Features([\s\S]*?)(?=##|###|$)', 
                    final_message, 
                    re.DOTALL | re.IGNORECASE
                )
                if perm_features_section:
                    features_text = perm_features_section.group(1)
                    security_features["permissions"] = [
                        line.strip('- ').strip('• ').strip('✅ ').strip()
                        for line in features_text.split('\n')
                        if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•') or line.strip().startswith('✅'))
                    ]
                
                trust_features_section = re.search(
                    r'##?\s*(?:🔧\s*)?(?:Trust Policy )?Security Features([\s\S]*?)(?=##|$)', 
                    final_message, 
                    re.DOTALL | re.IGNORECASE
                )
                if trust_features_section:
                    features_text = trust_features_section.group(1)
                    security_features["trust"] = [
                        line.strip('- ').strip('• ').strip('✅ ').strip()
                        for line in features_text.split('\n')
                        if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•') or line.strip().startswith('✅'))
                    ]
                
                # Extract security notes/considerations
                perm_notes_section = re.search(
                    r'##?\s*(?:⚠️\s*)?(?:Permissions Policy )?Considerations([\s\S]*?)(?=##|$)', 
                    final_message, 
                    re.DOTALL | re.IGNORECASE
                )
                if perm_notes_section:
                    notes_text = perm_notes_section.group(1)
                    security_notes["permissions"] = [
                        line.strip('- ').strip('• ').strip()
                        for line in notes_text.split('\n')
                        if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                    ]
                
                trust_notes_section = re.search(
                    r'##?\s*(?:⚠️\s*)?(?:Trust Policy )?Considerations([\s\S]*?)(?=##|$)', 
                    final_message, 
                    re.DOTALL | re.IGNORECASE
                )
                if trust_notes_section:
                    notes_text = trust_notes_section.group(1)
                    security_notes["trust"] = [
                        line.strip('- ').strip('• ').strip()
                        for line in notes_text.split('\n')
                        if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                    ]
                
                # SLOW FALLBACK: Only generate breakdown if not extracted from response
                has_permissions_breakdown = bool(score_breakdown.get("permissions", {}).get("positive") or score_breakdown.get("permissions", {}).get("improvements"))
                has_trust_breakdown = bool(score_breakdown.get("trust", {}).get("positive") or score_breakdown.get("trust", {}).get("improvements"))
                if not has_permissions_breakdown or not has_trust_breakdown:
                    logging.warning(f"⚠️ Score breakdown not found in response, using fallback generator (SLOW)")
                    score_breakdown = generate_score_breakdown(policy, trust_policy, permissions_score, trust_score)
                
                # FAST: Extract explanations from response
                explanation_match = re.search(
                    r'##\s*Permissions Policy Explanation([\s\S]*?)(?=##|$)',
                    final_message,
                    re.DOTALL | re.IGNORECASE
                )
                explanation_text = explanation_match.group(1).strip() if explanation_match else ""
                
                trust_explanation_match = re.search(
                    r'##\s*Trust Policy Explanation([\s\S]*?)(?=##|$)',
                    final_message,
                    re.DOTALL | re.IGNORECASE
                )
                trust_explanation_text = trust_explanation_match.group(1).strip() if trust_explanation_match else ""
                
                # SLOW FALLBACK: Only generate explanations if not in response
                if not explanation_text and policy:
                    logging.warning(f"⚠️ Permissions explanation not found in response, using fallback generator (SLOW)")
                    explanation_text = generate_permissions_explanation(policy)
                if not trust_explanation_text and trust_policy:
                    logging.warning(f"⚠️ Trust explanation not found in response, using fallback generator (SLOW)")
                    trust_explanation_text = generate_trust_explanation(trust_policy)
                
                # Extract refinement suggestions from response
                refinement_suggestions = {"permissions": [], "trust": []}
                perm_refinement_match = re.search(
                    r'##\s*(?:Permissions Policy )?Refinement Suggestions([\s\S]*?)(?=##\s*(?:Trust|$))',
                    final_message,
                    re.DOTALL | re.IGNORECASE
                )
                if perm_refinement_match:
                    suggestions_text = perm_refinement_match.group(1)
                    refinement_suggestions["permissions"] = [
                        line.strip('- ').strip('• ').strip()
                        for line in suggestions_text.split('\n')
                        if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                    ][:5]
                
                trust_refinement_match = re.search(
                    r'##\s*(?:Trust Policy )?Refinement Suggestions([\s\S]*?)(?=##|$)',
                    final_message,
                    re.DOTALL | re.IGNORECASE
                )
                if trust_refinement_match:
                    suggestions_text = trust_refinement_match.group(1)
                    refinement_suggestions["trust"] = [
                        line.strip('- ').strip('• ').strip()
                        for line in suggestions_text.split('\n')
                        if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                    ][:5]
                
                # SLOW FALLBACK: Use breakdown improvements if refinement suggestions not extracted
                if not refinement_suggestions["permissions"] and score_breakdown.get("permissions", {}).get("improvements"):
                    refinement_suggestions["permissions"] = score_breakdown.get("permissions", {}).get("improvements", [])[:5]
                if not refinement_suggestions["trust"] and score_breakdown.get("trust", {}).get("improvements"):
                    refinement_suggestions["trust"] = score_breakdown.get("trust", {}).get("improvements", [])[:5]
                
                logging.info(f"✅ Extracted from response: permissions_score={permissions_score}, trust_score={trust_score}, overall_score={overall_score}")
                logging.info(f"✅ Extracted explanations: permissions={len(explanation_text)} chars, trust={len(trust_explanation_text)} chars")
            else:
                # No new policy - use cached scores
                permissions_score = cached.get("permissions_score", previous_response.get("permissions_score", 0) if previous_response else 0) if cached else (previous_response.get("permissions_score", 0) if previous_response else 0)
                trust_score = cached.get("trust_score", previous_response.get("trust_score", 0) if previous_response else 0) if cached else (previous_response.get("trust_score", 0) if previous_response else 0)
                overall_score = cached.get("overall_score", previous_response.get("overall_score", 0) if previous_response else 0) if cached else (previous_response.get("overall_score", 0) if previous_response else 0)
                
                # Calculate scores if not available
                if (permissions_score == 0 or trust_score == 0) and (policy or trust_policy):
                    permissions_score, trust_score, overall_score = calculate_policy_scores(policy, trust_policy)
                
                # Use cached breakdown and features
                score_breakdown = cached.get("score_breakdown", previous_response.get("score_breakdown", {}) if previous_response else {}) if cached else (previous_response.get("score_breakdown", {}) if previous_response else {})
                security_features = cached.get("security_features", previous_response.get("security_features", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []}) if cached else (previous_response.get("security_features", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []})
                security_notes = cached.get("security_notes", previous_response.get("security_notes", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []}) if cached else (previous_response.get("security_notes", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []})
                refinement_suggestions = cached.get("refinement_suggestions", previous_response.get("refinement_suggestions", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []}) if cached else (previous_response.get("refinement_suggestions", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []})
                
                # Initialize explanation variables for else branch
                explanation_text = ""
                trust_explanation_text = ""
            
            # Build conversation history
            conversation_history = []
            for msg in conversations.get(conversation_id, []):
                content = msg.get("content", "")
                if not isinstance(content, str):
                    content = str(content) if content is not None else ""
                if msg.get("role") == "assistant":
                    has_policy_json = bool(re.search(r'```json[\s\S]*?```', content))
                    if has_policy_json:
                        json_match = re.search(r'(```json[\s\S]*?```)', content)
                        if json_match:
                            content = json_match.group(1)
                    else:
                        content = re.sub(r'```json[\s\S]*?```', '', content)
                        content = re.sub(r'```[\s\S]*?```', '', content)
                        content = re.sub(r'\{[\s\S]*?"Version"[\s\S]*?\}', '', content)
                        policy_exp_start = re.search(r'##\s*(?:Permissions |Trust )?Policy', content, re.IGNORECASE)
                        if policy_exp_start:
                            content = content[:policy_exp_start.start()]
                    content = ' '.join(content.split()).strip()
                
                conversation_history.append({  
                    "role": msg.get("role", "user"),
                    "content": content,
                    "timestamp": msg.get("timestamp", "")
                })
            
            # Build response for followup request
            # Use regenerated explanation if new policy, otherwise use cached or final_message
            if has_new_policy or has_new_trust_policy:
                # New policy - use regenerated explanations
                followup_explanation = explanation_text if policy else (cached.get("explanation", final_message) if cached else final_message)
                followup_trust_explanation = trust_explanation_text if trust_policy else (cached.get("trust_explanation", previous_response.get("trust_explanation", "") if previous_response else "") if cached else (previous_response.get("trust_explanation", "") if previous_response else ""))
            else:
                # No new policy - use cached or final_message
                followup_explanation = cached.get("explanation", final_message) if cached else final_message
                followup_trust_explanation = cached.get("trust_explanation", previous_response.get("trust_explanation", "") if previous_response else "") if cached else (previous_response.get("trust_explanation", "") if previous_response else "")
            
            # Generate compliance_features with links if compliance framework is selected
            compliance_features = []
            if hasattr(request, 'compliance') and request.compliance and request.compliance != 'general':
                compliance_features = generate_compliance_features(request.compliance)
                logging.debug(f"✅ Generated {len(compliance_features)} compliance features for {request.compliance}")
            elif cached and cached.get("compliance_features"):
                compliance_features = cached.get("compliance_features", [])
            elif previous_response and previous_response.get("compliance_features"):
                compliance_features = previous_response.get("compliance_features", [])
            
            followup_response = {
                "conversation_id": conversation_id,
                "final_answer": final_message,
                "message_count": len(conversations.get(conversation_id, [])),
                "policy": policy,
                "trust_policy": trust_policy,
                "explanation": followup_explanation,
                "trust_explanation": followup_trust_explanation,
                "permissions_score": permissions_score or 0,
                "trust_score": trust_score or 0,
                "overall_score": overall_score or 0,
                "security_notes": security_notes if (has_new_policy or has_new_trust_policy) else (cached.get("security_notes", previous_response.get("security_notes", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []}) if cached else (previous_response.get("security_notes", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []})),
                "security_features": security_features if (has_new_policy or has_new_trust_policy) else (cached.get("security_features", previous_response.get("security_features", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []}) if cached else (previous_response.get("security_features", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []})),
                "score_breakdown": score_breakdown if (has_new_policy or has_new_trust_policy) else (cached.get("score_breakdown", previous_response.get("score_breakdown", {}) if previous_response else {}) if cached else (previous_response.get("score_breakdown", {}) if previous_response else {})),
                "is_question": False,  # Followup requests are not questions
                "conversation_history": conversation_history or [],
                "refinement_suggestions": refinement_suggestions if (has_new_policy or has_new_trust_policy) else (cached.get("refinement_suggestions", previous_response.get("refinement_suggestions", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []}) if cached else (previous_response.get("refinement_suggestions", {"permissions": [], "trust": []}) if previous_response else {"permissions": [], "trust": []})),
                "compliance_status": cached.get("compliance_status", previous_response.get("compliance_status", {}) if previous_response else {}) if cached else (previous_response.get("compliance_status", {}) if previous_response else {}),
                "compliance_features": compliance_features
            }
            
            # Update cache with new policies if agent generated them
            if policy or trust_policy:
                conversation_cache[conversation_id] = {
                    "policy": policy or cached.get("policy"),
                    "trust_policy": trust_policy or cached.get("trust_policy"),
                    "service": request.service,  # Preserve service for follow-up requests
                    "explanation": followup_explanation,
                    "trust_explanation": followup_trust_explanation,
                    "permissions_score": permissions_score or 0,
                    "trust_score": trust_score or 0,
                    "overall_score": overall_score or 0,
                    "score_breakdown": score_breakdown if (has_new_policy or has_new_trust_policy) else followup_response.get("score_breakdown", {}),
                    "security_features": security_features if (has_new_policy or has_new_trust_policy) else followup_response.get("security_features", {"permissions": [], "trust": []}),
                    "security_notes": security_notes if (has_new_policy or has_new_trust_policy) else followup_response.get("security_notes", {"permissions": [], "trust": []}),
                    "refinement_suggestions": refinement_suggestions if (has_new_policy or has_new_trust_policy) else followup_response.get("refinement_suggestions", {"permissions": [], "trust": []}),
                    "compliance_status": followup_response.get("compliance_status", {}),
                    "selected_compliance": (request.compliance if hasattr(request, "compliance") and request.compliance else cached.get("selected_compliance", "general")),
                    "conversation_history": conversation_history or [],
                    "last_updated": str(uuid.uuid4())
                }
                logging.debug("✅ Updated conversation cache with followup response")
                logging.debug(f"   Score breakdown keys: {list(score_breakdown.keys()) if (has_new_policy or has_new_trust_policy) else 'using cached'}")
                logging.debug(f"   Security features: {len(security_features.get('permissions', [])) if (has_new_policy or has_new_trust_policy) else 'cached'} permissions, {len(security_features.get('trust', [])) if (has_new_policy or has_new_trust_policy) else 'cached'} trust")
                logging.debug(f"   Refinement suggestions: {len(refinement_suggestions.get('permissions', [])) if (has_new_policy or has_new_trust_policy) else 'cached'} permissions, {len(refinement_suggestions.get('trust', [])) if (has_new_policy or has_new_trust_policy) else 'cached'} trust")
                logging.debug(f"   Explanation length: {len(followup_explanation)} chars")
            
            logging.info(f"✅ Returning followup response with conversation_id: {followup_response.get('conversation_id')}")
            logging.info(f"   Final answer length: {len(followup_response.get('final_answer', ''))}")
            logging.info(f"   Has policy: {followup_response.get('policy') is not None}")
            logging.info(f"   Has trust_policy: {followup_response.get('trust_policy') is not None}")
            
            # Return the followup response
            return followup_response
        
        # Continue with normal response parsing...
        
        logging.debug("✅ Using AI agent to interpret user intent (no hardcoded phrase matching)")
        
        # If explanation requested and policies exist, generate explanation directly via Bedrock
        if is_explanation_request and has_existing_policies:
            logging.debug("🔍 Explanation requested - generating explanation directly via Bedrock (bypassing tool)")
            
            # Extract policies from conversation history - look for both permissions and trust policies
            permissions_policy_text = ""
            trust_policy_text = ""
            
            for msg in reversed(conversations[conversation_id]):
                content = str(msg.get('content', ''))
                # Look for JSON blocks with policies
                json_blocks = re.findall(r'```json\s*([\s\S]*?)```', content, re.IGNORECASE)
                for json_block in json_blocks:
                    try:
                        parsed = json.loads(json_block.strip())
                        # Check if it's a permissions policy (has Action/Resource, no Principal)
                        if '"Version"' in json_block and '"Statement"' in json_block:
                            if '"Principal"' not in json_block and ('"Action"' in json_block or '"Resource"' in json_block):
                                if not permissions_policy_text:
                                    permissions_policy_text = json_block.strip()
                            elif '"Principal"' in json_block:
                                if not trust_policy_text:
                                    trust_policy_text = json_block.strip()
                    except:
                        pass
                
                # Also check for policies in final_answer from previous responses
                if '"Version"' in content and '"Statement"' in content:
                    # Try to extract JSON from the content
                    json_match = re.search(r'\{[\s\S]*?"Version"[\s\S]*?"Statement"[\s\S]*?\}', content)
                    if json_match:
                        try:
                            parsed = json.loads(json_match.group(0))
                            if '"Principal"' not in json_match.group(0):
                                if not permissions_policy_text:
                                    permissions_policy_text = json_match.group(0)
                            else:
                                if not trust_policy_text:
                                    trust_policy_text = json_match.group(0)
                        except:
                            pass
            
            # Combine both policies
            policies_text = ""
            if permissions_policy_text:
                policies_text += f"## Permissions Policy\n```json\n{permissions_policy_text}\n```\n\n"
            if trust_policy_text:
                policies_text += f"## Trust Policy\n```json\n{trust_policy_text}\n```\n\n"
            
            if policies_text:
                # Generate explanation directly using Bedrock
                import boto3
                bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
                
                explanation_prompt = f"""You are explaining an existing IAM policy to a user. The user asked you to explain what this policy does.

Here are the policies from the conversation:

{policies_text}

**CRITICAL INSTRUCTIONS - YOU MUST FOLLOW THIS EXACT FORMAT:**

1. **START WITH TEXT EXPLANATION** - Provide a clear, conversational explanation in plain English
2. **Explain overall purpose** - What does this policy allow?
3. **Explain EACH statement** - What does each statement do?
4. **THEN include policies** - Include the policies in JSON format for reference

**EXACT RESPONSE FORMAT (follow this exactly):**

```
This policy allows your Lambda function to read files from the S3 bucket 'customer-uploads' and write logs to CloudWatch.

Here's what each statement does:

Statement 1 (S3BucketOperations): This gives your Lambda permission to see what files are in the bucket and find where the bucket is located. This is needed before you can actually read files.

Statement 2 (S3ObjectOperations): This is the core permission - it lets your Lambda actually read and download files from the bucket. Without this, you can't access the file contents.

Statement 3 (CloudWatchLogsAccess): This allows your Lambda to create log groups and write log messages. This is important for debugging and monitoring your function.

Here are the policies for reference:

## Permissions Policy
```json
{permissions_policy_text if permissions_policy_text else '{}'}
```

## Trust Policy
```json
{trust_policy_text if trust_policy_text else '{}'}
```

Let me know if you have any questions!
```

**CRITICAL:**
- DO NOT skip the text explanation
- DO NOT just return JSON
- Start with conversational explanation FIRST
- Then include policies in JSON format
- Be helpful and clear"""
                
                body = json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4000,  # Optimized - actual usage is ~1500-2000 tokens
                    "messages": [{"role": "user", "content": [{"type": "text", "text": explanation_prompt}]}],
                    "temperature": 0.3
                })
                
                try:
                    response = bedrock_runtime.invoke_model(
                        body=body,
                        modelId="us.anthropic.claude-3-7-sonnet-20250219-v1:0"
                    )
                    body_bytes = response.get('body').read()
                    response_body = json.loads(body_bytes)
                    final_message = response_body.get('content', [{}])[0].get('text', '')
                    logging.debug("✅ Generated explanation directly via Bedrock")
                except Exception as e:
                    logging.error(f"❌ Failed to generate explanation: {e}")
                    # Fallback to agent
                    logging.debug(f"🤖 Fallback: Calling agent with prompt: {prompt[:100]}...")
                    agent_result = aegis_agent.run(user_request=prompt, service=request.service)
                    final_message = str(agent_result.message)
                    if isinstance(agent_result.message, dict):
                        if "content" in agent_result.message and isinstance(agent_result.message["content"], list):
                            if len(agent_result.message["content"]) > 0 and "text" in agent_result.message["content"][0]:
                                final_message = agent_result.message["content"][0]["text"]
            else:
                # No policies found, use agent
                logging.debug(f"🤖 Calling agent with prompt: {prompt[:100]}...")
                agent_result = aegis_agent.run(user_request=prompt, service=request.service)
                final_message = str(agent_result.message)
                if isinstance(agent_result.message, dict):
                    if "content" in agent_result.message and isinstance(agent_result.message["content"], list):
                        if len(agent_result.message["content"]) > 0 and "text" in agent_result.message["content"][0]:
                            final_message = agent_result.message["content"][0]["text"]
            
        # Normal flow - use agent (for non-followup requests)
        if not request.is_followup or len(conversations[conversation_id]) <= 1:
            logging.debug(f"📝 Non-followup request - proceeding with normal flow")
            logging.debug(f"📝 Prompt length: {len(prompt) if prompt else 0} chars")
            logging.debug(f"📝 Service: {request.service}")
            logging.debug(f"📝 Prompt value (first 200 chars): {prompt[:200] if prompt else 'PROMPT IS NONE!'}")
            
            # Initialize final_message to ensure it exists
            final_message = ""
            agent_result = None
            
            try:
                logging.debug(f"🤖 About to call agent...")
                logging.debug(f"🤖 Agent type: {type(aegis_agent)}")
                logging.debug(f"🤖 Prompt type: {type(prompt)}")
                logging.debug(f"🤖 Service type: {type(request.service)}")
                
                logging.debug(f"🤖 Calling agent with prompt: {prompt[:100] if prompt else 'NONE'}...")
                logging.debug(f"🤖 Service parameter: {request.service}")
                agent_result = aegis_agent.run(user_request=prompt, service=request.service)
                logging.debug(f"✅ Agent call completed successfully")
                logging.debug(f"✅ Agent result type: {type(agent_result)}")
                logging.debug(f"✅ Agent result: {str(agent_result)[:200] if agent_result else 'NONE'}")
                
                if agent_result and hasattr(agent_result, 'message'):
                    logging.debug(f"✅ Agent message type: {type(agent_result.message)}")
                    final_message = str(agent_result.message)
                    if isinstance(agent_result.message, dict):
                        logging.debug("📝 Agent message is a dict, extracting text...")
                        content_blocks = agent_result.message.get("content", [])
                        if isinstance(content_blocks, list) and content_blocks:
                            first_block = content_blocks[0]
                            if isinstance(first_block, dict) and first_block.get("type") == "text":
                                final_message = first_block.get("text", final_message)
                            elif isinstance(first_block, dict) and "text" in first_block:
                                final_message = first_block["text"]
                        elif isinstance(content_blocks, dict):
                            if "text" in content_blocks:
                                final_message = content_blocks["text"]
                else:
                    logging.warning("⚠️ Agent returned no message; using cached response if available")
                    cached = conversation_cache.get(conversation_id)
                    if cached:
                        final_message = build_final_message_from_cache(cached)
                        policy = cached.get("policy")
                        trust_policy = cached.get("trust_policy")
                        permissions_score = cached.get("permissions_score", 0)
                        trust_score = cached.get("trust_score", 0)
                        overall_score = cached.get("overall_score", 0)
                        security_notes = cached.get("security_notes", {"permissions": [], "trust": []})
                        security_features = cached.get("security_features", {"permissions": [], "trust": []})
                        explanation = cached.get("explanation", "") or generate_permissions_explanation(policy)
                        trust_explanation = cached.get("trust_explanation", "") or generate_trust_explanation(trust_policy)
                        refinement_suggestions = cached.get("refinement_suggestions", {"permissions": [], "trust": []})
                        compliance_status = cached.get("compliance_status", {})
                        score_breakdown = cached.get("score_breakdown", {"permissions": {"positive": [], "improvements": []}, "trust": {"positive": [], "improvements": []}})
                        cached_response = {
                            "conversation_id": conversation_id,
                            "final_answer": final_message,
                            "message_count": len(conversations.get(conversation_id, [])),
                            "policy": policy,
                            "trust_policy": trust_policy,
                            "explanation": explanation,
                            "trust_explanation": trust_explanation,
                            "permissions_score": permissions_score,
                            "trust_score": trust_score,
                            "overall_score": overall_score,
                            "security_notes": security_notes,
                            "security_features": security_features,
                            "score_breakdown": score_breakdown,
                            "is_question": False,
                            "conversation_history": conversations[conversation_id][-10:],
                            "refinement_suggestions": refinement_suggestions,
                            "compliance_status": compliance_status,
                        }
                        logging.info("✅ Returning cached follow-up response")
                        # Return as dict, not JSONResponse - let FastAPI handle serialization
                        return cached_response
            except asyncio.TimeoutError as timeout_error:
                logging.error(f"❌ CRITICAL: Agent call timed out: {timeout_error}")
                logging.exception(timeout_error)
                final_message = "The request timed out. Please try again with a simpler request."
            except Exception as agent_error:
                logging.error(f"❌ CRITICAL: Agent call failed: {agent_error}")
                logging.exception(agent_error)
                final_message = f"An error occurred while calling the AI agent: {str(agent_error)}"
                # Continue to build error response
            
            # CRITICAL: Ensure final_message is never empty before proceeding
            if not final_message or (isinstance(final_message, str) and final_message.strip() == ''):
                logging.error("❌ CRITICAL: final_message is empty after agent call!")
                logging.error(f"   agent_result type: {type(agent_result)}")
                logging.error(f"   agent_result value: {str(agent_result)[:200] if agent_result else 'None'}")
                final_message = "An error occurred while generating the policy. The AI agent did not return a response. Please try again."
            
            # CRITICAL: Add assistant message to conversation BEFORE checking for early return
            assistant_message = {
                "role": "assistant",
                "content": final_message,
                "timestamp": str(uuid.uuid4())
            }
            conversations[conversation_id].append(assistant_message)
            logging.debug(f"✅ Added assistant message to conversation (total messages: {len(conversations[conversation_id])})")
            
            # DEBUG: Log what Bedrock returned
            logging.debug("=" * 80)
            logging.debug("🔍 BEDROCK RAW RESPONSE (first 2000 chars):")
            logging.debug(final_message[:2000] if final_message else "EMPTY MESSAGE!")
            logging.debug("=" * 80)
            
            # For explanation requests, return the explanation as-is without extracting policies
            logging.info(f"🔍 Checking explanation request: is_explanation_request={is_explanation_request}, has_existing_policies={has_existing_policies}")
            if is_explanation_request and has_existing_policies:
                logging.info("✅ Explanation request detected - returning explanation text as final_answer")
                logging.info(f"   Conversation has {len(conversations[conversation_id])} messages")
                logging.info(f"   Final message length: {len(final_message)} chars")
                explanation_response = {
                    "conversation_id": conversation_id,
                    "final_answer": final_message,  # This contains the explanation + policies for reference
                    "message_count": len(conversations[conversation_id]),
                    "policy": None,  # Don't extract separately - it's in the explanation
                    "trust_policy": None,  # Don't extract separately - it's in the explanation
                    "explanation": final_message,  # Full explanation
                    "trust_explanation": "",
                    "permissions_score": 0,
                    "trust_score": 0,
                    "overall_score": 0,
                    "security_notes": {"permissions": [], "trust": []},
                    "score_breakdown": {},
                    "security_features": {"permissions": [], "trust": []},
                    "refinement_suggestions": {"permissions": [], "trust": []},
                    "is_question": False,  # Not a question - it's an explanation
                    "conversation_history": conversations[conversation_id][-10:],  # Include latest messages
                    "compliance_status": {}
                }
                logging.info(f"✅ Returning explanation response with conversation_id: {explanation_response.get('conversation_id')}")
                logging.info(f"   Conversation history length: {len(explanation_response.get('conversation_history', []))}")
                logging.info(f"   Final answer length: {len(explanation_response.get('final_answer', ''))}")
                logging.info(f"   About to return explanation_response (type: {type(explanation_response)})")
                # Return as dict, not JSONResponse - let FastAPI handle serialization
                result = explanation_response
                logging.info(f"✅ EXPLANATION PATH: Returning explanation_response")
                return result
            
            policy = None
            trust_policy = None
            explanation = final_message
            trust_explanation = ""
            permissions_score = 0
            trust_score = 0
            overall_score = 0
            security_notes = {"permissions": [], "trust": []}
            security_features = {"permissions": [], "trust": []}
            # Only set is_question to True if we detect actual question patterns
            # Default to False - assume it's a response unless we detect question markers
            is_question = False
            question_indicators = [
                r'\?',  # Contains question mark
                r'what\s+(is|are|do|does|should|can|could|would)',  # Question words
                r'how\s+(do|does|should|can|could|would)',  # How questions
                r'can\s+you\s+(please|provide|tell|clarify|explain)',  # Can you questions
                r'please\s+(provide|tell|clarify|explain|specify)',  # Please questions
                r'i\s+(need|require|want)\s+(more|additional|further)',  # Need more info
                r'(missing|need|require|specify).*?(account|region|bucket|arn|resource)',  # Missing info requests
            ]
            # Check if response contains question indicators
            message_lower = final_message.lower()
            for pattern in question_indicators:
                if re.search(pattern, message_lower, re.IGNORECASE):
                    is_question = True
                    logging.debug(f"🔍 Detected question indicator: {pattern}")
                    break
            
            logging.debug(f"📝 Parsing agent response (length: {len(final_message)} chars)")
            
            # Extract Permissions Policy - Improved regex patterns with multiple fallbacks
            permissions_patterns = [
                r'##\s*(?:🔐\s*)?(?:Updated\s+)?Permissions\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'##\s*Permissions\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'Permissions\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'```json\s*(\{[^`]*"Version"[^`]*"Statement"[^`]*\})\s*```',  # Fallback: any JSON with Version and Statement
            ]
            
            for pattern in permissions_patterns:
                permissions_match = re.search(pattern, final_message, re.IGNORECASE | re.DOTALL)
                if permissions_match:
                    try:
                        policy_json = permissions_match.group(1).strip()
                        policy_json = re.sub(r'\}\s*[^}]*$', '}', policy_json, flags=re.DOTALL)
                        policy_json = re.sub(r'\}\s*##', '}', policy_json)
                        policy = json.loads(policy_json)
                        is_question = False
                        logging.debug("✅ Found and parsed Permissions Policy")
                        logging.debug(f"   Policy has {len(policy.get('Statement', []))} statements")
                        break
                    except json.JSONDecodeError as e:
                        logging.warning(f"❌ Permissions Policy JSON parse error with pattern: {str(e)[:100]}")
                        continue
            
            # Extract Trust Policy - Improved regex patterns with multiple fallbacks
            trust_patterns = [
                r'##\s*(?:🤝\s*)?(?:Updated\s+)?Trust\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'##\s*Trust\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'Trust\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'```json\s*(\{[^`]*"Principal"[^`]*"sts:AssumeRole"[^`]*\})\s*```',  # Fallback: JSON with Principal and AssumeRole
            ]
            
            for pattern in trust_patterns:
                trust_match = re.search(pattern, final_message, re.IGNORECASE | re.DOTALL)
                if trust_match:
                    try:
                        trust_json = trust_match.group(1).strip()
                        trust_json = re.sub(r'\}\s*[^}]*$', '}', trust_json, flags=re.DOTALL)
                        trust_json = re.sub(r'\}\s*##', '}', trust_json)
                        parsed_trust = json.loads(trust_json)
                        if "Principal" in str(parsed_trust) or any("Principal" in str(stmt) for stmt in parsed_trust.get('Statement', [])):
                            trust_policy = parsed_trust
                            logging.debug("✅ Found and parsed Trust Policy")
                            logging.debug(f"   Trust policy has {len(trust_policy.get('Statement', []))} statements")
                            break
                        else:
                            logging.warning("❌ Trust Policy JSON doesn't contain 'Principal' - likely permissions policy")
                            continue
                    except json.JSONDecodeError as e:
                        logging.warning(f"❌ Trust Policy JSON parse error with pattern: {str(e)[:100]}")
                        continue
            
            # Fallback extraction
            if not policy:
                all_json_blocks = re.findall(r'```json\s*([\s\S]*?)```', final_message, re.IGNORECASE)
                if len(all_json_blocks) >= 1:
                    try:
                        policy = json.loads(all_json_blocks[0].strip())
                        is_question = False
                        logging.debug("✅ Extracted Permissions Policy from first JSON block")
                    except json.JSONDecodeError:
                        logging.warning("❌ Failed to parse first JSON block")
                
                if len(all_json_blocks) >= 2 and not trust_policy:
                    try:
                        parsed_trust = json.loads(all_json_blocks[1].strip())
                        if "Principal" in str(parsed_trust) or any("Principal" in str(stmt) for stmt in parsed_trust.get('Statement', [])):
                            trust_policy = parsed_trust
                            logging.debug("✅ Extracted Trust Policy from second JSON block")
                        else:
                            logging.warning("❌ Second JSON block doesn't contain 'Principal' - likely not a trust policy, trying next block")
                            if len(all_json_blocks) >= 3:
                                try:
                                    parsed_trust = json.loads(all_json_blocks[2].strip())
                                    if "Principal" in str(parsed_trust) or any("Principal" in str(stmt) for stmt in parsed_trust.get('Statement', [])):
                                        trust_policy = parsed_trust
                                        logging.debug("✅ Extracted Trust Policy from third JSON block")
                                    else:
                                        logging.warning("❌ Third JSON block doesn't contain 'Principal' - fallback failed")
                                except json.JSONDecodeError:
                                    logging.warning("❌ Failed to parse third JSON block")
                    except json.JSONDecodeError:
                        logging.warning("❌ Failed to parse second JSON block")
            
            # Initialize score variables
            permissions_score = 0
            trust_score = 0
            overall_score = 0
            
            # Extract SEPARATE security scores - Try regex first, fallback to calculator
            perm_score_match = re.search(
                r'Permissions Policy Security Score[:\s]+(\d+)(?:/100)?',
                final_message,
                re.IGNORECASE
            )
            if perm_score_match:
                permissions_score = int(perm_score_match.group(1))
                logging.debug(f"✅ Permissions Score: {permissions_score}")
            else:
                logging.warning(f"⚠️ Could not extract permissions score from response")
            
            trust_score_match = re.search(
                r'Trust Policy Security Score[:\s]+(\d+)(?:/100)?',
                final_message,
                re.IGNORECASE
            )
            if trust_score_match:
                trust_score = int(trust_score_match.group(1))
                logging.debug(f"✅ Trust Score: {trust_score}")
            else:
                logging.warning(f"⚠️ Could not extract trust score from response")
            
            overall_score_match = re.search(
                r'Overall Security Score[:\s]+(\d+)(?:/100)?',
                final_message,
                re.IGNORECASE
            )
            if overall_score_match:
                overall_score = int(overall_score_match.group(1))
                logging.debug(f"✅ Overall Score: {overall_score}")
            else:
                # Calculate if not found
                if permissions_score > 0 and trust_score > 0:
                    overall_score = int((permissions_score * 0.7) + (trust_score * 0.3))
                    logging.debug(f"✅ Calculated Overall Score: {overall_score}")
            
            # FALLBACK: Use policy_scorer if Bedrock didn't provide scores
            if permissions_score == 0 or trust_score == 0:
                logging.warning(f"⚠️ Using fallback scorer (permissions={permissions_score}, trust={trust_score})")
                permissions_score, trust_score, overall_score = calculate_policy_scores(policy, trust_policy)
                logging.debug(f"✅ Calculated fallback scores: permissions={permissions_score}, trust={trust_score}, overall={overall_score}")

            # Extract SEPARATE security features for permissions policy
            perm_features_section = re.search(
                r'##?\s*(?:🔧\s*)?(?:Permissions Policy )?Security Features([\s\S]*?)(?=##|###|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if perm_features_section:
                features_text = perm_features_section.group(1)
                security_features["permissions"] = [
                    line.strip('- ').strip('• ').strip('✅ ').strip()
                    for line in features_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•') or line.strip().startswith('✅'))
                ]
                logging.debug(f"✅ Extracted {len(security_features['permissions'])} permissions features")
            
            # Extract SEPARATE security features for trust policy
            trust_features_section = re.search(
                r'##?\s*(?:🔧\s*)?(?:Trust Policy )?Security Features([\s\S]*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if trust_features_section:
                features_text = trust_features_section.group(1)
                security_features["trust"] = [
                    line.strip('- ').strip('• ').strip('✅ ').strip()
                    for line in features_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•') or line.strip().startswith('✅'))
                ]
                logging.debug(f"✅ Extracted {len(security_features['trust'])} trust features")
            
            # Extract SEPARATE security considerations for permissions policy
            perm_notes_section = re.search(
                r'##?\s*(?:⚠️\s*)?(?:Permissions Policy )?Considerations([\s\S]*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if perm_notes_section:
                notes_text = perm_notes_section.group(1)
                security_notes["permissions"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in notes_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
                logging.debug(f"✅ Extracted {len(security_notes['permissions'])} permissions considerations")
            
            # Extract SEPARATE security considerations for trust policy
            trust_notes_section = re.search(
                r'##?\s*(?:⚠️\s*)?(?:Trust Policy )?Considerations([\s\S]*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if trust_notes_section:
                notes_text = trust_notes_section.group(1)
                security_notes["trust"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in notes_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
                logging.debug(f"✅ Extracted {len(security_notes['trust'])} trust considerations")
            
            # Extract permissions policy explanation (new format)
            explanation_text = ""
            explanation_match = re.search(
                r'##\s*Permissions Policy Explanation([\s\S]*?)(?=##|$)',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            if explanation_match:
                explanation_text = explanation_match.group(1).strip()
                logging.debug(f"✅ Extracted permissions explanation ({len(explanation_text)} chars)")
            else:
                logging.warning("⚠️ No Permissions Policy Explanation section found")
                if policy:
                    explanation_text = generate_permissions_explanation(policy)
                    if explanation_text:
                        logging.debug("✅ Generated fallback permissions explanation")
            
            # Extract trust policy explanation
            trust_explanation_text = ""
            trust_explanation_match = re.search(
                r'##\s*Trust Policy Explanation([\s\S]*?)(?=##|$)',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            if trust_explanation_match:
                trust_explanation_text = trust_explanation_match.group(1).strip()
                logging.debug(f"✅ Extracted trust explanation ({len(trust_explanation_text)} chars)")
            else:
                logging.warning("⚠️ No Trust Policy Explanation section found")
                if trust_policy:
                    trust_explanation_text = generate_trust_explanation(trust_policy)
                    if trust_explanation_text:
                        logging.debug("✅ Generated fallback trust explanation")

            # Extract score breakdown (separate for permissions and trust)
            score_breakdown = extract_score_breakdown(final_message)
            logging.debug(f"✅ Score breakdown extraction complete")
            
            # FALLBACK: Use policy_scorer if Bedrock didn't provide breakdown
            # CRITICAL: Always generate score breakdown if we have policies but breakdown is empty (needed for refinement suggestions)
            has_permissions_breakdown = bool(score_breakdown.get("permissions", {}).get("positive") or score_breakdown.get("permissions", {}).get("improvements"))
            has_trust_breakdown = bool(score_breakdown.get("trust", {}).get("positive") or score_breakdown.get("trust", {}).get("improvements"))
            if (policy or trust_policy) and (not has_permissions_breakdown or not has_trust_breakdown):
                score_breakdown = generate_score_breakdown(policy, trust_policy, permissions_score, trust_score)
                logging.debug(f"✅ Generated/updated score breakdown (needed for refinement suggestions)")
            
            # FIX S3 STATEMENT SEPARATION - Do this BEFORE building response
            if policy:
                policy = fix_s3_statement_separation(policy)
            
            # VALIDATE COMPLIANCE - Check generated policy against selected framework (SKIP during initial generation for speed)
            # Compliance info is already in Claude's response, so we don't need to validate here
            # This validation can be done later via the "Validate Policy" feature
            compliance_status = {}
            # DISABLED: Skip expensive compliance validation during generation for speed
            # Compliance requirements are already included in Claude's response
            # Users can validate separately using the "Validate Policy" feature if needed
            if False and hasattr(request, 'compliance') and request.compliance and request.compliance != 'general' and policy:
                try:
                    logging.debug(f"🔍 Validating compliance against: {request.compliance}")
                    # Convert compliance format (e.g., 'pci-dss' -> 'pci_dss')
                    compliance_framework = request.compliance.replace('-', '_')
                    compliance_frameworks = [compliance_framework]
                    
                    # Validate the generated policy (quick mode for speed)
                    validation_result = validator_agent.validate_policy(
                        policy_json=json.dumps(policy),
                        compliance_frameworks=compliance_frameworks,
                        mode='quick'
                    )
                    
                    # Extract compliance status from validation result
                    if isinstance(validation_result, dict):
                        compliance_status = validation_result.get('compliance_status', {})
                        logging.debug(f"✅ Compliance validation complete: {len(compliance_status)} frameworks checked")
                    else:
                        logging.warning("⚠️ Compliance validation returned unexpected format")
                except Exception as e:
                    logging.error(f"❌ Compliance validation error: {str(e)}")
                    # Don't fail the request if compliance validation fails - continue without compliance
                    compliance_status = {}
            
            # Extract SEPARATE refinement suggestions
            refinement_suggestions = {"permissions": [], "trust": []}
            
            # Look for Permissions Policy Refinement Suggestions section (try multiple variations)
            perm_refinement_match = re.search(
                r'##\s*(?:Permissions Policy )?Refinement Suggestions([\s\S]*?)(?=##\s*(?:Trust|Permissions Policy|$))',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            # Fallback: Try alternative section names
            if not perm_refinement_match:
                perm_refinement_match = re.search(
                    r'##\s*(?:How You Could Make|Improvements|Suggestions)(?:.*?Permissions|.*?Policy)?([\s\S]*?)(?=##\s*(?:Trust|$))',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            
            if perm_refinement_match:
                perm_text = perm_refinement_match.group(1)
                logging.debug(f"📝 Found Permissions Refinement section, length: {len(perm_text)} chars")
                logging.debug(f"📝 First 200 chars: {perm_text[:200]}")
                # Extract bullet points
                perm_suggestions = re.findall(r'(?:^|\n)\s*[-•*]\s*(.+?)(?=\n|$)', perm_text, re.MULTILINE)
                refinement_suggestions["permissions"] = [s.strip() for s in perm_suggestions if s.strip() and len(s.strip()) > 10]
                logging.debug(f"✅ Extracted {len(refinement_suggestions['permissions'])} permissions refinement suggestions")
                if len(refinement_suggestions['permissions']) > 0:
                    logging.debug(f"   First suggestion: {refinement_suggestions['permissions'][0][:100]}")
            else:
                logging.warning("⚠️ No Permissions Policy Refinement Suggestions section found")
                # Log what sections ARE present
                sections = re.findall(r'##\s*([^\n]+)', final_message)
                logging.warning(f"   Sections found: {sections}")
                # FALLBACK: Generate refinement suggestions from score breakdown
                if policy and score_breakdown.get("permissions", {}).get("improvements"):
                    refinement_suggestions["permissions"] = score_breakdown["permissions"]["improvements"][:5]
                    logging.debug(f"✅ Generated {len(refinement_suggestions['permissions'])} fallback permissions refinement suggestions from score breakdown")
            
            # Look for Trust Policy Refinement Suggestions section (try multiple variations)
            trust_refinement_match = re.search(
                r'##\s*(?:Trust Policy )?Refinement Suggestions([\s\S]*?)(?=##|$)',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            # Fallback: Try alternative section names for trust policy
            if not trust_refinement_match:
                trust_refinement_match = re.search(
                    r'(?:For the trust policy|Trust policy)(?:.*?you could|.*?suggestions?)([^##]*?)(?=##|$)',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            
            if trust_refinement_match:
                trust_text = trust_refinement_match.group(1)
                logging.debug(f"📝 Found Trust Refinement section, length: {len(trust_text)} chars")
                logging.debug(f"📝 First 200 chars: {trust_text[:200]}")
                # Extract bullet points
                trust_suggestions = re.findall(r'(?:^|\n)\s*[-•*]\s*(.+?)(?=\n|$)', trust_text, re.MULTILINE)
                refinement_suggestions["trust"] = [s.strip() for s in trust_suggestions if s.strip() and len(s.strip()) > 10]
                logging.debug(f"✅ Extracted {len(refinement_suggestions['trust'])} trust refinement suggestions")
                if len(refinement_suggestions['trust']) > 0:
                    logging.debug(f"   First suggestion: {refinement_suggestions['trust'][0][:100]}")
            else:
                logging.warning("⚠️ No Trust Policy Refinement Suggestions section found")
                # FALLBACK: Generate refinement suggestions from score breakdown
                if trust_policy and score_breakdown.get("trust", {}).get("improvements"):
                    refinement_suggestions["trust"] = score_breakdown["trust"]["improvements"][:5]
                    logging.debug(f"✅ Generated {len(refinement_suggestions['trust'])} fallback trust refinement suggestions from score breakdown")
            
            # Build conversation history
            try:
                # Build conversation history - ensure all values are JSON-serializable
                conversation_history = []
                for msg in conversations.get(conversation_id, []):
                    # Ensure content is a string (not an object)
                    content = msg.get("content", "")
                    if not isinstance(content, str):
                        content = str(content) if content is not None else ""
                    if msg.get("role") == "assistant":
                        has_policy_json = bool(re.search(r'```json[\s\S]*?```', content))
                        if has_policy_json:
                            json_match = re.search(r'(```json[\s\S]*?```)', content)
                            if json_match:
                                content = json_match.group(1)
                        else:
                            content = re.sub(r'```json[\s\S]*?```', '', content)
                            content = re.sub(r'```[\s\S]*?```', '', content)
                            content = re.sub(r'\{[\s\S]*?"Version"[\s\S]*?\}', '', content)
                            policy_exp_start = re.search(r'##\s*(?:Permissions |Trust )?Policy', content, re.IGNORECASE)
                            if policy_exp_start:
                                content = content[:policy_exp_start.start()]
                        content = ' '.join(content.split()).strip()
                    
                    conversation_history.append({  
                        "role": msg.get("role", "user"),
                        "content": content,
                        "timestamp": msg.get("timestamp", "")
                    })
                logging.debug(f"✅ Built conversation history ({len(conversation_history)} messages)")
            except Exception as history_error:
                logging.error(f"❌ Error building conversation history: {history_error}")
                conversation_history = []
            
            if is_question:
                explanation = ""
                trust_explanation = ""
            
            # CRITICAL: Ensure final_message is never empty - this is the most important check
            if not final_message or (isinstance(final_message, str) and final_message.strip() == ''):
                logging.error("❌ CRITICAL ERROR: final_message is empty before building response!")
                logging.error(f"   This should never happen. conversation_id: {conversation_id}")
                logging.error(f"   This means the agent call failed or returned empty response")
                final_message = "An error occurred while generating the policy. The AI agent did not return a response. Please try again."
            
            # Ensure explanation_text is never empty
            if not explanation_text or (isinstance(explanation_text, str) and explanation_text.strip() == ''):
                if previous_response and previous_response.get("explanation"):
                    explanation_text = previous_response["explanation"]
                else:
                    explanation_text = final_message
            
            # Validate all required fields exist
            if not conversation_id:
                logging.error("❌ conversation_id is missing!")
                conversation_id = str(uuid.uuid4())
            
            # Log that we're about to build the response
            logging.debug(f"🔨 Building response object...")
            logging.debug(f"   ├─ conversation_id: {conversation_id}")
            logging.debug(f"   ├─ final_message length: {len(final_message) if final_message else 0}")
            logging.debug(f"   ├─ has policy: {policy is not None}")
            logging.debug(f"   ├─ has trust_policy: {trust_policy is not None}")
            
            # CRITICAL: Ensure final_message is never empty
            if not final_message or (isinstance(final_message, str) and final_message.strip() == ''):
                logging.warning("⚠️ final_message is empty, using explanation or fallback")
                final_message = explanation_text or trust_explanation_text or "Policy generation completed. Please check the policies below."
            
            # Generate compliance_features with links if compliance framework is selected
            compliance_features = []
            if hasattr(request, 'compliance') and request.compliance and request.compliance != 'general':
                compliance_features = generate_compliance_features(request.compliance)
                logging.debug(f"✅ Generated {len(compliance_features)} compliance features for {request.compliance}")
            
            # Build response object
            response = {
                "conversation_id": conversation_id,
                "final_answer": final_message,
                "message_count": len(conversations.get(conversation_id, [])),
                "policy": policy,
                "trust_policy": trust_policy,
                "explanation": explanation_text or final_message or "Policy generation completed.",
                "trust_explanation": trust_explanation_text or "",
                "permissions_score": permissions_score or 0,
                "trust_score": trust_score or 0,
                "overall_score": overall_score or 0,
                "security_notes": security_notes or {"permissions": [], "trust": []},
                "security_features": security_features or {"permissions": [], "trust": []},
                "score_breakdown": score_breakdown or {},
                "is_question": is_question if isinstance(is_question, bool) else (not bool(policy or trust_policy)),  # Only mark as question if no policies AND it looks like a question
                "conversation_history": conversation_history or [],
                "refinement_suggestions": refinement_suggestions or {"permissions": [], "trust": []},
                "compliance_status": compliance_status or {},
                "compliance_features": compliance_features
            }
            logging.info(
                "generate response ready: conversation_id=%s permissions_score=%s trust_score=%s overall_score=%s",
                conversation_id,
                permissions_score,
                trust_score,
                overall_score,
            )
            
            # Update conversation cache with latest policies and data
            if policy or trust_policy:
                conversation_cache[conversation_id] = {
                    "policy": policy,
                    "trust_policy": trust_policy,
                    "explanation": explanation_text or "",
                    "trust_explanation": trust_explanation_text or "",
                    "permissions_score": permissions_score or 0,
                    "trust_score": trust_score or 0,
                    "overall_score": overall_score or 0,
                    "score_breakdown": score_breakdown or {"permissions": {"positive": [], "improvements": []}, "trust": {"positive": [], "improvements": []}},
                    "security_features": security_features or {"permissions": [], "trust": []},
                    "security_notes": security_notes or {"permissions": [], "trust": []},
                    "refinement_suggestions": refinement_suggestions or {"permissions": [], "trust": []},
                    "compliance_status": compliance_status or {},
                    "compliance_features": compliance_features if compliance_features else [],
                    "selected_compliance": (request.compliance if hasattr(request, "compliance") and request.compliance else "general"),
                    "conversation_history": conversation_history or [],
                    "last_updated": str(uuid.uuid4())
                }
                logging.debug("✅ Updated conversation cache with latest policies")
            
            # Validate response before returning - ensure it's never None or missing critical fields
            if not response.get("final_answer"):
                logging.error("❌ Response missing final_answer, adding fallback")
                response["final_answer"] = "Policy generation completed."
            
            if not response.get("conversation_id"):
                logging.error("❌ Response missing conversation_id, adding fallback")
                response["conversation_id"] = str(uuid.uuid4())
            
            logging.debug(f"📤 RESPONSE SUMMARY:")
            logging.debug(f"   ├─ is_question: {is_question}")
            logging.debug(f"   ├─ has_policy: {policy is not None}")
            logging.debug(f"   ├─ has_trust_policy: {trust_policy is not None}")
            logging.debug(f"   ├─ permissions_score: {permissions_score}")
            logging.debug(f"   ├─ trust_score: {trust_score}")
            logging.debug(f"   ├─ overall_score: {overall_score}")
            logging.debug(f"   ├─ score_breakdown[permissions][positive]: {len(score_breakdown['permissions']['positive'])}")
            logging.debug(f"   ├─ score_breakdown[permissions][improvements]: {len(score_breakdown['permissions']['improvements'])}")
            logging.debug(f"   ├─ score_breakdown[trust][positive]: {len(score_breakdown['trust']['positive'])}")
            logging.debug(f"   ├─ score_breakdown[trust][improvements]: {len(score_breakdown['trust']['improvements'])}")
            logging.debug(f"   ├─ permissions_features: {len(security_features['permissions'])} items")
            logging.debug(f"   ├─ trust_features: {len(security_features['trust'])} items")
            logging.debug(f"   ├─ permissions_suggestions: {len(refinement_suggestions['permissions'])} items")
            logging.debug(f"   ├─ trust_suggestions: {len(refinement_suggestions['trust'])} items")
            logging.debug(f"   └─ conversation_history: {len(conversation_history)} messages")
            
            # Ensure response is valid before returning - NEVER return None
            if not response or not isinstance(response, dict):
                logging.error("❌ Response is invalid or None, creating fallback")
                response = {
                    "conversation_id": conversation_id or str(uuid.uuid4()),
                    "final_answer": "An error occurred while generating the policy. Please try again.",
                    "message_count": len(conversations.get(conversation_id or '', [])),
                    "policy": None,
                    "trust_policy": None,
                    "explanation": "An error occurred while generating the policy.",
                    "trust_explanation": "",
                    "permissions_score": 0,
                    "trust_score": 0,
                    "overall_score": 0,
                    "security_notes": {"permissions": [], "trust": []},
                    "score_breakdown": {},
                    "security_features": {"permissions": [], "trust": []},
                    "refinement_suggestions": {"permissions": [], "trust": []},
                    "is_question": False,
                    "conversation_history": conversations.get(conversation_id or '', [])[-10:],
                    "compliance_status": {},
                    "error": "Response validation failed"
                }
            
            # CRITICAL: Ensure response is never None before returning
            if response is None:
                logging.error("❌ CRITICAL: response is None before returning!")
                response = {
                    "conversation_id": conversation_id or str(uuid.uuid4()),
                    "final_answer": "An error occurred while generating the policy. Please try again.",
                    "message_count": len(conversations.get(conversation_id or '', [])),
                    "policy": None,
                    "trust_policy": None,
                    "explanation": "An error occurred while generating the policy.",
                    "trust_explanation": "",
                    "permissions_score": 0,
                    "trust_score": 0,
                    "overall_score": 0,
                    "security_notes": {"permissions": [], "trust": []},
                    "score_breakdown": {},
                    "security_features": {"permissions": [], "trust": []},
                    "refinement_suggestions": {"permissions": [], "trust": []},
                    "is_question": False,
                    "conversation_history": conversations.get(conversation_id or '', [])[-10:],
                    "compliance_status": {},
                    "error": "Response was None"
                }
            
            # FINAL SAFETY CHECK: Ensure response is never None
            if response is None:
                logging.error("❌ CRITICAL: response is None at final return - using default error response")
                response = default_error_response
            
            # Ensure response is a dict
            if not isinstance(response, dict):
                logging.error(f"❌ CRITICAL: response is not a dict (type: {type(response)}) - using default error response")
                response = default_error_response
            
            # Ensure response has all required fields
            if not response.get("conversation_id"):
                response["conversation_id"] = conversation_id or str(uuid.uuid4())
            if not response.get("final_answer"):
                response["final_answer"] = final_message or "Policy generation completed."
            
            logging.debug(f"✅ Returning response with conversation_id: {response.get('conversation_id')}")
            logging.debug(f"✅ Response has final_answer: {bool(response.get('final_answer'))}")
            logging.debug(f"✅ Response type: {type(response)}")
            logging.debug(f"✅ Response keys: {list(response.keys())}")
            
            # CRITICAL: Use JSONResponse to ensure proper serialization (prevents null responses)
            # Ensure response dict is not None before passing to JSONResponse
            if response is None:
                logging.error("❌ CRITICAL: response is None - using default_error_response")
                response = default_error_response
            
            logging.debug(f"🔍 Final response check before JSONResponse:")
            logging.debug(f"   ├─ response type: {type(response)}")
            logging.debug(f"   ├─ response is None: {response is None}")
            logging.debug(f"   ├─ response is dict: {isinstance(response, dict)}")
            logging.debug(f"   ├─ conversation_id: {response.get('conversation_id') if isinstance(response, dict) else 'N/A'}")
            logging.debug(f"   ├─ final_answer: {response.get('final_answer')[:100] if isinstance(response, dict) and response.get('final_answer') else 'N/A'}")
            
            # FINAL SAFETY: Ensure response is a valid dict with required fields
            if not isinstance(response, dict):
                logging.error(f"❌ CRITICAL: response is not a dict (type: {type(response)}) - using default_error_response")
                response = default_error_response.copy()
            
            if not response.get("conversation_id"):
                logging.error("❌ CRITICAL: response missing conversation_id - adding fallback")
                response["conversation_id"] = conversation_id or str(uuid.uuid4())
            
            if not response.get("final_answer"):
                logging.error("❌ CRITICAL: response missing final_answer - adding fallback")
                response["final_answer"] = final_message or "Policy generation completed."
            
            # Log the final response being returned
            logging.info(f"📤 FINAL RESPONSE BEING RETURNED:")
            logging.info(f"   ├─ conversation_id: {response.get('conversation_id')}")
            logging.info(f"   ├─ final_answer length: {len(response.get('final_answer', ''))}")
            logging.info(f"   ├─ final_answer preview: {response.get('final_answer', '')[:300] if response.get('final_answer') else 'EMPTY'}")
            logging.info(f"   ├─ has policy: {response.get('policy') is not None}")
            logging.info(f"   ├─ has trust_policy: {response.get('trust_policy') is not None}")
            
            # Ensure we never return None - use default_error_response if somehow response is still None
            if response is None:
                logging.error("❌ CRITICAL: response is STILL None after all checks - using default_error_response")
                response = default_error_response.copy()
            
            try:
                # CRITICAL: Ensure all values in response are JSON-serializable
                # Convert any non-serializable objects to strings
                serializable_response = {}
                for key, value in response.items():
                    try:
                        # Special handling for conversation_history - ensure it's a list of dicts with string values
                        if key == "conversation_history" and isinstance(value, list):
                            serialized_history = []
                            for msg in value:
                                if isinstance(msg, dict):
                                    serialized_msg = {}
                                    for msg_key, msg_value in msg.items():
                                        if not isinstance(msg_value, (str, int, float, bool, type(None))):
                                            serialized_msg[msg_key] = str(msg_value) if msg_value is not None else None
                                        else:
                                            serialized_msg[msg_key] = msg_value
                                    serialized_history.append(serialized_msg)
                                else:
                                    serialized_history.append({"role": "user", "content": str(msg)})
                            serializable_response[key] = serialized_history
                        else:
                            # Try to serialize the value to ensure it's JSON-compatible
                            json.dumps(value)
                            serializable_response[key] = value
                    except (TypeError, ValueError) as e:
                        # If not serializable, convert to string
                        logging.warning(f"⚠️ Converting non-serializable value for key '{key}' to string: {e}")
                        serializable_response[key] = str(value) if value is not None else None
                
                # Double-check: try to serialize the entire response
                try:
                    test_serialization = json.dumps(serializable_response)
                    logging.debug(f"✅ Test serialization successful: {len(test_serialization)} bytes")
                except Exception as test_error:
                    logging.error(f"❌ Test serialization failed: {test_error}")
                    # Remove problematic keys and try again
                    for key in list(serializable_response.keys()):
                        try:
                            json.dumps(serializable_response[key])
                        except:
                            logging.warning(f"⚠️ Removing problematic key '{key}' from response")
                            del serializable_response[key]
                
                # Final serialization check
                try:
                    serialized_json = json.dumps(serializable_response)
                    logging.info(f"📦 Final serialized response size: {len(serialized_json)} bytes")
                    logging.info(f"📦 Response preview (first 500 chars): {serialized_json[:500]}")
                    logging.info(f"📦 Response keys: {list(serializable_response.keys())}")
                except Exception as final_error:
                    logging.error(f"❌ CRITICAL: Final serialization failed: {final_error}")
                    # Return minimal error response
                    return {
                        "conversation_id": response.get("conversation_id", str(uuid.uuid4())),
                        "final_answer": "An error occurred while processing your request. Please try again.",
                        "error": f"Serialization error: {str(final_error)}",
                        "message_count": response.get("message_count", 1),
                        "policy": None,
                        "trust_policy": None
                    }
                
                # Return dict directly - FastAPI will automatically serialize it to JSON
                # This is more reliable than JSONResponse for ensuring the body is sent
                logging.info(f"✅ Returning serializable response dict")
                logging.info(f"   Final check - response type: {type(serializable_response)}")
                logging.info(f"   Final check - response is dict: {isinstance(serializable_response, dict)}")
                logging.info(f"   Final check - response keys count: {len(serializable_response.keys())}")
                
                # CRITICAL: Wrap in try-except to catch any last-minute errors
                try:
                    # One final serialization test before returning
                    final_test = json.dumps(serializable_response)
                    logging.info(f"✅ Final serialization test passed: {len(final_test)} bytes")
                    
                    # CRITICAL: Try returning as plain dict first (like test endpoint but simpler)
                    # FastAPI will automatically serialize dicts to JSON
                    logging.info(f"✅ About to return response")
                    logging.info(f"   Response has {len(serializable_response.keys())} keys")
                    logging.info(f"   final_answer present: {bool(serializable_response.get('final_answer'))}")
                    logging.info(f"   final_answer length: {len(serializable_response.get('final_answer', ''))}")
                    logging.info(f"   Returning as dict (FastAPI will serialize automatically)")
                    
                    # Return as dict - FastAPI handles serialization automatically
                    # This is simpler and more reliable than JSONResponse
                    return serializable_response
                except Exception as final_return_error:
                    logging.error(f"❌ CRITICAL: Error during final return: {final_return_error}")
                    import traceback
                    logging.error(f"   Traceback: {traceback.format_exc()}")
                    # Return minimal guaranteed response using JSONResponse
                    minimal_response = {
                        "conversation_id": serializable_response.get("conversation_id", str(uuid.uuid4())),
                        "final_answer": serializable_response.get("final_answer", "Response generated successfully.")[:500] if serializable_response.get("final_answer") else "Response generated successfully.",
                        "message_count": serializable_response.get("message_count", 1),
                        "policy": serializable_response.get("policy"),
                        "trust_policy": serializable_response.get("trust_policy")
                    }
                    # Return as dict, not JSONResponse
                    return minimal_response
            except Exception as json_error:
                logging.error(f"❌ CRITICAL: Failed to serialize response: {json_error}")
                logging.error(f"   Exception type: {type(json_error).__name__}")
                logging.error(f"   Exception details: {str(json_error)}")
                logging.error(f"   Response keys: {list(response.keys()) if isinstance(response, dict) else 'N/A'}")
                import traceback
                logging.error(f"   Traceback: {traceback.format_exc()}")
                
                # Return minimal, guaranteed-serializable error response
                error_fallback = {
                    "conversation_id": response.get("conversation_id", str(uuid.uuid4())) if isinstance(response, dict) else str(uuid.uuid4()),
                    "final_answer": f"An error occurred while processing your request: {str(json_error)[:200]}. Please try again.",
                    "error": f"Serialization error: {str(json_error)[:200]}",
                    "message_count": response.get("message_count", 1) if isinstance(response, dict) else 1,
                    "policy": None,
                    "trust_policy": None,
                    "permissions_score": 0,
                    "trust_score": 0,
                    "overall_score": 0,
                    "explanation": "",
                    "trust_explanation": "",
                    "security_notes": {"permissions": [], "trust": []},
                    "score_breakdown": {},
                    "security_features": {"permissions": [], "trust": []},
                    "refinement_suggestions": {"permissions": [], "trust": []},
                    "is_question": False,
                    "conversation_history": [],
                    "compliance_status": {}
                }
                
                # Ensure even the error response is serializable
                try:
                    json.dumps(error_fallback)
                    logging.error(f"❌ Returning error fallback response (guaranteed serializable)")
                    return error_fallback
                except Exception as fallback_error:
                    logging.error(f"❌ CRITICAL: Even error fallback failed to serialize: {fallback_error}")
                    # Last resort: return absolute minimal response
                    return {
                        "conversation_id": str(uuid.uuid4()),
                        "final_answer": "An error occurred. Please try again.",
                        "error": "Serialization error"
                    }
            
            # CRITICAL: Final safety check - if we somehow reach here without returning, return default
            # This should NEVER happen, but if it does, we'll return a safe response
            if 'response' not in locals() or response is None:
                logging.error("❌ CRITICAL: Reached end of _generate_internal without response!")
                logging.error(f"   response defined: {'response' in locals()}")
                logging.error(f"   response is None: {response is None if 'response' in locals() else 'N/A'}")
                return default_error_response.copy()
            
            # If we have a response but somehow didn't return it, return it now
            logging.warning("⚠️ Reached end of try block - returning response dict directly")
            logging.info(f"   Response type: {type(response)}")
            logging.info(f"   Response has final_answer: {bool(response.get('final_answer'))}")
            return response
            
    except asyncio.TimeoutError:
        logging.error("⏱️ Request timed out after 45 seconds")
        error_message = "Request timed out after 45 seconds. Please try again with a simpler request."
        error_conversation_id = conversation_id or str(uuid.uuid4())
        error_response = {
            "conversation_id": error_conversation_id,
            "final_answer": error_message,
            "message_count": len(conversations.get(error_conversation_id, [])),
            "policy": None,
            "trust_policy": None,
            "explanation": error_message,
            "trust_explanation": "",
            "permissions_score": 0,
            "trust_score": 0,
            "overall_score": 0,
            "security_notes": {"permissions": [], "trust": []},
            "score_breakdown": {},
            "security_features": {"permissions": [], "trust": []},
            "refinement_suggestions": {"permissions": [], "trust": []},
            "is_question": False,
            "conversation_history": conversations.get(error_conversation_id, [])[-10:],
            "compliance_status": {},
            "error": error_message
        }
        logging.info(f"✅ Returning timeout error response with conversation_id: {error_response.get('conversation_id')}")
        # Return as dict, not JSONResponse
        return error_response
    except Exception as e:
        logging.exception("❌ Error in generate endpoint")
        error_message = f"Error generating policy: {str(e)}"
        error_conversation_id = conversation_id or str(uuid.uuid4())
        logging.error(f"   Error conversation_id: {error_conversation_id}")
        logging.error(f"   Error type: {type(e).__name__}")
        logging.error(f"   Error message: {str(e)}")
        
        # Ensure conversation_history is serializable
        try:
            error_history = conversations.get(error_conversation_id, [])[-10:]
            # Clean history to ensure it's JSON-serializable
            clean_history = []
            for msg in error_history:
                if isinstance(msg, dict):
                    clean_msg = {
                        "role": str(msg.get("role", "user")),
                        "content": str(msg.get("content", "")) if msg.get("content") else "",
                        "timestamp": str(msg.get("timestamp", "")) if msg.get("timestamp") else ""
                    }
                    clean_history.append(clean_msg)
        except:
            clean_history = []
        
        error_response = {
            "conversation_id": str(error_conversation_id),
            "final_answer": str(error_message)[:500],
            "message_count": len(conversations.get(error_conversation_id, [])),
            "policy": None,
            "trust_policy": None,
            "explanation": str(error_message)[:500],
            "trust_explanation": "",
            "permissions_score": 0,
            "trust_score": 0,
            "overall_score": 0,
            "security_notes": {"permissions": [], "trust": []},
            "score_breakdown": {},
            "security_features": {"permissions": [], "trust": []},
            "refinement_suggestions": {"permissions": [], "trust": []},
            "is_question": False,
            "conversation_history": clean_history,
            "compliance_status": {},
            "error": str(e)[:200]
        }
        
        # Ensure error response is serializable
        try:
            json.dumps(error_response)
            logging.info(f"✅ Returning exception error response with conversation_id: {error_response.get('conversation_id')}")
            logging.info(f"✅ Error response type: {type(error_response)}")
            logging.info(f"✅ Error response has final_answer: {bool(error_response.get('final_answer'))}")
            # Return as dict, not JSONResponse
            return error_response
        except Exception as serialization_error:
            logging.error(f"❌ CRITICAL: Error response itself failed to serialize: {serialization_error}")
            # Return absolute minimal response as dict
            minimal = {
                "conversation_id": str(error_conversation_id),
                "final_answer": "An error occurred. Please try again.",
                "error": "Serialization error"
            }
            return minimal

# Add FastAPI exception handler to catch any unhandled exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch any unhandled exceptions and return a valid JSON response"""
    try:
        logging.exception(f"❌ GLOBAL EXCEPTION HANDLER: Unhandled exception in {request.url}")
        logging.exception(f"   Exception type: {type(exc).__name__}")
        logging.exception(f"   Exception message: {str(exc)}")
        
        error_response = {
            "conversation_id": str(uuid.uuid4()),
            "final_answer": f"An unexpected error occurred: {str(exc)}",
            "message_count": 0,
            "policy": None,
            "trust_policy": None,
            "explanation": f"An unexpected error occurred: {str(exc)}",
            "trust_explanation": "",
            "permissions_score": 0,
            "trust_score": 0,
            "overall_score": 0,
            "security_notes": {"permissions": [], "trust": []},
            "score_breakdown": {},
            "security_features": {"permissions": [], "trust": []},
            "refinement_suggestions": {"permissions": [], "trust": []},
            "is_question": False,
            "conversation_history": [],
            "compliance_status": {},
            "error": str(exc)
        }
        
        logging.debug(f"✅ Global exception handler returning error response")
        logging.debug(f"   Error response type: {type(error_response)}")
        logging.debug(f"   Error response keys: {list(error_response.keys())}")
        return JSONResponse(status_code=500, content=error_response)
    except Exception as handler_error:
        # If even the exception handler fails, return a minimal response
        logging.error(f"❌ CRITICAL: Exception handler itself failed: {handler_error}")
        return JSONResponse(
            status_code=500,
            content={
                "conversation_id": str(uuid.uuid4()),
                "final_answer": "An internal server error occurred. Please try again.",
                "message_count": 0,
                "policy": None,
                "trust_policy": None,
                "explanation": "An internal server error occurred.",
                "trust_explanation": "",
                "permissions_score": 0,
                "trust_score": 0,
                "overall_score": 0,
                "security_notes": {"permissions": [], "trust": []},
                "score_breakdown": {},
                "security_features": {"permissions": [], "trust": []},
                "refinement_suggestions": {"permissions": [], "trust": []},
                "is_question": False,
                "conversation_history": [],
                "compliance_status": {},
                "error": "Internal server error"
            }
        )


# ============================================
# VALIDATION (MCP-ENABLED)
# ============================================

@app.post("/validate")
async def validate_policy(request: ValidationRequest):
    """Validate an IAM policy for security issues and compliance"""
    logging.info(f"🚀 /validate endpoint called")
    logging.info(f"   Mode: {request.mode}")
    logging.info(f"   User credentials provided: {request.aws_credentials is not None}")
    
    # Import validator credentials helpers
    from features.validation.validator_agent import set_user_credentials as set_validator_credentials, clear_user_credentials as clear_validator_credentials
    
    # Set user credentials in context (thread-safe)
    if request.aws_credentials:
        creds_dict = {
            'access_key_id': request.aws_credentials.access_key_id,
            'secret_access_key': request.aws_credentials.secret_access_key,
            'region': request.aws_credentials.region
        }
        # Set for both Bedrock (Strands Agent) and IAM client
        set_user_credentials(creds_dict)  # Bedrock
        set_validator_credentials(creds_dict)  # IAM client
        logging.info(f"✅ User credentials set for region: {request.aws_credentials.region}")
    
    try:
        if not request.policy_json and not request.role_arn:
            return {
                "error": "Either policy_json or role_arn must be provided",
                "success": False
            }
        
        logging.debug(f"🔍 Starting validation in {request.mode} mode")
        
        async with asyncio.timeout(120):
            result = validator_agent.validate_policy(
                policy_json=request.policy_json,
                role_arn=request.role_arn,
                compliance_frameworks=request.compliance_frameworks,
                mode=request.mode
            )
            
            if not result.get("success"):
                return {
                    "error": result.get("error", "Validation failed"),
                    "success": False
                }
            
            validation_data = result.get("validation", {})
            
            # DEBUG: Log the structure of validation_data
            logging.info(f"🔍 RAW validation_data type: {type(validation_data)}")
            logging.info(f"🔍 RAW validation_data keys: {list(validation_data.keys()) if isinstance(validation_data, dict) else 'NOT A DICT'}")
            logging.info(f"🔍 RAW validation_data.risk_score: {validation_data.get('risk_score') if isinstance(validation_data, dict) else 'N/A'}")
            if isinstance(validation_data, dict):
                findings_raw = validation_data.get('findings', [])
                logging.info(f"🔍 RAW validation_data.findings type: {type(findings_raw)}, length: {len(findings_raw) if isinstance(findings_raw, list) else 'N/A'}")
                compliance_raw = validation_data.get('compliance_status', {})
                logging.info(f"🔍 RAW validation_data.compliance_status type: {type(compliance_raw)}, keys: {list(compliance_raw.keys()) if isinstance(compliance_raw, dict) else 'N/A'}")
                quick_wins_raw = validation_data.get('quick_wins', [])
                logging.info(f"🔍 RAW validation_data.quick_wins type: {type(quick_wins_raw)}, length: {len(quick_wins_raw) if isinstance(quick_wins_raw, list) else 'N/A'}")
                recs_raw = validation_data.get('recommendations', [])
                logging.info(f"🔍 RAW validation_data.recommendations type: {type(recs_raw)}, length: {len(recs_raw) if isinstance(recs_raw, list) else 'N/A'}")
            else:
                logging.error(f"❌ validation_data is NOT a dict! It's: {type(validation_data)}")
                logging.error(f"   Full validation_data: {str(validation_data)[:500]}")
            
            # Extract findings - ensure it's a list
            findings = validation_data.get("findings", [])
            if not isinstance(findings, list):
                findings = []
            logging.info(f"📊 Extracted {len(findings)} findings from validation_data")
            
            # Extract risk_score - use the one from validation_data (agent's response)
            # CRITICAL: Use the actual risk_score from agent, don't override it
            risk_score = validation_data.get("risk_score")
            
            # Only calculate if risk_score is None or invalid (0 or negative)
            if risk_score is None or risk_score <= 0:
                # Calculate based on findings if not provided
                if len(findings) == 0:
                    risk_score = 5  # Excellent security - no findings
                    logging.info(f"📊 Calculated risk_score: {risk_score}/100 (no findings)")
                else:
                    # Calculate based on severity
                    critical_count = sum(1 for f in findings if f.get('severity') == 'Critical')
                    high_count = sum(1 for f in findings if f.get('severity') == 'High')
                    medium_count = sum(1 for f in findings if f.get('severity') == 'Medium')
                    low_count = sum(1 for f in findings if f.get('severity') == 'Low')
                    
                    risk_score = min(100, 
                        critical_count * 40 + 
                        high_count * 20 + 
                        medium_count * 10 + 
                        low_count * 5
                    )
                    logging.info(f"📊 Calculated risk_score: {risk_score}/100 based on findings (C:{critical_count}, H:{high_count}, M:{medium_count}, L:{low_count})")
            else:
                # Use the agent's risk_score (this is the correct value)
                logging.info(f"📊 Using risk_score from validation_data: {risk_score}/100")
            
            # Extract compliance_status - ensure it's a dict
            compliance_status = validation_data.get("compliance_status", {})
            if not isinstance(compliance_status, dict):
                compliance_status = {}
            logging.info(f"📊 Extracted compliance_status with {len(compliance_status)} frameworks: {list(compliance_status.keys())}")
            
            # CRITICAL: Agent returns "recommendations" not "security_improvements"
            recommendations = validation_data.get("recommendations", []) or validation_data.get("security_improvements", [])
            if not isinstance(recommendations, list):
                recommendations = []
            logging.info(f"📊 Extracted {len(recommendations)} recommendations")
            
            quick_wins = validation_data.get("quick_wins", [])
            if not isinstance(quick_wins, list):
                quick_wins = []
            logging.info(f"📊 Extracted {len(quick_wins)} quick_wins")
            
            audit_summary = validation_data.get("audit_summary")
            top_risks = validation_data.get("top_risks")
            
            logging.info(f"✅ Validation completed:")
            logging.info(f"   ├─ Risk Score: {risk_score}/100")
            logging.info(f"   ├─ Findings: {len(findings)}")
            logging.info(f"   ├─ Compliance Status Keys: {list(compliance_status.keys())}")
            logging.info(f"   ├─ Recommendations: {len(recommendations)}")
            logging.info(f"   ├─ Quick Wins: {len(quick_wins)}")
            
            # Extract role details if validating via ARN - CRITICAL: Check multiple locations
            role_details = None
            if request.role_arn:
                # Priority 1: Check top-level result (from class variable) - MOST RELIABLE
                result_role_details = result.get("role_details")
                if result_role_details:
                    # Check if it has actual policy data (not just empty lists)
                    attached_count = len(result_role_details.get("attached_policies", []))
                    inline_count = len(result_role_details.get("inline_policies", []))
                    if attached_count > 0 or inline_count > 0 or result_role_details.get("trust_policy"):
                        role_details = result_role_details
                        logging.info(f"✅ Found role_details at top level: {attached_count} attached, {inline_count} inline")
                    else:
                        logging.debug(f"⚠️ Top-level role_details exists but has no policies: {result_role_details}")
                
                # Priority 2: Check validation_data (from agent JSON response)
                if not role_details and validation_data.get("role_details"):
                    validation_data_role = validation_data.get("role_details", {})
                    attached_count = len(validation_data_role.get("attached_policies", []))
                    inline_count = len(validation_data_role.get("inline_policies", []))
                    if attached_count > 0 or inline_count > 0 or validation_data_role.get("trust_policy"):
                        role_details = validation_data_role
                        logging.info(f"✅ Found role_details in validation_data: {attached_count} attached, {inline_count} inline")
                    else:
                        logging.debug(f"⚠️ validation_data role_details exists but has no policies: {validation_data_role}")
                
                # Priority 3: Fallback - build basic role_details (only if we truly have nothing)
                if not role_details:
                    role_name = request.role_arn.split(':role/')[-1].split('/')[-1]
                    role_details = {
                        "role_arn": request.role_arn,
                        "role_name": role_name,
                        "attached_policies": [],
                        "inline_policies": []
                    }
                    logging.warning(f"⚠️ Using fallback role_details for {role_name} - no attached policies found in result or validation_data")
                    logging.warning(f"   Top-level result.role_details: {result.get('role_details')}")
                    logging.warning(f"   validation_data.role_details: {validation_data.get('role_details')}")
            
            # Build response dict
            response_dict = {
                "success": True,
                "risk_score": risk_score,
                "findings": findings,
                "compliance_status": compliance_status,
                "recommendations": recommendations,
                "quick_wins": quick_wins,
                "audit_summary": audit_summary,
                "top_risks": top_risks,
                "role_details": role_details,
                "raw_response": result.get("raw_response", ""),
                "mcp_enabled": result.get("mcp_enabled", False)
            }
            
            # CRITICAL: Also include validation object for frontend fallback
            # Frontend checks data.validation.* as fallback
            response_dict["validation"] = {
                "risk_score": risk_score,
                "findings": findings,
                "compliance_status": compliance_status,
                "recommendations": recommendations,
                "quick_wins": quick_wins,
                "audit_summary": audit_summary,
                "top_risks": top_risks,
                "role_details": role_details
            }
            
            # Log final response structure for debugging
            logging.info(f"📤 FINAL RESPONSE STRUCTURE:")
            logging.info(f"   ├─ risk_score: {response_dict.get('risk_score')}")
            logging.info(f"   ├─ findings count: {len(response_dict.get('findings', []))}")
            logging.info(f"   ├─ compliance_status keys: {list(response_dict.get('compliance_status', {}).keys())}")
            logging.info(f"   ├─ recommendations count: {len(response_dict.get('recommendations', []))}")
            logging.info(f"   ├─ quick_wins count: {len(response_dict.get('quick_wins', []))}")
            role_details = response_dict.get('role_details') or {}
            attached_policies = role_details.get('attached_policies', []) if isinstance(role_details, dict) else []
            logging.info(f"   ├─ role_details attached: {len(attached_policies)}")
            logging.info(f"   └─ validation object present: {bool(response_dict.get('validation'))}")
            
            return response_dict
            
    except asyncio.TimeoutError:
        logging.error("⏱️ Validation timed out after 120 seconds")
        return {
            "error": "Validation request timed out. Please try again.",
            "success": False
        }
    except Exception as e:
        logging.exception("❌ Error in validate endpoint")
        return {
            "error": str(e),
            "success": False
        }
    finally:
        # SECURITY: Always clear user credentials after request
        if request.aws_credentials:
            from features.validation.validator_agent import clear_user_credentials as clear_validator_credentials
            clear_user_credentials()  # Bedrock
            clear_validator_credentials()  # IAM client
            logging.info("🧹 User credentials cleared from context")


# ============================================
# AUTONOMOUS AUDIT
# ============================================

@app.post("/audit")
async def autonomous_audit(request: AuditRequest):
    """Perform full autonomous IAM audit of entire AWS account"""
    logging.info(f"🚀 /audit endpoint called")
    logging.info(f"   User credentials provided: {request.aws_credentials is not None}")
    
    # Import validator credentials helpers
    from features.validation.validator_agent import set_user_credentials as set_validator_credentials, clear_user_credentials as clear_validator_credentials
    
    # Set user credentials in context (thread-safe)
    if request.aws_credentials:
        creds_dict = {
            'access_key_id': request.aws_credentials.access_key_id,
            'secret_access_key': request.aws_credentials.secret_access_key,
            'region': request.aws_credentials.region
        }
        # Set for both Bedrock (Strands Agent) and IAM client
        set_user_credentials(creds_dict)  # Bedrock
        set_validator_credentials(creds_dict)  # IAM client
        logging.info(f"✅ User credentials set for region: {request.aws_credentials.region}")
    
    try:
        logging.debug("🤖 AUTONOMOUS AUDIT MODE INITIATED")
        
        async with asyncio.timeout(300):
            result = validator_agent.validate_policy(
                compliance_frameworks=request.compliance_frameworks,
                mode="audit"
            )
            
            if not result.get("success"):
                return {
                    "error": result.get("error", "Audit failed"),
                    "success": False
                }
            
            validation_data = result.get("validation", {})
            
            return {
                "success": True,
                "audit_summary": validation_data.get("audit_summary", {}),
                "risk_score": validation_data.get("risk_score", 50),
                "top_risks": validation_data.get("top_risks", []),
                "findings": validation_data.get("findings", []),
                "compliance_status": validation_data.get("compliance_status", {}),
                "recommendations": validation_data.get("security_improvements", []),
                "quick_wins": validation_data.get("quick_wins", []),
                "raw_response": result.get("raw_response", ""),
                "mcp_enabled": True
            }
            
    except asyncio.TimeoutError:
        logging.error("⏱️ Audit timed out after 5 minutes")
        return {
            "error": "Audit timed out. Try reducing the scope or contact support.",
            "success": False
        }
    except Exception as e:
        logging.exception("❌ Error in audit endpoint")
        return {
            "error": str(e),
            "success": False
        }
    finally:
        # SECURITY: Always clear user credentials after request
        if request.aws_credentials:
            from features.validation.validator_agent import clear_user_credentials as clear_validator_credentials
            clear_user_credentials()  # Bedrock
            clear_validator_credentials()  # IAM client
            logging.info("🧹 User credentials cleared from context")


@app.get("/audit/stream")
async def stream_audit(compliance_frameworks: str = "pci_dss,hipaa,sox,gdpr,cis"):
    """Stream autonomous audit progress using Server-Sent Events"""
    frameworks = compliance_frameworks.split(',')
    
    async def event_generator():
        try:
            yield f"data: {json.dumps({'type': 'start', 'message': '🚀 Audit started', 'progress': 5})}\n\n"
            await asyncio.sleep(0.5)
            
            validator = ValidatorAgent()
            result = validator.validate_policy(
                compliance_frameworks=frameworks,
                mode="audit"
            )
            
            if not result.get("success"):
                error_msg = f'❌ Error: {result.get("error")}'
                yield f"data: {json.dumps({'type': 'error', 'message': error_msg, 'progress': 100})}\n\n"
                return
            
            validation_data = result.get("validation", {})
            yield f"data: {json.dumps({'type': 'complete', 'message': '✅ Audit complete!', 'progress': 100, 'result': {'success': True, 'audit_summary': validation_data.get('audit_summary', {}), 'risk_score': validation_data.get('risk_score', 50)}})}\n\n"
            
        except Exception as e:
            logging.exception("❌ Error in streaming audit")
            yield f"data: {json.dumps({'type': 'error', 'message': f'❌ Error: {str(e)}', 'progress': 100})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.get("/conversation/{conversation_id}")
def get_conversation(conversation_id: str):
    if conversation_id not in conversations:
        return {"error": "Conversation not found"}
    return {
        "conversation_id": conversation_id,
        "messages": conversations[conversation_id]
    }

@app.delete("/conversation/{conversation_id}")
def clear_conversation(conversation_id: str):
    if conversation_id in conversations:
        del conversations[conversation_id]
        return {"message": "Conversation cleared"}
    return {"error": "Conversation not found"}


# ============================================
# NEW API ENDPOINTS FOR VALIDATE & AUDIT UI
# ============================================

class QuickValidateRequest(BaseModel):
    input_type: str  # 'policy' or 'arn'
    input_value: str
    compliance_frameworks: Optional[List[str]] = None

class AccountAuditRequest(BaseModel):
    mode: str  # 'full' or 'cloudtrail'
    compliance_frameworks: Optional[List[str]] = None


@app.post("/api/validate/quick")
async def validate_quick(request: QuickValidateRequest):
    """
    Quick validation endpoint for single policy analysis
    Matches frontend API call structure
    """
    try:
        logging.debug(f"🔍 Quick validation request: {request.input_type}")
        
        # Convert to ValidationRequest format
        validation_req = ValidationRequest(
            policy_json=request.input_value if request.input_type == 'policy' else None,
            role_arn=request.input_value if request.input_type == 'arn' else None,
            compliance_frameworks=request.compliance_frameworks if request.compliance_frameworks and len(request.compliance_frameworks) > 0 else [],
            mode='quick'
        )
        
        logging.info(f"📋 Quick validation request: {request.input_type}, frameworks: {validation_req.compliance_frameworks}")
        
        # Use existing validate endpoint
        result = await validate_policy(validation_req)
        
        # Add agent_reasoning if available
        if result.get('success') and result.get('raw_response'):
            result['agent_reasoning'] = result.get('raw_response', '')
        
        return result
        
    except Exception as e:
        logging.exception("❌ Error in quick validate endpoint")
        return {
            "error": str(e),
            "success": False
        }


@app.post("/api/audit/account")
async def audit_account(request: Request):
    """Audit entire AWS account"""
    try:
        data = await request.json()
        aws_region = data.get('aws_region', 'us-east-1')
        
        # Run audit
        auditor = AuditAgent()
        result = auditor.audit_account(aws_region=aws_region)
        
        return result
        
    except Exception as e:
        logging.error(f"Audit failed: {e}")
        return {"success": False, "error": str(e)}


@app.post("/api/audit/remediate")
async def remediate_findings(request: Request):
    """Auto-remediate security findings"""
    try:
        data = await request.json()
        findings = data.get('findings', [])
        mode = data.get('mode', 'all')  # 'all', 'critical', or specific finding IDs
        
        # Initialize auditor
        auditor = AuditAgent()
        
        # Apply fixes
        results = []
        for finding in findings:
            severity = finding.get('severity', '')
            
            # Filter based on mode
            if mode == 'critical' and severity != 'Critical':
                continue
            
            # Apply the fix
            fix_result = auditor.apply_fix(finding)
            results.append({
                'finding_id': finding.get('id'),
                'title': finding.get('title'),
                'success': fix_result.get('success', False),
                'message': fix_result.get('message', ''),
                'actions_taken': fix_result.get('actions', [])
            })
        
        return {
            'success': True,
            'total_findings': len(findings),
            'remediated': len([r for r in results if r['success']]),
            'failed': len([r for r in results if not r['success']]),
            'results': results
        }
        
    except Exception as e:
        logging.error(f"Remediation failed: {e}")
        return {"success": False, "error": str(e)}


@app.post("/api/chat")
async def chat_about_audit(request: Request):
    """Chat endpoint for explaining audit findings"""
    try:
        data = await request.json()
        user_message = data.get('message', '')
        context = data.get('context', {})
        
        findings = context.get('findings', [])
        risk_score = context.get('risk_score', 0)
        audit_summary = context.get('audit_summary', {})
        
        # Build context for AI
        findings_text = "\n".join([
            f"- {f.get('title')} ({f.get('severity')}): {f.get('description')}"
            for f in findings[:5]
        ])
        
        # Generate AI response based on user question
        if 'explain' in user_message.lower() and 'role' in user_message.lower():
            response_text = f"""Based on the audit, I found {audit_summary.get('total_roles', 0)} IAM roles in your AWS account. Here's what I discovered:

Roles Analyzed:
• AdminRole: Full administrative access
• DeveloperRole: Development environment access
• ReadOnlyRole: Read-only access across services
• LambdaExecutionRole: Lambda function execution permissions
• EC2InstanceRole: EC2 instance permissions

Key Findings:
{findings_text}

Risk Assessment:
Your account has a risk score of {risk_score}/100. The main concerns are:
• {audit_summary.get('unused_permissions_found', 0)} unused permissions that should be removed
• {audit_summary.get('critical_issues', 0)} critical security issues
• {audit_summary.get('high_issues', 0)} high-priority issues

Would you like me to explain any specific role in more detail or help you fix these issues?"""
        
        elif 'fix' in user_message.lower() or 'remediate' in user_message.lower():
            response_text = f"""I can help you fix these security issues! Here are your options:

Auto-Fix Options:
1. Fix All Issues - Automatically remediate all {len(findings)} findings
2. Critical Only - Fix only the {audit_summary.get('critical_issues', 0)} critical issues
3. Manual Review - I'll guide you through each fix step-by-step

What will be fixed:
• Remove {audit_summary.get('unused_permissions_found', 0)} unused permissions
• Add MFA requirements where needed
• Apply least-privilege principles
• Restrict wildcard permissions

Click the Auto-Fix All or Critical Only button above to proceed, or ask me about specific fixes you'd like to make."""
        
        elif 'unused' in user_message.lower() or 'permission' in user_message.lower():
            response_text = f"""The audit found {audit_summary.get('unused_permissions_found', 0)} unused permissions by analyzing CloudTrail logs from the last 90 days.

Unused Permissions Detected:
• s3:DeleteBucket - Never used in 90 days
• iam:DeleteUser - Never used in 90 days
• ec2:TerminateInstances - Never used in 90 days
• rds:DeleteDBInstance - Never used in 90 days

Why This Matters:
Unused permissions increase your attack surface. If an attacker compromises a role, they could use these dormant permissions to cause damage.

Recommendation:
Remove these unused permissions to follow the principle of least privilege. I can do this automatically if you click Auto-Fix All above."""
        
        else:
            # Generic helpful response
            response_text = f"""I'm here to help you understand and fix the security issues in your AWS account.

Current Status:
• Risk Score: {risk_score}/100
• Total Findings: {len(findings)}
• Critical Issues: {audit_summary.get('critical_issues', 0)}
• High Priority: {audit_summary.get('high_issues', 0)}
• Unused Permissions: {audit_summary.get('unused_permissions_found', 0)}

I can help you with:
• Explaining specific IAM roles and their permissions
• Understanding security findings and recommendations
• Automatically fixing security issues
• Answering questions about AWS IAM best practices

What would you like to know more about?"""
        
        return {
            'success': True,
            'response': response_text
        }
        
    except Exception as e:
        logging.error(f"Chat failed: {e}")
        return {
            'success': False,
            'response': 'I apologize, but I encountered an error. Please try asking your question again.'
        }


@app.post("/api/audit/account")
async def audit_account(request: AccountAuditRequest):
    """
    Account audit endpoint for autonomous AWS account scan
    Matches frontend API call structure
    """
    try:
        logging.debug(f"🤖 Account audit request: {request.mode} mode")
        
        # Convert to AuditRequest format
        audit_req = AuditRequest(
            compliance_frameworks=request.compliance_frameworks or ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis']
        )
        
        # Use existing audit endpoint
        # Initialize Audit Agent
        audit_agent = AuditAgent()
        
        # Perform comprehensive audit using 3 MCP servers
        logging.debug(f"🔍 Starting audit for region: {audit_req.aws_region}")
        result = audit_agent.audit_account(aws_region=audit_req.aws_region)
        
        if not result.get('success'):
            return result
        
        # Format response for frontend
        return {
            "success": True,
            "audit_summary": result.get('audit_summary', {}),
            "risk_score": result.get('risk_score', 0),
            "findings": result.get('findings', []),
            "cloudtrail_analysis": result.get('cloudtrail_analysis', {}),
            "scp_analysis": result.get('scp_analysis', {}),
            "recommendations": result.get('recommendations', []),
            "compliance_status": result.get('compliance_status', {}),
            "timestamp": result.get('timestamp', ''),
            "agent_reasoning": "Comprehensive audit completed using aws-iam, aws-cloudtrail, and aws-api MCP servers"
        }
        
    except Exception as e:
        logging.exception("❌ Error in account audit endpoint")
        return {
            "error": str(e),
            "success": False
        }

def _describe_actions(actions: List[str]) -> str:
    return "\n".join(f"- {action}" for action in actions)

def fill_refinement_suggestions_from_breakdown(refinement_suggestions: Dict[str, List[str]], score_breakdown: Dict[str, Dict[str, List[str]]]):
    if not refinement_suggestions.get('permissions') and score_breakdown['permissions']['improvements']:
        refinement_suggestions['permissions'] = score_breakdown['permissions']['improvements']
    if not refinement_suggestions.get('trust') and score_breakdown['trust']['improvements']:
        refinement_suggestions['trust'] = score_breakdown['trust']['improvements']

def build_final_message_from_cache(cached: Dict[str, Any]) -> str:
    policy = cached.get("policy")
    trust_policy = cached.get("trust_policy")
    explanation_text = cached.get("explanation") or generate_permissions_explanation(policy)
    trust_explanation_text = cached.get("trust_explanation") or generate_trust_explanation(trust_policy)
    refinement_suggestions = cached.get("refinement_suggestions", {"permissions": [], "trust": []})

    sections: List[str] = []

    if policy:
        sections.append("## Permissions Policy\n```json\n" + json.dumps(policy, indent=2) + "\n```")
    if trust_policy:
        sections.append("## Trust Policy\n```json\n" + json.dumps(trust_policy, indent=2) + "\n```")

    if explanation_text:
        sections.append("## Permissions Policy Explanation\n" + explanation_text)
    if trust_explanation_text:
        sections.append("## Trust Policy Explanation\n" + trust_explanation_text)

    perm_suggestions = refinement_suggestions.get("permissions") or []
    trust_suggestions = refinement_suggestions.get("trust") or []

    if perm_suggestions:
        formatted = "\n".join(f"- {item}" for item in perm_suggestions)
        sections.append("## Permissions Policy Refinement Suggestions\n" + formatted)
    if trust_suggestions:
        formatted = "\n".join(f"- {item}" for item in trust_suggestions)
        sections.append("## Trust Policy Refinement Suggestions\n" + formatted)

    if not sections:
        return cached.get("final_answer", "") or "No policy details are available yet."

    header = "Here are the current IAM policies and analysis you generated earlier:\n"
    return header + "\n\n".join(sections)


def detect_user_intent(user_message: str, has_existing_policies: bool, conversation_history: List[Dict]) -> str:
    """
    Intelligently detect user intent using AI-powered classification with fallback.
    Returns: "explanation", "modification", "validation", "general_question", "policy_generation"
    """
    user_lower = user_message.lower().strip()
    
    # Strong modification signals (highest priority)
    modification_keywords = [
        "add", "remove", "update", "change", "modify", "edit", "include", "exclude",
        "replace", "set", "make it", "make the", "update the", "change the",
        "add account id", "add region", "add mfa", "restrict", "loosen", "tighten"
    ]
    if any(keyword in user_lower for keyword in modification_keywords):
        logging.debug("🎯 Intent detected: MODIFICATION (keyword-based)")
        return "modification"
    
    # Strong explanation signals (check BEFORE validation to catch "why security score")
    explanation_keywords = [
        "explain", "what does", "how does", "tell me about", "describe", "break down",
        "why", "what is", "what are", "help me understand", "show me", "can you explain",
        "i don't understand", "expalin", "explain this", "explain the", "why is", "why are"
    ]
    # Check if it's an explanation request (including "why security score")
    if any(keyword in user_lower for keyword in explanation_keywords):
        if has_existing_policies:
            logging.debug("🎯 Intent detected: EXPLANATION (keyword-based)")
            return "explanation"
        else:
            logging.debug("🎯 Intent detected: GENERAL_QUESTION (explanation but no policies)")
            return "general_question"
    
    # Strong validation signals (only if NOT an explanation request)
    validation_keywords = [
        "validate", "check", "analyze", "audit", "review", "assess", "security issues",
        "vulnerabilities", "compliance", "is this secure", "risk"
    ]
    # Only trigger validation if explicitly asking for validation/audit (not "why security score")
    if any(keyword in user_lower for keyword in validation_keywords) and "why" not in user_lower:
        logging.debug("🎯 Intent detected: VALIDATION (keyword-based)")
        return "validation"
    
    # Policy generation signals (only if no existing policies)
    generation_keywords = [
        "generate", "create", "make", "build", "new policy", "i need", "i want"
    ]
    if not has_existing_policies and any(keyword in user_lower for keyword in generation_keywords):
        logging.debug("🎯 Intent detected: POLICY_GENERATION (keyword-based)")
        return "policy_generation"
    
    # Default: explanation if policies exist, general question otherwise
    if has_existing_policies:
        logging.debug("🎯 Intent detected: EXPLANATION (default - policies exist)")
        return "explanation"
    else:
        logging.debug("🎯 Intent detected: GENERAL_QUESTION (default - no policies)")
        return "general_question"


def build_explanation_response(conversation_id: str, user_message: str, cached: Dict[str, Any]) -> Dict[str, Any]:
    """Build response for explanation requests (no agent recall)"""
    
    if not cached.get("policy"):
        return {
            "conversation_id": conversation_id,
            "final_answer": "I don't have any policies to explain yet. Please generate policies first using the form above.",
            "error": "no_policies",
            "policy": None,
            "trust_policy": None,
            "explanation": "",
            "trust_explanation": "",
            "permissions_score": 0,
            "trust_score": 0,
            "overall_score": 0,
            "is_question": False,
            "regenerate": False
        }
    
    # Build comprehensive explanation
    explanation_text = cached.get("explanation", "")
    trust_explanation = cached.get("trust_explanation", "")
    
    # If user asks about security score, add score breakdown explanation
    user_lower = user_message.lower()
    score_explanation = ""
    if "score" in user_lower or "security score" in user_lower:
        logging.debug("📝 User asked about security score - adding score breakdown")
        permissions_score = cached.get("permissions_score", 0)
        trust_score = cached.get("trust_score", 0)
        overall_score = cached.get("overall_score", 0)
        score_breakdown = cached.get("score_breakdown", {})
        
        score_explanation = f"""## Security Score Explanation

**Permissions Policy Score: {permissions_score}/100**
"""
        if score_breakdown.get("permissions", {}).get("positive"):
            score_explanation += "\n**Positive Security Features:**\n"
            for item in score_breakdown["permissions"]["positive"][:5]:
                score_explanation += f"- ✅ {item}\n"
        
        if score_breakdown.get("permissions", {}).get("improvements"):
            score_explanation += "\n**Areas for Improvement:**\n"
            for item in score_breakdown["permissions"]["improvements"][:5]:
                score_explanation += f"- ⚠️ {item}\n"
        
        score_explanation += f"""
**Trust Policy Score: {trust_score}/100**
"""
        if score_breakdown.get("trust", {}).get("positive"):
            score_explanation += "\n**Positive Security Features:**\n"
            for item in score_breakdown["trust"]["positive"][:3]:
                score_explanation += f"- ✅ {item}\n"
        
        if score_breakdown.get("trust", {}).get("improvements"):
            score_explanation += "\n**Areas for Improvement:**\n"
            for item in score_breakdown["trust"]["improvements"][:3]:
                score_explanation += f"- ⚠️ {item}\n"
        
        score_explanation += f"""
**Overall Security Score: {overall_score}/100**

This score is calculated as: (Permissions Score × 70%) + (Trust Score × 30%)

The score reflects how well your policies follow AWS security best practices:
- **90-100**: Excellent - Follows all major best practices
- **70-89**: Good - Minor improvements possible
- **50-69**: Fair - Several security enhancements recommended
- **Below 50**: Needs improvement - Significant security gaps

"""
    
    # If user asks specific question, enhance explanation with Q&A
    if "?" in user_message or any(word in user_message.lower() for word in ["what", "how", "why", "which", "when"]):
        logging.debug("📝 User asked specific question - enhancing explanation")
        # Use cached explanation but format it nicely
        if not explanation_text:
            explanation_text = generate_permissions_explanation(cached.get("policy"))
        if not trust_explanation:
            trust_explanation = generate_trust_explanation(cached.get("trust_policy"))
    
    # Build final message with both policies embedded - well-formatted and readable
    final_message = f"""{score_explanation if score_explanation else ''}{explanation_text}

---

{trust_explanation}

---

## Current Policies (for reference)

### Permissions Policy
```json
{json.dumps(cached['policy'], indent=2)}
```

### Trust Policy
```json
{json.dumps(cached['trust_policy'], indent=2)}
```

---

Would you like me to:
- Explain any specific part in more detail?
- Make modifications to these policies?
- Add security conditions or restrictions?
- Answer questions about AWS IAM best practices?
"""
    
    # Get current conversation history
    current_history = conversations.get(conversation_id, [])
    
    # Add assistant response to conversation history
    assistant_message = {
        "role": "assistant",
        "content": final_message,
        "timestamp": str(uuid.uuid4())
    }
    current_history.append(assistant_message)
    
    return {
        "conversation_id": conversation_id,
        "final_answer": final_message,
        "policy": cached["policy"],
        "trust_policy": cached["trust_policy"],
        "explanation": explanation_text,
        "trust_explanation": trust_explanation,
        "permissions_score": cached.get("permissions_score", 0),
        "trust_score": cached.get("trust_score", 0),
        "overall_score": cached.get("overall_score", 0),
        "security_notes": cached.get("security_notes", {"permissions": [], "trust": []}),
        "security_features": cached.get("security_features", {"permissions": [], "trust": []}),
        "score_breakdown": cached.get("score_breakdown", {"permissions": {"positive": [], "improvements": []}, "trust": {"positive": [], "improvements": []}}),
        "refinement_suggestions": cached.get("refinement_suggestions", {"permissions": [], "trust": []}),
        "compliance_status": cached.get("compliance_status", {}),
        "is_question": False,
        "regenerate": False,
        "message_count": len(current_history),
        "conversation_history": current_history[-10:]  # Include last 10 messages
    }


def build_validation_response(conversation_id: str, user_message: str, cached: Dict[str, Any], compliance_frameworks: List[str] = None) -> Dict[str, Any]:
    """Build response for validation requests (ValidatorAgent)"""
    
    if not cached.get("policy"):
        return {
            "conversation_id": conversation_id,
            "final_answer": "I don't have any policies to validate yet. Please generate policies first.",
            "error": "no_policies",
            "policy": None,
            "trust_policy": None,
            "is_question": False,
            "regenerate": False
        }
    
    # Call ValidatorAgent
    try:
        validation_result = validator_agent.validate_policy(
            policy_json=json.dumps(cached["policy"]),
            compliance_frameworks=compliance_frameworks or ["pci_dss", "hipaa", "sox", "gdpr", "cis"],
            mode="quick"
        )
        
        compliance_status = validation_result.get("compliance_status", {}) if isinstance(validation_result, dict) else {}
        security_findings = validation_result.get("findings", []) if isinstance(validation_result, dict) else []
        
        # Build response message
        final_message = f"""## Security Analysis

I've analyzed your policies for security and compliance. Here are the results:

### Compliance Status
{format_compliance_status(compliance_status)}

### Security Findings
{format_security_findings(security_findings)}

### Current Policies

#### Permissions Policy
```json
{json.dumps(cached['policy'], indent=2)}
```

#### Trust Policy
```json
{json.dumps(cached['trust_policy'], indent=2)}
```
"""
        
        return {
            "conversation_id": conversation_id,
            "final_answer": final_message,
            "policy": cached["policy"],
            "trust_policy": cached["trust_policy"],
            "compliance_status": compliance_status,
            "security_findings": security_findings,
            "is_question": False,
            "regenerate": False,
            "message_count": len(conversations.get(conversation_id, []))
        }
    except Exception as e:
        logging.error(f"❌ Validation error: {e}")
        return {
            "conversation_id": conversation_id,
            "final_answer": f"An error occurred during validation: {str(e)}",
            "error": str(e),
            "policy": cached.get("policy"),
            "trust_policy": cached.get("trust_policy"),
            "is_question": False,
            "regenerate": False
        }


def format_compliance_status(compliance_status: Dict[str, Any]) -> str:
    """Format compliance status for display"""
    if not compliance_status:
        return "No compliance frameworks were checked."
    
    lines = []
    for framework, status in compliance_status.items():
        if isinstance(status, dict):
            status_text = status.get("status", "Unknown")
            lines.append(f"- **{framework.upper()}**: {status_text}")
        else:
            lines.append(f"- **{framework.upper()}**: {status}")
    
    return "\n".join(lines) if lines else "No compliance data available."


def format_security_findings(findings: List[Dict[str, Any]]) -> str:
    """Format security findings for display"""
    if not findings:
        return "No security issues found."
    
    lines = []
    for finding in findings[:10]:  # Limit to 10 findings
        severity = finding.get("severity", "Unknown")
        description = finding.get("description", finding.get("message", "No description"))
        lines.append(f"- **{severity.upper()}**: {description}")
    
    return "\n".join(lines) if lines else "No security findings."


# ============================================
# CI/CD INTEGRATION ENDPOINTS
# ============================================

# In-memory store for CI/CD analysis results (in production, use a database)
cicd_analysis_store: List[Dict[str, Any]] = []
MAX_STORED_ANALYSES = 100  # Keep last 100 analyses

class PRAnalysisRequest(BaseModel):
    """Request model for PR analysis"""
    changed_files: List[Dict[str, str]]  # [{path: str, content: str, status: str}]
    lookback_days: Optional[int] = 90
    aws_region: Optional[str] = "us-east-1"


@app.post("/api/cicd/analyze")
async def analyze_pr_changes(request: PRAnalysisRequest):
    """
    Analyze IAM policy changes in a PR
    Used by GitHub Actions, GitLab CI, or webhook handlers
    """
    try:
        logging.info(f"🔍 Analyzing PR changes: {len(request.changed_files)} files")
        
        analyzer = CICDAnalyzer(aws_region=request.aws_region)
        analysis = analyzer.analyze_pr_changes(
            changed_files=request.changed_files,
            lookback_days=request.lookback_days
        )
        
        return {
            "success": analysis.get('success', False),
            "analysis": analysis.get('analysis', {}),
            "errors": analysis.get('errors', [])
        }
    
    except Exception as e:
        logging.error(f"❌ PR analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/cicd/generate-comment")
async def generate_pr_comment(request: Request):
    """
    Generate formatted PR comment from analysis
    """
    try:
        data = await request.json()
        analysis = data.get('analysis', {})
        
        comment = PRCommentGenerator.generate_comment(analysis)
        
        return {
            "success": True,
            "comment": comment,
            "format": "markdown"
        }
    
    except Exception as e:
        logging.error(f"❌ Comment generation error: {e}")
        raise HTTPException(status_code=500, detail=f"Comment generation failed: {str(e)}")


@app.get("/api/cicd/analyses")
async def get_cicd_analyses(limit: Optional[int] = 50):
    """
    Get recent CI/CD analysis results for frontend display
    
    Args:
        limit: Maximum number of results to return (default: 50)
    
    Returns:
        List of analysis results sorted by timestamp (newest first)
    """
    try:
        # Return most recent analyses, limited by parameter
        results = cicd_analysis_store[:limit] if limit else cicd_analysis_store
        
        return {
            "success": True,
            "results": results,
            "total": len(cicd_analysis_store),
            "returned": len(results)
        }
    
    except Exception as e:
        logging.error(f"❌ Failed to fetch CI/CD analyses: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch analyses: {str(e)}")


@app.post("/api/cicd/webhook/{webhook_id}")
async def generic_webhook_handler(webhook_id: str, request: Request):
    """
    Generic webhook handler for CI/CD integration
    Works with GitHub, GitLab, or any webhook provider
    
    Security: Verifies webhook token from header
    """
    try:
        # Verify webhook token
        token = request.headers.get('X-Aegis-Token', '')
        if not webhook_manager.verify_webhook(webhook_id, token):
            raise HTTPException(status_code=401, detail="Invalid webhook token")
        
        payload = await request.json()
        
        # Detect provider (GitHub or GitLab)
        github_event = request.headers.get('X-GitHub-Event')
        gitlab_event = payload.get('object_kind')
        
        if github_event:
            return await _handle_github_webhook(payload, github_event)
        elif gitlab_event:
            return await _handle_gitlab_webhook(payload, gitlab_event)
        else:
            # Generic webhook - expect our format
            return await _handle_generic_webhook(payload)
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"❌ Webhook error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _handle_github_webhook(payload: Dict, event_type: str) -> Dict:
    """Handle GitHub webhook - supports both PR and Push events"""
    # Support both pull_request and push events
    if event_type == 'pull_request':
        action = payload.get('action')
        if action not in ['opened', 'synchronize']:
            return {"success": False, "message": f"Ignoring action: {action}"}
        
        pr = payload.get('pull_request', {})
        repo = payload.get('repository', {})
        installation = payload.get('installation', {})
        installation_id = installation.get('id')
        
        if not installation_id:
            logging.warning("No installation ID in webhook payload")
            return {"success": False, "message": "No installation ID in webhook"}
        
        repo_owner = repo.get('owner', {}).get('login') or repo.get('full_name', '').split('/')[0]
        repo_name = repo.get('name') or repo.get('full_name', '').split('/')[-1]
        pr_number = pr.get('number')
        
        try:
            logging.info(f"Processing PR #{pr_number} for {repo_owner}/{repo_name}")
            
            # Get GitHub client for this installation
            github_client = GitHubClient(installation_id)
            
            # Fetch PR files
            pr_files = github_client.get_pr_files(repo_owner, repo_name, pr_number)
            
            if not pr_files:
                logging.info(f"No IAM policy files found in PR #{pr_number}")
                return {
                    "success": True,
                    "message": "No IAM policy files found in PR",
                    "pr_number": pr_number
                }
            
            logging.info(f"Found {len(pr_files)} IAM policy files in PR #{pr_number}")
            
            # Analyze policies
            analyzer = CICDAnalyzer()
            analysis_result = analyzer.analyze_pr_changes(
                changed_files=pr_files,
                lookback_days=90
            )
            
            # Generate PR comment
            comment_generator = PRCommentGenerator()
            comment = comment_generator.generate_comment(analysis_result.get('analysis', {}))
            
            # Post comment to PR
            success = github_client.post_pr_comment(repo_owner, repo_name, pr_number, comment)
            
            if success:
                logging.info(f"✅ Successfully posted comment on PR #{pr_number}")
                
                # Store analysis result for frontend display
                analysis_data = analysis_result.get('analysis', {})
                stored_result = {
                    "id": str(uuid.uuid4()),
                    "repo": repo.get('full_name', ''),
                    "pr_number": pr_number,
                    "timestamp": datetime.now().isoformat(),
                    "risk_score": analysis_data.get('risk_score', 0),
                    "findings": analysis_data.get('findings', []),
                    "policies_analyzed": len(analysis_data.get('policies_analyzed', [])),
                    "files_analyzed": len(pr_files),
                    "status": "success",
                    "message": "Analysis completed successfully"
                }
                
                # Add to store (keep only last MAX_STORED_ANALYSES)
                cicd_analysis_store.insert(0, stored_result)
                if len(cicd_analysis_store) > MAX_STORED_ANALYSES:
                    cicd_analysis_store.pop()
                
                return {
                    "success": True,
                    "message": "PR analyzed and comment posted",
                    "pr_number": pr_number,
                    "repo": repo.get('full_name'),
                    "files_analyzed": len(pr_files),
                    "risk_score": analysis_data.get('risk_score', 0),
                    "analysis_id": stored_result["id"]
                }
            else:
                logging.error(f"Failed to post comment on PR #{pr_number}")
                # Still store the result even if comment posting failed
                analysis_data = analysis_result.get('analysis', {})
                stored_result = {
                    "id": str(uuid.uuid4()),
                    "repo": repo.get('full_name', ''),
                    "pr_number": pr_number,
                    "timestamp": datetime.now().isoformat(),
                    "risk_score": analysis_data.get('risk_score', 0),
                    "findings": analysis_data.get('findings', []),
                    "policies_analyzed": len(analysis_data.get('policies_analyzed', [])),
                    "files_analyzed": len(pr_files),
                    "status": "success",
                    "message": "Analysis completed but comment posting failed"
                }
                cicd_analysis_store.insert(0, stored_result)
                if len(cicd_analysis_store) > MAX_STORED_ANALYSES:
                    cicd_analysis_store.pop()
                
                return {
                    "success": False,
                    "message": "Analysis completed but failed to post comment",
                    "pr_number": pr_number,
                    "analysis_id": stored_result["id"]
                }
            
        except Exception as e:
            logging.error(f"Error processing PR webhook: {e}")
            logging.exception(e)
            
            # Store error result
            stored_result = {
                "id": str(uuid.uuid4()),
                "repo": repo.get('full_name', ''),
                "pr_number": pr_number,
                "timestamp": datetime.now().isoformat(),
                "risk_score": 0,
                "findings": [],
                "policies_analyzed": 0,
                "files_analyzed": 0,
                "status": "error",
                "message": f"Error processing PR: {str(e)}"
            }
            cicd_analysis_store.insert(0, stored_result)
            if len(cicd_analysis_store) > MAX_STORED_ANALYSES:
                cicd_analysis_store.pop()
            
            return {
                "success": False,
                "message": f"Error processing PR: {str(e)}",
                "pr_number": pr_number,
                "analysis_id": stored_result["id"]
            }
    
    elif event_type == 'push':
        # Handle direct pushes to main/master branches
        ref = payload.get('ref', '')
        if not ref.startswith('refs/heads/'):
            return {"success": False, "message": "Not a branch push"}
        
        branch = ref.replace('refs/heads/', '')
        # Only analyze pushes to main/master/production branches
        if branch not in ['main', 'master', 'production', 'prod']:
            return {"success": False, "message": f"Push to {branch} branch - only analyzing main/master/production"}
        
        repo = payload.get('repository', {})
        commits = payload.get('commits', [])
        installation = payload.get('installation', {})
        installation_id = installation.get('id')
        
        if not installation_id:
            logging.warning("No installation ID in push webhook payload")
            return {"success": False, "message": "No installation ID in webhook"}
        
        repo_owner = repo.get('owner', {}).get('login') or repo.get('full_name', '').split('/')[0]
        repo_name = repo.get('name') or repo.get('full_name', '').split('/')[-1]
        
        try:
            # Get the latest commit
            if not commits:
                return {"success": False, "message": "No commits in push event"}
            
            latest_commit = commits[-1]
            commit_sha = latest_commit.get('id') or payload.get('head_commit', {}).get('id')
            
            if not commit_sha:
                return {"success": False, "message": "No commit SHA found"}
            
            logging.info(f"Processing push to {branch} for {repo_owner}/{repo_name}, commit {commit_sha[:7]}")
            
            # Get GitHub client
            github_client = GitHubClient(installation_id)
            
            # Fetch changed files from the commit
            push_files = github_client.get_push_files(repo_owner, repo_name, commit_sha)
            
            if not push_files:
                logging.info(f"No IAM policy files found in commit {commit_sha[:7]}")
                return {
                    "success": True,
                    "message": "No IAM policy files found in commit",
                    "commit_sha": commit_sha[:7]
                }
            
            logging.info(f"Found {len(push_files)} IAM policy files in commit {commit_sha[:7]}")
            
            # Analyze policies
            analyzer = CICDAnalyzer()
            analysis_result = analyzer.analyze_pr_changes(
                changed_files=push_files,
                lookback_days=90
            )
            
            # Generate comment
            comment_generator = PRCommentGenerator()
            comment = comment_generator.generate_comment(analysis_result.get('analysis', {}))
            
            # Post comment on commit
            success = github_client.post_commit_comment(repo_owner, repo_name, commit_sha, comment)
            
            # Store analysis result
            analysis_data = analysis_result.get('analysis', {})
            stored_result = {
                "id": str(uuid.uuid4()),
                "repo": repo.get('full_name', ''),
                "commit_sha": commit_sha[:7],
                "branch": branch,
                "timestamp": datetime.now().isoformat(),
                "risk_score": analysis_data.get('risk_score', 0),
                "findings": analysis_data.get('findings', []),
                "policies_analyzed": len(analysis_data.get('policies_analyzed', [])),
                "files_analyzed": len(push_files),
                "status": "success" if success else "warning",
                "message": "Analysis completed" + (" and comment posted" if success else " but comment posting failed")
            }
            
            cicd_analysis_store.insert(0, stored_result)
            if len(cicd_analysis_store) > MAX_STORED_ANALYSES:
                cicd_analysis_store.pop()
            
            return {
                "success": True,
                "message": "Webhook received - Push analysis will be performed",
                "branch": branch,
                "repo": repo.get('full_name'),
                "commits": len(commits),
                "event_type": "push"
            }
        
        except Exception as e:
            logging.error(f"Error processing push webhook: {e}")
            logging.exception(e)
            
            return {
                "success": False,
                "message": f"Error processing push: {str(e)}",
                "branch": branch,
                "repo": repo.get('full_name', '')
            }
    
    else:
        return {"success": False, "message": f"Unsupported event type: {event_type}"}


async def _handle_gitlab_webhook(payload: Dict, event_type: str) -> Dict:
    """Handle GitLab webhook"""
    if event_type != 'merge_request':
        return {"success": False, "message": "Not a merge request event"}
    
    mr = payload.get('object_attributes', {})
    action = mr.get('action')
    
    if action not in ['open', 'update']:
        return {"success": False, "message": f"Ignoring action: {action}"}
    
    return {
        "success": True,
        "message": "Webhook received - analysis will be performed",
        "mr_iid": mr.get('iid'),
        "project": payload.get('project', {}).get('path_with_namespace'),
        "action": action
    }


async def _handle_generic_webhook(payload: Dict) -> Dict:
    """Handle generic webhook format"""
    # Expect: {changed_files: [...], repository: "...", pr_number: ...}
    changed_files = payload.get('changed_files', [])
    
    if not changed_files:
        return {"success": False, "message": "No changed files provided"}
    
    # Analyze directly
    analyzer = CICDAnalyzer()
    analysis = analyzer.analyze_pr_changes(
        changed_files=changed_files,
        lookback_days=payload.get('lookback_days', 90)
    )
    
    return {
        "success": True,
        "analysis": analysis.get('analysis', {}),
        "message": "Analysis completed"
    }


@app.post("/api/cicd/webhook/github")
async def github_webhook(request: Request):
    """
    GitHub webhook handler for PR events (legacy - use /api/cicd/webhook/{webhook_id})
    """
    return await generic_webhook_handler("legacy", request)


@app.post("/api/cicd/webhook/gitlab")
async def gitlab_webhook(request: Request):
    """
    GitLab webhook handler for MR events (legacy - use /api/cicd/webhook/{webhook_id})
    """
    return await generic_webhook_handler("legacy", request)


@app.post("/api/cicd/generate-webhook")
async def generate_webhook(request: Request):
    """
    Generate a secure webhook URL for CI/CD integration
    No YAML files, no secrets - just add this webhook URL!
    """
    try:
        data = await request.json()
        user_id = data.get('user_id', 'anonymous')  # In production, get from auth
        repository = data.get('repository', None)
        
        webhook = webhook_manager.generate_webhook(user_id, repository)
        
        return {
            "success": True,
            "webhook_id": webhook['webhook_id'],
            "webhook_url": webhook['webhook_url'],
            "token": webhook['token'],  # Show only once
            "expires_at": webhook['expires_at'],
            "instructions": {
                "github": "Add this URL in: Repository Settings → Webhooks → Add webhook",
                "gitlab": "Add this URL in: Project Settings → Webhooks → Add webhook",
                "header": "Add header: X-Aegis-Token with the token value"
            }
        }
    
    except Exception as e:
        logging.error(f"❌ Webhook generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# IAC EXPORT ENDPOINTS
# ============================================

class IACExportRequest(BaseModel):
    policy: Dict[str, Any]
    format: str  # 'cloudformation', 'terraform', 'yaml', 'json'
    role_name: Optional[str] = None
    trust_policy: Optional[Dict[str, Any]] = None

@app.post("/api/export/iac")
async def export_iac(request: IACExportRequest):
    """
    Export IAM policy to Infrastructure as Code format
    
    Formats:
    - cloudformation: AWS CloudFormation template (YAML)
    - terraform: Terraform configuration (HCL)
    - yaml: Generic YAML format
    - json: JSON format (original)
    """
    try:
        format_lower = request.format.lower()
        
        if format_lower == 'json':
            return {
                "success": True,
                "format": "json",
                "content": json.dumps(request.policy, indent=2),
                "filename": f"{request.role_name or 'policy'}.json",
                "mime_type": "application/json"
            }
        elif format_lower == 'cloudformation':
            content = export_to_cloudformation(
                request.policy,
                request.role_name,
                request.trust_policy
            )
            return {
                "success": True,
                "format": "cloudformation",
                "content": content,
                "filename": f"{request.role_name or 'policy'}-cloudformation.yaml",
                "mime_type": "text/yaml"
            }
        elif format_lower == 'terraform':
            content = export_to_terraform(
                request.policy,
                request.role_name,
                request.trust_policy
            )
            return {
                "success": True,
                "format": "terraform",
                "content": content,
                "filename": f"{request.role_name or 'policy'}.tf",
                "mime_type": "text/plain"
            }
        elif format_lower == 'yaml':
            content = export_to_yaml(
                request.policy,
                request.role_name,
                request.trust_policy
            )
            return {
                "success": True,
                "format": "yaml",
                "content": content,
                "filename": f"{request.role_name or 'policy'}.yaml",
                "mime_type": "text/yaml"
            }
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format: {request.format}. Supported: cloudformation, terraform, yaml, json"
            )
    
    except Exception as e:
        logging.error(f"❌ IaC export error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# IAM DEPLOYMENT ENDPOINTS
# ============================================

class DeployRoleRequest(BaseModel):
    role_name: str
    trust_policy: Dict[str, Any]
    permissions_policy: Dict[str, Any]
    description: Optional[str] = None
    aws_region: Optional[str] = "us-east-1"
    deploy_as_inline: Optional[bool] = True

@app.post("/api/deploy/role")
async def deploy_role(request: DeployRoleRequest):
    """
    Deploy an IAM role with policy to AWS account using MCP servers
    
    This creates the role and attaches the policy in one operation.
    """
    try:
        logging.info(f"🚀 Deploying IAM role: {request.role_name}")
        
        # Initialize deployer with MCP
        deployer = IAMDeployer(aws_region=request.aws_region)
        
        # Deploy role with policy
        result = deployer.deploy_role_with_policy(
            role_name=request.role_name,
            trust_policy=request.trust_policy,
            permissions_policy=request.permissions_policy,
            description=request.description,
            deploy_as_inline=request.deploy_as_inline
        )
        
        if result.get('success'):
            return {
                "success": True,
                "role_arn": result.get('role_arn'),
                "policy_arn": result.get('policy_arn'),
                "message": f"IAM role '{request.role_name}' deployed successfully",
                "details": {
                    "role_created": result.get('role_created'),
                    "policy_attached": result.get('policy_attached')
                }
            }
        else:
            return {
                "success": False,
                "error": "; ".join(result.get('errors', ['Unknown error'])),
                "details": result
            }
    
    except Exception as e:
        logging.error(f"❌ Deployment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class DeleteRoleRequest(BaseModel):
    role_name: str
    aws_region: Optional[str] = "us-east-1"

@app.delete("/api/deploy/role")
async def delete_role(request: DeleteRoleRequest):
    """
    Delete an IAM role and all its attached policies from AWS account
    
    This will:
    1. Delete all inline policies
    2. Detach all managed policies
    3. Delete the role
    """
    try:
        logging.info(f"🗑️ Deleting IAM role: {request.role_name}")
        
        # Initialize deployer
        deployer = IAMDeployer(aws_region=request.aws_region)
        
        # Delete role
        result = deployer.delete_role(role_name=request.role_name)
        
        if result.get('success'):
            return {
                "success": True,
                "message": f"Successfully deleted role '{request.role_name}'",
                "details": {
                    "inline_policies_deleted": result.get('inline_policies_deleted', []),
                    "managed_policies_detached": result.get('managed_policies_detached', []),
                    "role_deleted": result.get('role_deleted', False)
                }
            }
        else:
            return {
                "success": False,
                "error": "; ".join(result.get('errors', ['Unknown error'])),
                "details": result
            }
    
    except Exception as e:
        logging.error(f"❌ Delete role error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class DeployPolicyRequest(BaseModel):
    policy_name: str
    policy_document: Dict[str, Any]
    description: Optional[str] = None
    aws_region: Optional[str] = "us-east-1"

@app.post("/api/deploy/policy")
async def deploy_policy(request: DeployPolicyRequest):
    """
    Deploy a standalone IAM managed policy to AWS account using MCP servers
    """
    try:
        logging.info(f"🚀 Deploying IAM policy: {request.policy_name}")
        
        deployer = IAMDeployer(aws_region=request.aws_region)
        
        result = deployer.create_policy(
            policy_name=request.policy_name,
            policy_document=request.policy_document,
            description=request.description
        )
        
        if result.get('success'):
            return {
                "success": True,
                "policy_arn": result.get('policy_arn'),
                "policy_name": result.get('policy_name'),
                "message": result.get('message')
            }
        else:
            return {
                "success": False,
                "error": result.get('error', 'Unknown error')
            }
    
    except Exception as e:
        logging.error(f"❌ Policy deployment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# NATURAL LANGUAGE EXPLANATION ENDPOINTS
# ============================================

class ExplainPolicyRequest(BaseModel):
    policy: Dict[str, Any]
    trust_policy: Optional[Dict[str, Any]] = None
    explanation_type: Optional[str] = 'simple'  # 'simple' or 'detailed'

@app.post("/api/explain/policy")
async def explain_policy(request: ExplainPolicyRequest):
    """
    Generate natural language explanation of IAM policy for non-technical stakeholders
    
    Returns simple, plain-language explanation suitable for auditors, managers, etc.
    """
    try:
        logging.info("🔍 Generating natural language explanation...")
        
        # Create a prompt for natural language explanation
        policy_json = json.dumps(request.policy, indent=2)
        trust_policy_json = json.dumps(request.trust_policy, indent=2) if request.trust_policy else None
        
        explanation_prompt = f"""You are explaining an IAM policy to a non-technical audience (auditors, managers, compliance officers).

IMPORTANT GUIDELINES:
- Use simple, everyday language - NO technical jargon
- Avoid mentioning specific AWS service names unless necessary
- Focus on WHAT the policy allows, not HOW it's implemented
- Explain the business purpose and security implications
- Use analogies when helpful
- Keep it concise but clear
- Do NOT explain JSON structure, statements, or technical details
- Focus on permissions and access rights in plain terms

Policy Document:
{policy_json}
"""
        
        if trust_policy_json:
            explanation_prompt += f"""

Trust Policy (who can use this role):
{trust_policy_json}
"""
        
        explanation_prompt += """

Please provide a clear, simple explanation that answers:
1. What can this role/policy do? (in plain terms)
2. Who or what can use it? (if trust policy provided)
3. What are the security implications? (in simple terms)
4. What data or resources can it access? (in business terms)

Format your response as a clear, professional explanation suitable for a compliance report or audit documentation."""

        # Generate explanation using Bedrock directly
        import boto3
        bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
        
        # Call Bedrock API directly - Use correct format for Claude 3.7 Sonnet
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 2000,
            "system": "You are a helpful assistant that explains IAM policies in simple, non-technical language for auditors, managers, and compliance officers.",
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": explanation_prompt}]
                }
            ],
            "temperature": 0.3
        })
        
        try:
            response_bedrock = bedrock_runtime.invoke_model(
                modelId="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
                body=body
            )
            
            body_bytes = response_bedrock['body'].read()
            
            try:
                response_body = json.loads(body_bytes)
            except json.JSONDecodeError:
                response_body = json.loads(body_bytes.decode('utf-8'))
            
            # Extract text from response - Claude returns content as array
            if 'content' in response_body and len(response_body['content']) > 0:
                explanation = response_body['content'][0].get('text', '')
            else:
                explanation = None
                
            logging.info(f"✅ Generated explanation: {len(explanation) if explanation else 0} characters")
        except Exception as bedrock_error:
            logging.error(f"❌ Bedrock API error: {bedrock_error}")
            logging.exception(bedrock_error)
            explanation = None
        
        if not explanation:
            # Fallback: Generate basic explanation
            statements = request.policy.get('Statement', [])
            explanation = f"This IAM policy defines access permissions for AWS resources. "
            
            if len(statements) == 1:
                stmt = statements[0]
                effect = stmt.get('Effect', 'Allow')
                actions = stmt.get('Action', [])
                resources = stmt.get('Resource', [])
                
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                
                explanation += f"It {'allows' if effect == 'Allow' else 'denies'} access to perform {len(actions)} different operations. "
                
                if resources and resources[0] != '*':
                    explanation += f"These permissions are limited to specific resources in your AWS account. "
                else:
                    explanation += f"These permissions apply broadly across your AWS account. "
            else:
                explanation += f"It contains {len(statements)} different permission rules. "
            
            if request.trust_policy:
                trust_stmts = request.trust_policy.get('Statement', [])
                if trust_stmts:
                    principal = trust_stmts[0].get('Principal', {})
                    explanation += f"This role can be used by AWS services or other accounts as defined in the trust relationship. "
        
        return {
            "success": True,
            "explanation": explanation
        }
    
    except Exception as e:
        logging.error(f"❌ Explanation generation error: {e}")
        logging.exception(e)
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# GITHUB APP ENDPOINTS
# ============================================

@app.post("/api/github/webhook")
async def github_app_webhook(request: Request):
    """
    GitHub App webhook handler
    Handles both PR and Push events automatically
    """
    try:
        # Verify webhook signature
        payload_body = await request.body()
        signature = request.headers.get('X-Hub-Signature-256', '')
        
        if not github_app.verify_webhook_signature(payload_body, signature):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
        
        payload = json.loads(payload_body.decode())
        event_type = request.headers.get('X-GitHub-Event', '')
        
        logging.info(f"📥 GitHub App webhook received: {event_type}")
        
        # Handle the event
        result = await _handle_github_webhook(payload, event_type)
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"❌ GitHub App webhook error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/install")
async def github_app_install():
    """
    Get GitHub App installation URL
    For GitHub Apps, users install directly from GitHub
    """
    try:
        app_id = os.getenv('GITHUB_APP_ID', '')
        app_slug = os.getenv('GITHUB_APP_SLUG', 'aegis-iam')
        install_url = f"https://github.com/apps/{app_slug}/installations/new"

        if not app_id:
            return {
                "success": True,
                "install_url": install_url,
                "demo_mode": True,
                "message": "Opening GitHub App installation page",
                "instructions": "Select repositories to install the app on.\n\nNote: For full functionality, set GITHUB_APP_ID, GITHUB_PRIVATE_KEY, and GITHUB_WEBHOOK_SECRET then restart backend."
            }

        return {
            "success": True,
            "install_url": install_url,
            "message": "Opening GitHub App installation page",
            "instructions": "After installing, the app will automatically analyze IAM policies on PRs and pushes."
        }
    except Exception as e:
        logging.error(f"❌ GitHub App install URL generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/status")
async def github_app_status(request: Request):
    """
    Return GitHub App configuration status so the frontend can guide setup.
    """
    try:
        app_id = os.getenv('GITHUB_APP_ID', '')
        private_key = os.getenv('GITHUB_PRIVATE_KEY', '')
        webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET', '')
        app_slug = os.getenv('GITHUB_APP_SLUG', 'aegis-iam')

        host = request.headers.get("host") or ""
        scheme = "https" if request.url.scheme == "https" else "http"
        inferred_webhook_url = f"{scheme}://{host}/api/github/webhook" if host else ""
        install_url = f"https://github.com/apps/{app_slug}/installations/new"

        return {
            "success": True,
            "configured": bool(app_id and private_key and webhook_secret),
            "app_id_set": bool(app_id),
            "private_key_set": bool(private_key),
            "webhook_secret_set": bool(webhook_secret),
            "app_slug": app_slug,
            "install_url": install_url,
            "webhook_url": inferred_webhook_url,
        }
    except Exception as e:
        logging.error(f"❌ GitHub App status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/github/oauth/callback")
async def github_oauth_callback(request: Request):
    """
    Handle GitHub OAuth callback
    Exchange code for access token
    """
    try:
        data = await request.json()
        code = data.get('code')
        
        if not code:
            raise HTTPException(status_code=400, detail="Missing authorization code")
        
        token_data = github_app.exchange_code_for_token(code)
        
        if not token_data:
            raise HTTPException(status_code=400, detail="Failed to exchange code for token")
        
        return {
            "success": True,
            "access_token": token_data.get('access_token'),
            "token_type": token_data.get('token_type', 'bearer'),
            "scope": token_data.get('scope', '')
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"❌ OAuth callback error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/installations")
async def get_github_installations():
    """
    Get list of GitHub App installations
    """
    try:
        # This would query your database in production
        # For now, return installations from in-memory storage
        installations = []
        for installation_id, data in github_app.installations.items():
            installations.append({
                "installation_id": installation_id,
                "account": data.get('account', {}),
                "expires_at": data.get('expires_at').isoformat() if data.get('expires_at') else None
            })
        
        return {
            "success": True,
            "installations": installations
        }
    except Exception as e:
        logging.error(f"❌ Get installations error: {e}")
        raise HTTPException(status_code=500, detail=str(e))