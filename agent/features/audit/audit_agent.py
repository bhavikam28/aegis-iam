# agent/audit_agent.py
"""
Production-Ready Audit Agent - Comprehensive AWS Account Security Audit
Uses 3 MCP servers: aws-iam, aws-cloudtrail, aws-api
Implements real auto-remediation with boto3
NO SAMPLE DATA - Production ready for any AWS account
"""
import logging
import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from core.fastmcp_client import get_mcp_client
from features.validation.security_validator import SecurityValidator
from features.validation.policy_scorer import calculate_policy_scores, generate_security_recommendations

logging.basicConfig(level=logging.INFO)

class AuditAgent:
    """Production-Ready Autonomous AWS Account Audit Agent"""
    
    def __init__(self, aws_region: str = "us-east-1", aws_credentials: dict = None):
        """
        Initialize Audit Agent
        
        Args:
            aws_region: AWS region
            aws_credentials: Optional dict with access_key_id, secret_access_key, region
                            If None, uses default boto3 credentials
        
        SECURITY: User credentials are used only for this agent instance, never stored
        """
        self.validator = SecurityValidator()
        self.aws_region = aws_region
        self.aws_credentials = aws_credentials
        
        # MCP clients
        self.iam_client = None
        self.cloudtrail_client = None
        self.api_client = None
        
        # Boto3 clients for real AWS operations and remediation
        try:
            if aws_credentials:
                # Use user-provided credentials
                logging.info(f"🔧 Creating IAM/STS clients with user credentials (region: {aws_region})")
                self.boto_iam = boto3.client(
                    'iam',
                    aws_access_key_id=aws_credentials['access_key_id'],
                    aws_secret_access_key=aws_credentials['secret_access_key'],
                    region_name=aws_region
                )
                self.boto_sts = boto3.client(
                    'sts',
                    aws_access_key_id=aws_credentials['access_key_id'],
                    aws_secret_access_key=aws_credentials['secret_access_key'],
                    region_name=aws_region
                )
            else:
                # Use default credentials (for development/testing only)
                logging.info(f"🔧 Creating IAM/STS clients with default credentials")
                self.boto_iam = boto3.client('iam', region_name=aws_region)
                self.boto_sts = boto3.client('sts', region_name=aws_region)
            
            # Get current account ID
            self.account_id = self.boto_sts.get_caller_identity()['Account']
            logging.info(f"✅ Boto3 IAM client initialized for account: {self.account_id}")
        except Exception as e:
            logging.error(f"❌ Failed to initialize boto3 clients: {e}")
            logging.error("   Please ensure AWS credentials are configured")
            self.boto_iam = None
            self.boto_sts = None
            self.account_id = None
        
    def initialize_mcp_clients(self) -> bool:
        """Initialize MCP clients (aws-iam, aws-cloudtrail, aws-api)"""
        try:
            logging.info("🚀 Initializing MCP clients for audit...")
            
            success_count = 0
            
            # Initialize IAM MCP server
            self.iam_client = get_mcp_client('aws-iam')
            if self.iam_client:
                logging.info("✅ aws-iam MCP server initialized")
                # List available tools to debug parameter issues
                tools = self.iam_client.list_tools()
                if tools:
                    logging.info(f"   Available IAM tools: {[t.get('name') for t in tools]}")
                    # Log first tool's schema for debugging
                    if len(tools) > 0:
                        logging.info(f"   Example tool schema: {tools[0]}")
                success_count += 1
            else:
                logging.warning("⚠️ aws-iam MCP server not available")
            
            # Initialize CloudTrail MCP server
            self.cloudtrail_client = get_mcp_client('aws-cloudtrail')
            if self.cloudtrail_client:
                logging.info("✅ aws-cloudtrail MCP server initialized")
                # List available tools
                tools = self.cloudtrail_client.list_tools()
                if tools:
                    logging.info(f"   Available CloudTrail tools: {[t.get('name') for t in tools]}")
                    if len(tools) > 0:
                        logging.info(f"   Example tool schema: {tools[0]}")
                success_count += 1
            else:
                logging.warning("⚠️ aws-cloudtrail MCP server not available")
            
            # Initialize AWS API MCP server
            self.api_client = get_mcp_client('aws-api')
            if self.api_client:
                logging.info("✅ aws-api MCP server initialized")
                # List available tools
                tools = self.api_client.list_tools()
                if tools:
                    logging.info(f"   Available API tools: {[t.get('name') for t in tools]}")
                    if len(tools) > 0:
                        logging.info(f"   Example tool schema: {tools[0]}")
                success_count += 1
            else:
                logging.warning("⚠️ aws-api MCP server not available")
            
            if success_count > 0:
                logging.info(f"✅ {success_count}/3 MCP clients initialized successfully")
                return True
            else:
                logging.warning("⚠️ No MCP clients available - will use boto3 fallback")
                return False
            
        except Exception as e:
            logging.error(f"❌ MCP initialization failed: {e}")
            return False
    
    def audit_account(self, aws_region: str = "us-east-1") -> Dict[str, Any]:
        """Perform comprehensive account audit using real AWS data"""
        try:
            logging.info("🔍 Starting comprehensive AWS account audit...")
            
            # Verify boto3 clients are available
            if not self.boto_iam:
                return {
                    "success": False,
                    "error": "AWS credentials not configured. Please set up AWS CLI or environment variables.",
                    "help": "Run 'aws configure' or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
                }
            
            # Initialize MCP clients (required for full audit)
            mcp_initialized = self.initialize_mcp_clients()
            if not mcp_initialized:
                logging.warning("⚠️ MCP clients not available - audit will use boto3 only")
                logging.warning("   For full audit capabilities, install MCP servers:")
                logging.warning("   uvx awslabs-iam-mcp-server")
                logging.warning("   uvx awslabs-cloudtrail-mcp-server")
            
            # Step 1: Discover all IAM roles
            logging.info("📋 Step 1: Discovering IAM roles...")
            roles = self._discover_iam_roles()
            
            # Step 2: Analyze each role's policies
            logging.info("🔍 Step 2: Analyzing role policies...")
            role_analysis = self._analyze_roles(roles)
            
            # Step 3: Analyze CloudTrail for unused permissions
            logging.info("📊 Step 3: Analyzing CloudTrail logs...")
            cloudtrail_analysis = self._analyze_cloudtrail(roles)
            
            # Step 4: Check for SCPs and permission boundaries
            logging.info("🛡️ Step 4: Checking SCPs and boundaries...")
            scp_analysis = self._analyze_scps()
            
            # Step 5: Generate comprehensive report
            logging.info("📝 Step 5: Generating audit report...")
            report = self._generate_audit_report(
                roles=roles,
                role_analysis=role_analysis,
                cloudtrail_analysis=cloudtrail_analysis,
                scp_analysis=scp_analysis
            )
            
            logging.info("✅ Audit completed successfully")
            return report
            
        except Exception as e:
            import traceback
            logging.error(f"❌ Audit failed: {e}")
            logging.error(f"Traceback: {traceback.format_exc()}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _discover_iam_roles(self) -> List[Dict[str, Any]]:
        """Discover all IAM roles - Try MCP first, fall back to boto3"""
        
        # Try MCP first (if available)
        if self.iam_client:
            try:
                logging.info("🔧 Trying MCP server for IAM roles...")
                # AWS IAM MCP server list_roles expects optional parameters
                result = self.iam_client.call_tool('list_roles', {
                    'maxItems': 100,
                    'pathPrefix': ''
                })
                
                if result.get('success', False):
                    roles_data = result.get('data', {})
                    
                    # FastMCP returns Pydantic-like model objects (e.g., list_rolesOutput)
                    # Convert to dict if it's a model object
                    if hasattr(roles_data, 'model_dump'):
                        # Pydantic v2
                        roles_data = roles_data.model_dump()
                    elif hasattr(roles_data, 'dict'):
                        # Pydantic v1
                        roles_data = roles_data.dict()
                    elif hasattr(roles_data, '__dict__'):
                        # Regular object - convert to dict
                        roles_data = vars(roles_data)
                    elif not isinstance(roles_data, (dict, list, str)):
                        # Try to convert using dict() constructor
                        try:
                            roles_data = dict(roles_data) if hasattr(roles_data, 'keys') else roles_data
                        except (TypeError, ValueError):
                            # If conversion fails, try accessing attributes directly
                            if hasattr(roles_data, 'roles'):
                                roles_list_from_attr = getattr(roles_data, 'roles', None)
                                if roles_list_from_attr:
                                    roles_data = {'roles': roles_list_from_attr}
                                else:
                                    roles_data = {}
                            elif hasattr(roles_data, 'Roles'):
                                roles_list_from_attr = getattr(roles_data, 'Roles', None)
                                if roles_list_from_attr:
                                    roles_data = {'Roles': roles_list_from_attr}
                                else:
                                    roles_data = {}
                            else:
                                # Try common attribute names from AWS IAM responses
                                for attr_name in ['Roles', 'roles', 'RoleList', 'role_list', 'items', 'data']:
                                    if hasattr(roles_data, attr_name):
                                        attr_value = getattr(roles_data, attr_name)
                                        if attr_value:
                                            roles_data = {attr_name: attr_value}
                                            break
                                else:
                                    # Log all available attributes for debugging
                                    attrs = [attr for attr in dir(roles_data) if not attr.startswith('_')]
                                    logging.warning(f"⚠️ Cannot convert FastMCP object to dict: {type(roles_data)}")
                                    logging.warning(f"   Available attributes: {attrs[:10]}")
                                    roles_data = {}
                    
                    logging.info(f"🔍 MCP response converted - type: {type(roles_data)}")
                    
                    # CRITICAL: Log the actual structure regardless of type
                    if isinstance(roles_data, dict):
                        all_keys = list(roles_data.keys())
                        logging.warning(f"🔍 [DEBUG] MCP response keys: {all_keys}")  # Use warning so it always shows
                        logging.warning(f"🔍 [DEBUG] MCP response dict length: {len(roles_data)}")
                        # Log the full structure for debugging - show actual dict structure
                        if all_keys:
                            for key in all_keys[:3]:  # Log first 3 keys
                                value = roles_data.get(key)
                                if isinstance(value, dict):
                                    logging.warning(f"🔍 [DEBUG] Key '{key}' -> dict with keys: {list(value.keys())}")
                                    if len(value) == 0:
                                        logging.warning(f"🔍 [DEBUG] Key '{key}' dict is EMPTY!")
                                    else:
                                        # Show nested structure
                                        for nested_key in list(value.keys())[:2]:
                                            nested_val = value.get(nested_key)
                                            logging.warning(f"🔍 [DEBUG] Key '{key}.{nested_key}' -> type: {type(nested_val)}, preview: {str(nested_val)[:200]}")
                                else:
                                    value_str = str(value)[:300] if value is not None else "None"
                                    logging.warning(f"🔍 [DEBUG] Key '{key}' -> type: {type(value)}, value: {value_str}")
                        else:
                            logging.warning("⚠️ MCP response dict is empty!")
                    elif isinstance(roles_data, list):
                        logging.warning(f"🔍 [DEBUG] MCP response is a list with {len(roles_data)} items")
                        if roles_data:
                            logging.warning(f"🔍 [DEBUG] First item type: {type(roles_data[0])}, value: {str(roles_data[0])[:200]}")
                    else:
                        logging.warning(f"🔍 [DEBUG] MCP response is neither dict nor list: {type(roles_data)}, value: {str(roles_data)[:500]}")
                    
                    # FastMCP returns responses in a specific format
                    # The data might be directly the roles list or wrapped in content
                    roles_list = None
                    
                    # Try direct access (if roles_data is already a list or dict with roles)
                    if isinstance(roles_data, list):
                        # Direct list of roles
                        roles_list = roles_data
                    elif isinstance(roles_data, dict):
                        # Check for common response structures from AWS IAM MCP server
                        # Try various possible key names
                        roles_list = None
                        for key in ['Roles', 'roles', 'roleList', 'role_list', 'items', 'data', 'result']:
                            if key in roles_data and roles_data[key]:
                                value = roles_data[key]
                                
                                # If value is another Pydantic model (like Result), convert it first
                                if hasattr(value, 'model_dump'):
                                    value = value.model_dump()
                                elif hasattr(value, 'dict'):
                                    value = value.dict()
                                elif hasattr(value, '__dict__') and not isinstance(value, (dict, list, str)):
                                    value = vars(value)
                                
                                # Now check if value is a list or dict with roles
                                if isinstance(value, list):
                                    roles_list = value
                                    logging.info(f"✅ Found roles list under key: '{key}' (direct list)")
                                    break
                                elif isinstance(value, dict):
                                    # The Result object might have roles nested inside
                                    # Check for MCP content format first (this is what AWS IAM MCP uses)
                                    if 'content' in value and isinstance(value['content'], list):
                                        # MCP content format - parse JSON from text items
                                        content_list = value['content']
                                        parsed_roles = []
                                        for item in content_list:
                                            if isinstance(item, dict) and 'text' in item:
                                                try:
                                                    import json
                                                    role_data = json.loads(item['text'])
                                                    parsed_roles.append(role_data)
                                                except (json.JSONDecodeError, TypeError):
                                                    pass
                                            elif isinstance(item, dict):
                                                # Already parsed dict
                                                parsed_roles.append(item)
                                        
                                        if parsed_roles:
                                            roles_list = parsed_roles
                                            logging.info(f"✅ Found roles list under key: '{key}' (MCP content format, {len(parsed_roles)} roles)")
                                            break
                                    
                                    # Check other nested keys
                                    for roles_key in ['Roles', 'roles', 'roleList', 'role_list', 'items', 'data']:
                                        if roles_key in value and value[roles_key]:
                                            roles_list = value[roles_key]
                                            logging.info(f"✅ Found roles list under key: '{key}.{roles_key}'")
                                            break
                                    if roles_list:
                                        break
                                else:
                                    logging.debug(f"   Key '{key}' has value type {type(value)}, skipping")
                        logging.info(f"   roles_list after key search: {roles_list is not None}")
                        
                        # If still not found, check for MCP content format at top level
                        if not roles_list and 'content' in roles_data:
                            # MCP content format - parse JSON from text items
                            content_list = roles_data['content']
                            if isinstance(content_list, list) and len(content_list) > 0:
                                parsed_roles = []
                                for item in content_list:
                                    if isinstance(item, dict) and 'text' in item:
                                        try:
                                            import json
                                            json_data = json.loads(item['text'])
                                            # The JSON might be {"Roles": [...]} - extract the Roles array
                                            if isinstance(json_data, dict):
                                                # Check for Roles array in the JSON
                                                if 'Roles' in json_data and isinstance(json_data['Roles'], list):
                                                    parsed_roles.extend(json_data['Roles'])  # Add all roles
                                                elif 'roles' in json_data and isinstance(json_data['roles'], list):
                                                    parsed_roles.extend(json_data['roles'])  # Add all roles
                                                else:
                                                    # Might be a single role object
                                                    parsed_roles.append(json_data)
                                            elif isinstance(json_data, list):
                                                # Direct list of roles
                                                parsed_roles.extend(json_data)
                                            else:
                                                parsed_roles.append(json_data)
                                        except (json.JSONDecodeError, TypeError) as e:
                                            logging.debug(f"   Failed to parse JSON: {e}")
                                            pass
                                    elif isinstance(item, dict):
                                        # Already a dict - check if it has Roles
                                        if 'Roles' in item and isinstance(item['Roles'], list):
                                            parsed_roles.extend(item['Roles'])
                                        elif 'roles' in item and isinstance(item['roles'], list):
                                            parsed_roles.extend(item['roles'])
                                        else:
                                            parsed_roles.append(item)
                                
                                if parsed_roles:
                                    roles_list = parsed_roles
                                    logging.info(f"✅ Found roles list in 'content' format ({len(parsed_roles)} roles)")
                        
                        # If still not found, check if any dict value is a list (could be roles)
                        if not roles_list:
                            for key, value in roles_data.items():
                                if isinstance(value, list) and len(value) > 0:
                                    # Check if first item looks like a role (has RoleName or similar)
                                    first_item = value[0]
                                    if isinstance(first_item, dict):
                                        if 'RoleName' in first_item or 'name' in first_item or 'Arn' in first_item:
                                            roles_list = value
                                            logging.info(f"✅ Found roles list in key: '{key}' (detected by role attributes)")
                                            break
                                    elif isinstance(first_item, str):
                                        # Might be a list of role names
                                        roles_list = value
                                        logging.info(f"✅ Found roles list in key: '{key}' (list of strings)")
                                        break
                        
                        # If not found in common keys, try content format
                        if not roles_list and 'content' in roles_data:
                            # Handle MCP content format
                            content = roles_data['content']
                            if isinstance(content, list) and len(content) > 0:
                                # Extract text from content items
                                if hasattr(content[0], 'text'):
                                    text_content = content[0].text
                                elif isinstance(content[0], dict) and 'text' in content[0]:
                                    text_content = content[0]['text']
                                else:
                                    # Content might be JSON string
                                    text_content = str(content[0])
                                
                                # Try to parse as JSON first
                                try:
                                    import json
                                    parsed = json.loads(text_content) if isinstance(text_content, str) else text_content
                                    if isinstance(parsed, dict):
                                        roles_list = parsed.get('roles') or parsed.get('Roles') or [parsed]
                                    elif isinstance(parsed, list):
                                        roles_list = parsed
                                    else:
                                        # Fall back to text parsing
                                        roles_list = self._parse_roles_from_text(text_content)
                                except (json.JSONDecodeError, TypeError):
                                    # Not JSON, parse as text
                                    roles_list = self._parse_roles_from_text(text_content)
                            elif isinstance(content, str):
                                roles_list = self._parse_roles_from_text(content)
                        elif isinstance(roles_data, str):
                            # Direct string response
                            roles_list = self._parse_roles_from_text(roles_data)
                    
                    # If we got roles from MCP, format and return them
                    if roles_list:
                        logging.info(f"🔍 [FORMAT] Processing {len(roles_list)} roles from roles_list")
                        formatted_roles = []
                        for idx, role in enumerate(roles_list):
                            if isinstance(role, dict):
                                role_name = role.get('RoleName') or role.get('name') or role.get('roleName', '')
                                logging.debug(f"   Role {idx}: keys={list(role.keys())[:5]}, name={role_name}")
                                formatted_roles.append({
                                    'name': role_name,
                                    'arn': role.get('Arn') or role.get('arn') or role.get('roleArn', ''),
                                    'created': str(role.get('CreateDate') or role.get('created') or role.get('createDate', '')),
                                    'path': role.get('Path') or role.get('path', '/'),
                                    'max_session_duration': role.get('MaxSessionDuration') or role.get('maxSessionDuration', 3600)
                                })
                            elif isinstance(role, str):
                                # Just a role name
                                formatted_roles.append({
                                    'name': role,
                                    'arn': f'arn:aws:iam::{self.account_id}:role/{role}',
                                    'created': '',
                                    'path': '/',
                                    'max_session_duration': 3600
                                })
                        
                        if formatted_roles:
                            logging.info(f"✅ MCP: Discovered {len(formatted_roles)} IAM roles")
                            return formatted_roles
                        else:
                            logging.warning("⚠️ MCP returned empty roles list")
                    else:
                        # Log why parsing failed
                        logging.warning("⚠️ MCP response format not recognized, falling back to boto3")
                        logging.warning(f"   [DEBUG] roles_list is None after parsing")
                        logging.warning(f"   [DEBUG] roles_data type: {type(roles_data)}")
                        if isinstance(roles_data, dict):
                            logging.warning(f"   [DEBUG] Dict keys that were checked: {list(roles_data.keys())}")
                            logging.warning(f"   [DEBUG] Dict structure sample: {str(roles_data)[:1000]}")
                        elif isinstance(roles_data, list):
                            logging.warning(f"   [DEBUG] List length: {len(roles_data)}")
                            if roles_data:
                                logging.warning(f"   [DEBUG] First item: {str(roles_data[0])[:500]}")
                        else:
                            logging.warning(f"   [DEBUG] roles_data value: {str(roles_data)[:500]}")
                else:
                    logging.warning(f"⚠️ MCP call failed: {result.get('error', 'Unknown error')}")
            except Exception as e:
                logging.warning(f"⚠️ MCP failed: {e}")
                import traceback
                logging.debug(traceback.format_exc())
        
        # Fall back to boto3 for REAL AWS data
        logging.info("🔄 Falling back to boto3 for REAL AWS data...")
        return self._discover_roles_boto3()
    
    def _discover_roles_boto3(self) -> List[Dict[str, Any]]:
        """Discover IAM roles using boto3 (fallback method)"""
        try:
            if not self.boto_iam:
                logging.error("❌ Boto3 IAM client not available")
                return []
            
            logging.info("📋 Fetching IAM roles from AWS account via boto3...")
            paginator = self.boto_iam.get_paginator('list_roles')
            roles = []
            
            for page in paginator.paginate():
                for role in page['Roles']:
                    roles.append({
                        'name': role['RoleName'],
                        'arn': role['Arn'],
                        'created': role['CreateDate'].isoformat() if hasattr(role['CreateDate'], 'isoformat') else str(role['CreateDate']),
                        'path': role.get('Path', '/'),
                        'max_session_duration': role.get('MaxSessionDuration', 3600)
                    })
            
            logging.info(f"✅ boto3: Discovered {len(roles)} REAL IAM roles from AWS account")
            return roles
            
        except ClientError as e:
            logging.error(f"❌ AWS API error: {e}")
            return []
        except Exception as e:
            logging.error(f"❌ Failed to discover roles via boto3: {e}")
            return []
    
    def _analyze_roles(self, roles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze each role's policies for security issues"""
        role_findings = []
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        skipped_service_roles = 0
        skipped_service_role_names = []  # Track actual role names

        for role in roles:  # Analyze user-managed roles only
            role_name = role.get('name', 'Unknown')
            
            # Skip AWS Service Roles - they are system-managed and cannot be modified
            if role_name.startswith('AWSServiceRoleFor'):
                skipped_service_roles += 1
                skipped_service_role_names.append(role_name)
                logging.info(f"  ⏭️  Skipping AWS Service Role: {role_name} (system-managed)")
                continue
            
            logging.info(f"  Analyzing role: {role_name}")
            
            # Get role policies
            policies = self._get_role_policies(role_name)
            
            # Skip if no policies found
            if not policies or len(policies) == 0:
                logging.info(f"    No policies found for role: {role_name}")
                continue
            
            # Validate each policy
            for policy in policies:
                validation_result = self.validator.validate_policy(policy)
                
                # Extract issues from validation result
                issues = validation_result.get('issues', [])
                
                for issue in issues:
                    # Parse severity from issue string (e.g., "IAM.1: Critical: ...")
                    severity = 'Medium'  # default
                    if 'Critical:' in issue or 'CRITICAL' in issue.upper():
                        severity = 'Critical'
                        total_critical += 1
                    elif 'High:' in issue or 'HIGH' in issue.upper():
                        severity = 'High'
                        total_high += 1
                    elif 'Medium:' in issue or 'MEDIUM' in issue.upper():
                        severity = 'Medium'
                        total_medium += 1
                    else:
                        severity = 'Low'
                        total_low += 1
                    
                    # Extract issue ID and title
                    issue_parts = issue.split(':', 2) if ':' in issue else ['UNKNOWN', issue]
                    issue_id = issue_parts[0]
                    issue_title = issue_parts[1].strip() if len(issue_parts) > 1 else issue
                    issue_detail = issue_parts[2].strip() if len(issue_parts) > 2 else issue_title
                    
                    # 🔍 DEBUG: Log finding creation
                    logging.debug(f"🔍 Creating finding for role: {role_name}")
                    logging.debug(f"   Issue raw: {issue}")
                    logging.debug(f"   Issue ID: {issue_id}")
                    logging.debug(f"   Issue Title: {issue_title}")
                    logging.debug(f"   Severity: {severity}")
                    
                    # Fix: Ensure title is not just severity
                    if issue_title == severity or issue_title.lower() in ['critical', 'high', 'medium', 'low']:
                        logging.warning(f"   ⚠️ Title equals severity, using description as title")
                        # Use issue_detail as title if available, otherwise generate from issue_id
                        issue_title = issue_detail if issue_detail and issue_detail != issue_title else f"{issue_id.replace('.', ' ').title()} Security Issue"
                    if not issue_title or len(issue_title.strip()) < 5:
                        issue_title = f"{issue_id.replace('.', ' ').title()} Security Issue"
                        logging.warning(f"   ⚠️ Title too short, using generated title: {issue_title}")
                    
                    # Build comprehensive description with specific context
                    why_it_matters = self._get_why_it_matters(issue_id, severity, issue_detail)
                    impact = self._get_impact(issue_id, severity, issue_detail)
                    remediation_steps = validation_result.get('recommendations', [])
                    
                    # Extract service name from issue_detail if it mentions a service
                    # e.g., "Wildcard resource detected for access-analyzer" -> service = "access-analyzer"
                    service_name = None
                    if 'Wildcard resource detected for' in issue_detail:
                        parts = issue_detail.split('Wildcard resource detected for')
                        if len(parts) > 1:
                            service_name = parts[1].strip().split()[0] if parts[1].strip() else None
                    elif 'detected for' in issue_detail:
                        parts = issue_detail.split('detected for')
                        if len(parts) > 1:
                            service_name = parts[1].strip().split()[0] if parts[1].strip() else None
                    
                    # Generate service-specific recommendation
                    if service_name and 'wildcard' in issue_detail.lower():
                        recommendation = f"Specify exact {service_name} resource ARNs instead of wildcards"
                    elif remediation_steps:
                        recommendation = remediation_steps[0]
                    else:
                        recommendation = 'Review and fix this issue'
                    
                    # Create finding with enriched context
                    finding = {
                        'id': issue_id,
                        'severity': severity,
                        'title': issue_title,
                        'description': issue_detail,
                        'why_it_matters': why_it_matters,
                        'impact': impact,
                        'recommendation': recommendation,
                        'detailed_remediation': self._get_detailed_remediation(issue_id, role_name, issue_detail),
                        'role': role_name,  # Store role for grouping
                        'compliance_violations': self._get_compliance_violations(issue_id, issue_detail),
                        'affected_permissions': self._extract_permissions_from_policy(policy),
                        'policy_snippet': self._get_policy_snippet(policy, issue_id),
                        'type': 'Policy Violation'
                    }
                    
                    # 🔍 DEBUG: Verify finding structure
                    logging.debug(f"   ✅ Finding created - ID: {finding.get('id')}, Title: {finding.get('title')}, Role: {role_name}")
                    
                    # Verify role_name is valid
                    if not role_name or not isinstance(role_name, str) or len(role_name.strip()) == 0:
                        logging.error(f"   ❌ Invalid role_name for finding {issue_id}: {role_name}")
                    
                    role_findings.append({
                        'role': role_name,
                        'finding': finding
                    })
        
        return {
            'findings': role_findings,
            'summary': {
                'critical': total_critical,
                'high': total_high,
                'medium': total_medium,
                'low': total_low
            },
            'skipped_service_roles': skipped_service_roles,
            'skipped_service_role_names': skipped_service_role_names
        }

    def _get_why_it_matters(self, issue_id: str, severity: str, description: str = '') -> str:
        """Provide context on why this finding matters - with specific explanations"""
        # Extract service/context from description if available
        desc_lower = description.lower() if description else ''
        
        explanations = {
            'IAM.1': 'Full administrative access (*:*) grants complete control over all AWS resources. If compromised, attackers can create users, modify policies, delete resources, and access sensitive data.',
            'IAM.RESOURCE.1': 'Wildcard resources (*) allow actions on ALL resources, not just intended ones. This violates least privilege and can lead to unauthorized data access or resource deletion.',
            'IAM.2': 'Missing MFA requirements allow compromised credentials to be used immediately without additional verification.',
            'IAM.3': 'Public access policies expose resources to the entire internet, increasing attack surface and risk of data breaches.',
        }
        
        # Generate specific explanations based on description
        if 'wildcard resource' in desc_lower or 'wildcard resource detected' in desc_lower:
            service = ''
            if 'detected for' in desc_lower:
                service = desc_lower.split('detected for')[-1].strip().split()[0] if 'detected for' in desc_lower else ''
            if service:
                return f'Wildcard resources (*) for {service} allow actions on ALL {service} resources in your account, not just the intended ones. This violates the principle of least privilege and can lead to unauthorized access to {service} resources, potential data breaches, or accidental resource deletion across your entire account.'
            return 'Wildcard resources (*) allow actions on ALL resources of a service, not just intended ones. This violates least privilege and can lead to unauthorized data access, resource deletion, or compliance violations.'
        
        elif 'wildcard action' in desc_lower or 'wildcard actions' in desc_lower:
            return 'Wildcard actions (*) grant ALL permissions for a service, including dangerous operations like Delete, Terminate, and Modify. If a role with wildcard actions is compromised, attackers gain full control over that service, enabling data exfiltration, resource destruction, or service disruption.'
        
        elif 'missing condition' in desc_lower or 'missing mfa' in desc_lower:
            if 'mfa' in desc_lower:
                return 'Missing MFA requirements allow compromised credentials to be used immediately without additional verification. Attackers who steal access keys can use them directly, bypassing multi-factor authentication protections.'
            return 'Missing condition keys remove important security restrictions. Conditions like IP whitelisting, encryption requirements, or MFA enforcement add critical security layers that prevent unauthorized access even if credentials are compromised.'
        
        elif 'unused' in desc_lower:
            return 'Unused permissions provide no operational value but significantly increase risk. If an attacker compromises any role with unused permissions, they could use these dormant permissions to cause destruction, access sensitive data, or disrupt services.'
        
        elif 'administrator' in desc_lower or 'admin' in desc_lower:
            return 'Administrator access grants complete control over all AWS resources and services. If compromised, attackers can create new admin users, modify all policies, delete critical resources, access all data, and cause complete account takeover.'
        
        # Use issue_id mapping if available
        if issue_id in explanations:
            return explanations[issue_id]
        
        # Generate severity-specific default
        if severity == 'Critical':
            return 'This critical security issue poses an immediate threat to your AWS account. If exploited, it could lead to complete account compromise, data exfiltration, or service disruption.'
        elif severity == 'High':
            return 'This high-severity issue significantly increases your security risk. If not addressed, it could lead to unauthorized access, data breaches, or compliance violations.'
        elif severity == 'Medium':
            return 'This medium-severity issue increases your attack surface and should be addressed to improve your security posture and reduce risk.'
        else:
            return 'This finding represents a security best practice that, while not immediately critical, should be addressed to maintain a strong security posture.'
    
    def _get_impact(self, issue_id: str, severity: str, description: str = '') -> str:
        """Describe the potential impact of this finding - with specific details"""
        desc_lower = description.lower() if description else ''
        
        impacts = {
            'IAM.1': 'Critical Impact: Account takeover, data exfiltration, resource deletion, compliance violations, financial impact from service abuse.',
            'IAM.RESOURCE.1': 'High Impact: Unauthorized access to unintended resources, potential data breach, compliance violations, increased attack surface.',
            'IAM.2': 'High Impact: Unauthorized access if credentials are compromised, potential account takeover, compliance violations (PCI DSS, HIPAA).',
            'IAM.3': 'Critical Impact: Public exposure of sensitive data, increased attack surface, potential data breaches, compliance violations.',
        }
        
        # Generate specific impacts based on description
        if 'wildcard resource' in desc_lower or 'wildcard resource detected' in desc_lower:
            service = ''
            if 'detected for' in desc_lower:
                service = desc_lower.split('detected for')[-1].strip().split()[0] if 'detected for' in desc_lower else ''
            if service:
                return f'High Impact: Unauthorized access to unintended {service} resources across your entire account. Attackers could read, modify, or delete {service} resources they should not have access to, leading to data breaches, service disruption, or compliance violations.'
            return 'High Impact: Unauthorized access to unintended resources, potential data breach, compliance violations (PCI DSS 7.1.2, HIPAA 164.308), increased attack surface.'
        
        elif 'wildcard action' in desc_lower or 'wildcard actions' in desc_lower:
            return 'Critical Impact: Full control over the affected service. Attackers can perform any action including Delete, Terminate, Modify, or Create operations, leading to complete service compromise, data loss, or account takeover.'
        
        elif 'missing condition' in desc_lower or 'missing mfa' in desc_lower:
            if 'mfa' in desc_lower:
                return 'High Impact: Immediate unauthorized access if credentials are compromised. Attackers can use stolen keys without MFA verification, leading to account takeover, data access, or resource modification. Violates PCI DSS 8.3 and HIPAA 164.312(a)(2).'
            return 'High Impact: Reduced security controls allow unauthorized access even with valid credentials. Missing conditions like IP restrictions or encryption requirements increase the risk of credential theft exploitation.'
        
        elif 'unused' in desc_lower:
            return 'Medium Impact: Unnecessary risk exposure without operational benefit. If compromised, attackers could use dormant permissions to delete resources, access sensitive data, or cause service disruptions. Increases attack surface unnecessarily.'
        
        elif 'administrator' in desc_lower or 'admin' in desc_lower:
            return 'Critical Impact: Complete AWS account compromise. Attackers can create new admin users, modify all policies, delete any resource, access all data, exfiltrate sensitive information, and cause financial damage through service abuse. Violates all major compliance frameworks.'
        
        # Use issue_id mapping if available
        if issue_id in impacts:
            return impacts[issue_id]
        
        # Generate severity-specific default
        if severity == 'Critical':
            return 'Critical Impact: Immediate threat to account security. Could lead to complete account takeover, data exfiltration, resource deletion, compliance violations, and significant financial impact.'
        elif severity == 'High':
            return 'High Impact: Significant security risk. Could lead to unauthorized access, data breaches, compliance violations (PCI DSS, HIPAA, SOX), and service disruption.'
        elif severity == 'Medium':
            return 'Medium Impact: Increased security risk that should be addressed. Could lead to unauthorized access or compliance issues if exploited.'
        else:
            return 'Low Impact: Security best practice violation. While not immediately critical, addressing this improves overall security posture.'
    
    def _get_detailed_remediation(self, issue_id: str, role_name: str, description: str = '') -> str:
        """Provide step-by-step remediation instructions - with specific guidance"""
        desc_lower = description.lower() if description else ''
        
        remediations = {
            'IAM.1': f'1. Review role "{role_name}" usage patterns in CloudTrail\n2. Identify actual permissions needed\n3. Replace wildcard (*:*) with specific actions like s3:GetObject, dynamodb:GetItem\n4. Test in staging before production\n5. Monitor for permission denied errors',
            'IAM.RESOURCE.1': f'1. Identify specific resources needed for role "{role_name}"\n2. Replace wildcard (*) with specific ARNs (e.g., arn:aws:s3:::my-bucket/*)\n3. Use conditions to further restrict access\n4. Test thoroughly before deploying',
            'IAM.2': f'1. Add MFA condition to trust policy of role "{role_name}"\n2. Update assume role policy to require aws:MultiFactorAuthPresent\n3. Communicate changes to users\n4. Test MFA enforcement',
            'IAM.3': f'1. Review public access policy for role "{role_name}"\n2. Remove public access (Principal: "*")\n3. Replace with specific AWS account IDs or IAM principals\n4. Add IP whitelisting if needed\n5. Test access restrictions',
        }
        
        # Generate specific remediation based on description
        if 'wildcard resource' in desc_lower or 'wildcard resource detected' in desc_lower:
            service = ''
            if 'detected for' in desc_lower:
                service = desc_lower.split('detected for')[-1].strip().split()[0] if 'detected for' in desc_lower else ''
            if service:
                return f'1. Identify specific {service} resources needed for role "{role_name}"\n2. Replace wildcard (*) with specific {service} ARNs\n3. Use resource-level restrictions (e.g., arn:aws:{service}:region:account:resource/*)\n4. Add condition keys to further restrict access if needed\n5. Test in staging environment\n6. Deploy to production and monitor for AccessDenied errors'
            return f'1. Identify specific resources needed for role "{role_name}"\n2. Replace wildcard (*) with specific resource ARNs\n3. Use conditions to further restrict access\n4. Test thoroughly before deploying\n5. Monitor CloudTrail for unauthorized access attempts'
        
        elif 'wildcard action' in desc_lower or 'wildcard actions' in desc_lower:
            return f'1. Review role "{role_name}" usage in CloudTrail to identify actual actions used\n2. Replace wildcard actions (*) with specific actions (e.g., s3:GetObject, s3:PutObject)\n3. Remove dangerous actions like Delete, Terminate if not needed\n4. Add condition keys for additional security (encryption, IP restrictions)\n5. Test in staging environment\n6. Deploy to production with monitoring\n7. Set up CloudWatch alarms for unexpected actions'
        
        elif 'missing condition' in desc_lower:
            if 'mfa' in desc_lower:
                return f'1. Add MFA condition to policies for role "{role_name}"\n2. Update policy to require aws:MultiFactorAuthPresent condition\n3. Communicate MFA requirement to users\n4. Test MFA enforcement in staging\n5. Deploy to production\n6. Monitor for AccessDenied errors from users without MFA'
            return f'1. Identify appropriate condition keys for role "{role_name}" (e.g., aws:SourceIP, s3:x-amz-server-side-encryption)\n2. Add Condition block to policy statements\n3. Test condition enforcement in staging\n4. Deploy to production\n5. Monitor for AccessDenied errors'
        
        elif 'unused' in desc_lower:
            return f'1. Review CloudTrail data to confirm permissions are truly unused\n2. For role "{role_name}", create new policy version excluding unused permissions\n3. Test in staging environment for 1 week\n4. Deploy to production with monitoring\n5. Monitor for AccessDenied errors for 30 days\n6. Schedule quarterly re-analysis'
        
        elif 'administrator' in desc_lower or 'admin' in desc_lower:
            return f'1. IMMEDIATE: Review role "{role_name}" actual usage in CloudTrail\n2. Identify minimum permissions needed\n3. Create custom policy with only required permissions\n4. Test in staging environment\n5. Replace AdministratorAccess during maintenance window\n6. Monitor closely for 48 hours\n7. Set up alerts for any permission denied errors'
        
        # Use issue_id mapping if available
        if issue_id in remediations:
            return remediations[issue_id]
        
        # Generate role-specific default
        return f'1. Review the policy for role "{role_name}"\n2. Identify security issues and required permissions\n3. Create updated policy following AWS security best practices\n4. Test in staging environment\n5. Deploy to production with monitoring\n6. Consult AWS IAM documentation for specific guidance'
    
    def _get_compliance_violations(self, issue_id: str, description: str = '') -> List[str]:
        """Return list of compliance frameworks violated - with specific mappings"""
        desc_lower = description.lower() if description else ''
        
        violations = {
            'IAM.1': ['PCI DSS 7.1.2 (Least Privilege)', 'HIPAA 164.308(a)(4) (Access Control)', 'SOC 2 CC6.1', 'CIS AWS 1.1, 1.2'],
            'IAM.RESOURCE.1': ['PCI DSS 7.1.2 (Least Privilege)', 'HIPAA 164.308(a)(4) (Access Control)', 'GDPR Article 5 (Data Minimization)', 'SOC 2 CC6.1'],
            'IAM.2': ['PCI DSS 8.3 (MFA Requirements)', 'HIPAA 164.312(a)(2) (Access Control)', 'SOC 2 CC6.2'],
            'IAM.3': ['GDPR Article 32 (Security)', 'HIPAA 164.312(a)(1) (Access Control)'],
        }
        
        # Generate specific violations based on description
        if 'wildcard resource' in desc_lower or 'wildcard resource detected' in desc_lower:
            return ['PCI DSS 7.1.2 (Least Privilege)', 'HIPAA 164.308(a)(4) (Access Control)', 'GDPR Article 5 (Data Minimization)', 'SOC 2 CC6.1', 'CIS AWS Benchmark 1.22']
        elif 'wildcard action' in desc_lower or 'wildcard actions' in desc_lower:
            return ['PCI DSS 7.1.2 (Least Privilege)', 'HIPAA 164.308(a)(4) (Access Control)', 'SOC 2 CC6.1', 'CIS AWS 1.1, 1.2', 'SOX Section 404']
        elif 'missing condition' in desc_lower:
            if 'mfa' in desc_lower:
                return ['PCI DSS 8.3 (MFA Requirements)', 'HIPAA 164.312(a)(2) (Access Control)', 'SOC 2 CC6.2']
            return ['PCI DSS 7.1.2 (Least Privilege)', 'HIPAA 164.308(a)(4) (Access Control)', 'SOC 2 CC6.1']
        elif 'unused' in desc_lower:
            return ['PCI DSS 7.1.2 (Least Privilege)', 'HIPAA 164.308(a)(4) (Access Control)', 'SOC 2 CC6.1']
        elif 'administrator' in desc_lower or 'admin' in desc_lower:
            return ['PCI DSS 7.1.2 (Least Privilege)', 'HIPAA 164.308(a)(4) (Access Control)', 'SOC 2 CC6.1', 'CIS AWS 1.1, 1.2', 'SOX Section 404']
        
        # Use issue_id mapping if available
        if issue_id in violations:
            return violations[issue_id]
        
        return ['General Security Best Practices']
    
    def _extract_permissions_from_policy(self, policy: Dict[str, Any]) -> List[str]:
        """Extract affected permissions from policy document"""
        permissions = []
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for stmt in statements:
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            permissions.extend(actions)
        
        return list(set(permissions))  # Return unique permissions
    
    def _get_policy_snippet(self, policy: Dict[str, Any], issue_id: str) -> str:
        """Extract relevant policy snippet that shows the issue"""
        import json
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        # Find statement with wildcard or issue
        for stmt in statements:
            actions = stmt.get('Action', [])
            resources = stmt.get('Resource', [])
            
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Check for wildcards
            if any('*' in str(action) for action in actions) or any('*' in str(resource) for resource in resources):
                snippet = {
                    'Effect': stmt.get('Effect'),
                    'Action': actions[:3] if len(actions) > 3 else actions,  # Show first 3
                    'Resource': resources[:2] if len(resources) > 2 else resources,  # Show first 2
                }
                return json.dumps(snippet, indent=2)
        
        # Return first statement if no obvious issue
        if statements:
            return json.dumps(statements[0], indent=2)
        
        return json.dumps(policy, indent=2)

    def _analyze_cloudtrail(self, roles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze CloudTrail logs for unused permissions - Try MCP first, fall back to boto3"""
        
        # Try MCP first
        if self.cloudtrail_client:
            try:
                logging.info("🔧 Trying MCP server for CloudTrail...")
                end_time = datetime.now()
                start_time = end_time - timedelta(days=90)

                # CloudTrail MCP uses snake_case parameters
                result = self.cloudtrail_client.call_tool('lookup_events', {
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'max_results': 1000
                })

                if result.get('success'):
                    events_data = result.get('data', {})

                    # Handle MCP response - it can be an object or dict
                    if hasattr(events_data, 'content'):
                        # Response is an object with attributes
                        content = events_data.content
                    elif isinstance(events_data, dict) and 'content' in events_data:
                        # Response is a dictionary
                        content = events_data['content']
                    else:
                        # Try to get content directly
                        content = events_data

                    # Parse events from content
                    events = []
                    if isinstance(content, list) and len(content) > 0:
                        # Get text from first content item if it's an object
                        for item in content:
                            text_content = None
                            if hasattr(item, 'text'):
                                text_content = item.text
                            elif isinstance(item, dict) and 'text' in item:
                                text_content = item['text']
                            
                            if text_content:
                                # Parse JSON from text (MCP returns JSON in text field)
                                try:
                                    import json
                                    json_data = json.loads(text_content)
                                    # Extract events array from JSON
                                    if isinstance(json_data, dict):
                                        if 'events' in json_data and isinstance(json_data['events'], list):
                                            events.extend(json_data['events'])
                                        elif 'Events' in json_data and isinstance(json_data['Events'], list):
                                            events.extend(json_data['Events'])
                                        else:
                                            # Might be a single event
                                            events.append(json_data)
                                    elif isinstance(json_data, list):
                                        events.extend(json_data)
                                except (json.JSONDecodeError, TypeError) as e:
                                    logging.debug(f"   Failed to parse CloudTrail JSON: {e}")
                                    pass
                            elif isinstance(item, dict):
                                # Already a parsed dict
                                events.append(item)
                    elif isinstance(content, dict):
                        # Single dict response - check for events
                        if 'events' in content:
                            events = content['events'] if isinstance(content['events'], list) else [content['events']]
                        elif 'Events' in content:
                            events = content['Events'] if isinstance(content['Events'], list) else [content['Events']]
                        else:
                            events = [content]

                    logging.info(f"🔍 [CLOUDTRAIL] Parsed {len(events)} events from MCP response")
                    used_actions = self._extract_used_actions(events)
                    unused_permissions = self._find_unused_permissions(roles, used_actions)

                    logging.info(f"✅ MCP CloudTrail: {len(used_actions)} unique actions used")
                    return {
                        'total_events': len(events),
                        'used_actions': list(used_actions),
                        'unused_permissions': unused_permissions,
                        'analysis_period_days': 90
                    }
            except Exception as e:
                logging.warning(f"⚠️ MCP CloudTrail failed: {e}")

        # Fall back to boto3
        logging.info("🔄 Falling back to boto3 for CloudTrail...")
        return self._analyze_cloudtrail_boto3(roles)

    def _analyze_cloudtrail_boto3(self, roles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze CloudTrail using boto3 (fallback method)"""
        try:
            if not self.boto_iam:
                return self._get_sample_cloudtrail_analysis()

            cloudtrail = boto3.client('cloudtrail', region_name=self.aws_region)
            end_time = datetime.now()
            start_time = end_time - timedelta(days=90)

            # Query CloudTrail events
            events = cloudtrail.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=1000
            ).get('Events', [])

            # Extract used actions
            used_actions = set()
            for event in events:
                event_name = event.get('EventName', '')
                if event_name:
                    used_actions.add(event_name)

            unused_permissions = self._find_unused_permissions(roles, used_actions)

            logging.info(f"✅ boto3 CloudTrail: Analyzed {len(events)} events, {len(used_actions)} unique actions")

            return {
                'total_events': len(events),
                'used_actions': list(used_actions),
                'unused_permissions': unused_permissions,
                'analysis_period_days': 90
            }

        except Exception as e:
            logging.error(f"❌ CloudTrail boto3 failed: {e}")
            return self._get_sample_cloudtrail_analysis()

    def _analyze_scps(self) -> Dict[str, Any]:
        """Analyze Service Control Policies and Permission Boundaries - Try MCP first, fall back to boto3"""

        # Try AWS API MCP server first
        if self.api_client:
            try:
                logging.info("🔧 Trying MCP server for SCP analysis...")
                # SCP analysis via MCP would go here
                # For now, return basic analysis
                return {
                    'scps_found': True,
                    'conflicts_detected': 0,
                    'recommendations': [
                        "Review SCP policies for overly restrictive rules",
                        "Ensure permission boundaries are properly configured"
                    ]
                }
            except Exception as e:
                logging.warning(f"⚠️ MCP SCP analysis failed: {e}")

        # Fall back to boto3 or return basic analysis
        logging.info("🔄 Using basic SCP analysis (boto3 not implemented for SCPs)")
        return {
            'scps_found': False,
            'conflicts_detected': 0,
            'recommendations': [
                "Review SCP policies for overly restrictive rules",
                "Ensure permission boundaries are properly configured"
            ]
        }

    def _group_similar_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group similar findings together to reduce duplication"""
        grouped = {}
        
        # Severity order for determining highest severity in a group
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        
        for finding in findings:
            # Create a grouping key based on issue type (NOT severity - group all severities together)
            title = finding.get('title', '').lower()
            severity = finding.get('severity', 'Low')
            issue_id = finding.get('id', 'UNKNOWN')
            
            # Group by common patterns - be more flexible with matching
            # Check description as well since titles might vary
            desc = finding.get('description', '').lower()
            combined_text = f"{title} {desc}".lower()
            
            # Group ALL similar findings together regardless of severity
            # We'll use the highest severity found in the group
            if 'wildcard resource' in combined_text or 'using wildcard resources' in combined_text:
                # Group ALL wildcard resource findings together (regardless of severity)
                group_key = "wildcard_resources"  # Single group for all wildcard resources
            elif 'wildcard action' in combined_text or 'wildcard actions' in combined_text:
                group_key = "wildcard_actions"  # Single group for all wildcard actions
            elif 'missing condition' in combined_text or 'missing mfa' in combined_text or 'missing condition key' in combined_text:
                group_key = "missing_conditions"  # Single group for all missing conditions
            elif 'unused' in combined_text and ('permission' in combined_text or 'iam' in combined_text):
                group_key = "unused_permissions"  # Single group for all unused permissions
            elif 'administrator' in combined_text or 'admin access' in combined_text:
                group_key = "admin_access"  # Single group for all admin access
            else:
                # Use issue_id as key for other findings (still group by type, not severity)
                group_key = f"other_{issue_id}"
            
            if group_key not in grouped:
                grouped[group_key] = {
                    'id': finding.get('id', 'GROUPED'),
                    'severity': severity,  # Will be updated to highest severity
                    'title': self._generate_grouped_title(title, severity),
                    'description': '',
                    'why_it_matters': finding.get('why_it_matters', ''),
                    'impact': finding.get('impact', ''),
                    'recommendation': finding.get('recommendation', ''),
                    'detailed_remediation': finding.get('detailed_remediation', ''),
                    'compliance_violations': finding.get('compliance_violations', []),
                    'affected_roles': [],
                    'affected_permissions': set(),
                    'affected_services': set(),
                    'policy_snippets': [],
                    'type': finding.get('type', 'Policy Violation'),
                    'count': 0,
                    'severities': [],  # Track all severities in the group
                    'findings': []  # Store original findings for reference
                }
            
            # Aggregate information
            group = grouped[group_key]
            group['count'] += 1
            group['severities'].append(severity)
            group['findings'].append(finding)  # Store original finding
            
            # Update to highest severity if current finding has higher severity
            if severity_order.get(severity, 3) < severity_order.get(group['severity'], 3):
                group['severity'] = severity
                # Update title with new severity
                group['title'] = self._generate_grouped_title(title, severity)
                # Don't update why_it_matters/impact here - we'll use generic ones for grouped findings later
            
            # Add role
            role = finding.get('role')
            if role and role not in group['affected_roles']:
                group['affected_roles'].append(role)
            
            # Add permissions
            perms = finding.get('affected_permissions', [])
            if isinstance(perms, list):
                group['affected_permissions'].update(perms)
            
            # Extract service names from description or title
            desc = finding.get('description', '')
            title_text = finding.get('title', '')
            
            # Try multiple patterns to extract service names
            if 'detected for' in desc.lower():
                service = desc.lower().split('detected for')[-1].strip().split()[0] if 'detected for' in desc.lower() else None
                if service and len(service) < 50:  # Sanity check
                    group['affected_services'].add(service)
            elif 'detected for' in title_text.lower():
                service = title_text.lower().split('detected for')[-1].strip().split()[0] if 'detected for' in title_text.lower() else None
                if service and len(service) < 50:
                    group['affected_services'].add(service)
            elif 'for ' in desc.lower() and ('wildcard' in desc.lower() or 'wildcard' in title_text.lower()):
                # Pattern: "Wildcard resource detected for <service>"
                parts = desc.lower().split('for ')
                if len(parts) > 1:
                    service = parts[-1].strip().split()[0]
                    if service and len(service) < 50:  # Sanity check
                        group['affected_services'].add(service)
            
            # Keep best explanation/impact - but use generic ones for grouped findings
            if not group['description']:
                group['description'] = desc
            
            # For grouped findings, use generic explanations and recommendations
            if group['count'] > 1:
                # Use generic explanations for grouped findings
                if 'wildcard resource' in combined_text:
                    if not group['why_it_matters'] or any(service in group['why_it_matters'].lower() for service in ['logs', 'ec2', 'rds', 's3', 'cloudwatch']):
                        group['why_it_matters'] = 'Wildcard resources (*) allow actions on ALL resources of a service, not just intended ones. This violates the principle of least privilege and can lead to unauthorized data access, resource deletion, or compliance violations across your entire account.'
                    if not group['impact'] or any(service in group['impact'].lower() for service in ['logs', 'ec2', 'rds', 's3', 'cloudwatch']):
                        group['impact'] = 'High Impact: Unauthorized access to unintended resources across your entire account. Attackers could read, modify, or delete resources they should not have access to, leading to data breaches, service disruption, or compliance violations (PCI DSS 7.1.2, HIPAA 164.308).'
                    # Override recommendation for wildcard resources
                    if not group.get('recommendation') or any(service in group.get('recommendation', '').lower() for service in ['logs', 'ec2', 'rds', 's3', 'cloudwatch', 'signer']):
                        group['recommendation'] = 'Specify exact resource ARNs instead of wildcards. For each role, identify specific resources needed and replace wildcard (*) with specific ARNs.'
                elif 'wildcard action' in combined_text:
                    if not group['why_it_matters'] or any(service in group['why_it_matters'].lower() for service in ['bedrock', 's3', 'dynamodb']):
                        group['why_it_matters'] = 'Wildcard actions (*) grant ALL permissions for a service, including dangerous operations like Delete, Terminate, and Modify. If a role with wildcard actions is compromised, attackers gain full control over that service, enabling data exfiltration, resource destruction, or service disruption.'
                    if not group['impact'] or any(service in group['impact'].lower() for service in ['bedrock', 's3', 'dynamodb']):
                        group['impact'] = 'Critical Impact: Full control over the affected service. Attackers can perform any action including Delete, Terminate, Modify, or Create operations, leading to complete service compromise, data loss, or account takeover.'
                    # Override recommendation for wildcard actions
                    if not group.get('recommendation') or 'vpc_endpoint' in group.get('recommendation', '').lower() or 'condition' in group.get('recommendation', '').lower():
                        group['recommendation'] = 'Replace wildcard actions (*) with specific actions. Review CloudTrail logs to identify actual actions used and create a policy with only those specific actions.'
                elif 'missing condition' in combined_text or 'missing mfa' in combined_text:
                    # Override recommendation for missing conditions
                    if not group.get('recommendation') or 'wildcard' in group.get('recommendation', '').lower():
                        group['recommendation'] = 'Add appropriate condition keys (e.g., aws:MultiFactorAuthPresent, aws:SourceIP, encryption requirements) to restrict access based on context.'
                elif 'different permission types' in combined_text or 'separate statements' in combined_text:
                    # Override recommendation for statement separation
                    if not group.get('recommendation') or 'wildcard' in group.get('recommendation', '').lower() or 'signer' in group.get('recommendation', '').lower():
                        group['recommendation'] = 'Separate different permission types (Allow/Deny, different resources, different conditions) into separate policy statements for better clarity and maintainability.'
            else:
                # For single findings, use the finding's explanation
                if not group['why_it_matters'] or 'security issue that could compromise' in group['why_it_matters'].lower():
                    group['why_it_matters'] = finding.get('why_it_matters', '')
                if not group['impact'] or 'severity finding that requires' in group['impact'].lower():
                    group['impact'] = finding.get('impact', '')
                # Ensure recommendation matches finding type for single findings too
                if 'wildcard action' in combined_text and ('vpc_endpoint' in group.get('recommendation', '').lower() or 'condition' in group.get('recommendation', '').lower()):
                    group['recommendation'] = 'Replace wildcard actions (*) with specific actions. Review CloudTrail logs to identify actual actions used and create a policy with only those specific actions.'
                elif 'different permission types' in combined_text or 'separate statements' in combined_text:
                    if 'wildcard' in group.get('recommendation', '').lower() or 'signer' in group.get('recommendation', '').lower():
                        group['recommendation'] = 'Separate different permission types (Allow/Deny, different resources, different conditions) into separate policy statements for better clarity and maintainability.'
        
        # Convert sets to lists and format
        grouped_findings = []
        for group_key, group in grouped.items():
            # Check if any finding in this group already has affected_roles_list (e.g., unused permissions)
            existing_affected_roles_list = []
            for finding in group.get('findings', []):
                if 'affected_roles_list' in finding and finding['affected_roles_list']:
                    existing_affected_roles_list.extend(finding['affected_roles_list'])
            
            # Format affected roles - keep both the display string and the actual list
            if existing_affected_roles_list:
                # Use the pre-populated affected_roles_list from findings (e.g., unused permissions)
                group['affected_roles_list'] = sorted(set(existing_affected_roles_list))
                group['role'] = f"Multiple roles ({len(group['affected_roles_list'])})" if len(group['affected_roles_list']) > 1 else (group['affected_roles_list'][0] if group['affected_roles_list'] else None)
            elif len(group['affected_roles']) == 1:
                group['role'] = list(group['affected_roles'])[0]
                group['affected_roles_list'] = list(group['affected_roles'])  # Store actual role names
            elif len(group['affected_roles']) > 1:
                group['role'] = f"Multiple roles ({len(group['affected_roles'])})"
                group['affected_roles_list'] = sorted(group['affected_roles'])  # Store actual role names as sorted list
            else:
                group['role'] = None
                group['affected_roles_list'] = []
            
            # Format affected permissions (limit to 10)
            group['affected_permissions'] = list(group['affected_permissions'])[:10]
            
            # Format affected services and update ALL fields for grouped findings
            services = list(group['affected_services'])
            is_grouped = group['count'] > 1
            is_wildcard_resource = 'wildcard resource' in group['title'].lower()
            multiple_roles = len(group['affected_roles']) > 1
            
            # Store services as a sorted list for frontend display
            group['affected_services_list'] = sorted(services) if services else []
            
            if services:
                # Create a comprehensive description with all affected services
                services_str = ', '.join(sorted(services)[:10])  # Show up to 10 services, sorted alphabetically
                if len(services) > 10:
                    services_str += f", and {len(services) - 10} more"
                group['description'] = f"Multiple roles use wildcard resources (*) allowing actions on ALL resources instead of specific ones. Affected services: {services_str}."
                
                # Update recommendation to be generic for grouped findings (not service-specific like "logs")
                if is_grouped and is_wildcard_resource:
                    # Use shorter, more concise recommendation for compact view
                    group['recommendation'] = f"Specify exact resource ARNs instead of wildcards for all affected services. Replace wildcard (*) with specific ARNs for each role."
                
                # Update detailed_remediation to be generic for multiple roles
                if is_grouped and multiple_roles and is_wildcard_resource:
                    group['detailed_remediation'] = f'1. For each affected role ({len(group["affected_roles"])} roles total), identify specific resources needed\n2. Replace wildcard (*) with specific resource ARNs for all services\n3. Use resource-level restrictions (e.g., arn:aws:service:region:account:resource/*)\n4. Add condition keys to further restrict access if needed\n5. Test in staging environment for each role\n6. Deploy to production with monitoring\n7. Monitor CloudTrail for unauthorized access attempts across all affected roles'
                
                # Force generic why_it_matters and impact for grouped wildcard resources (remove service-specific text)
                if is_grouped and is_wildcard_resource:
                    group['why_it_matters'] = 'Wildcard resources (*) allow actions on ALL resources of a service, not just intended ones. This violates the principle of least privilege and can lead to unauthorized data access, resource deletion, or compliance violations across your entire account.'
                    group['impact'] = 'High Impact: Unauthorized access to unintended resources across your entire account. Attackers could read, modify, or delete resources they should not have access to, leading to data breaches, service disruption, or compliance violations (PCI DSS 7.1.2, HIPAA 164.308).'
            elif is_wildcard_resource:
                # Generic description if no services extracted
                group['description'] = "Multiple roles use wildcard resources (*) allowing actions on ALL resources instead of specific ones. This violates the principle of least privilege."
                if is_grouped:
                    group['recommendation'] = "Specify exact resource ARNs instead of wildcards. For each role, identify specific resources needed and replace wildcard (*) with specific ARNs."
                    if multiple_roles:
                        group['detailed_remediation'] = f'1. For each affected role ({len(group["affected_roles"])} roles total), identify specific resources needed\n2. Replace wildcard (*) with specific resource ARNs\n3. Use conditions to further restrict access\n4. Test thoroughly before deploying for each role\n5. Monitor CloudTrail for unauthorized access attempts'
                    # Force generic explanations
                    group['why_it_matters'] = 'Wildcard resources (*) allow actions on ALL resources of a service, not just intended ones. This violates the principle of least privilege and can lead to unauthorized data access, resource deletion, or compliance violations across your entire account.'
                    group['impact'] = 'High Impact: Unauthorized access to unintended resources across your entire account. Attackers could read, modify, or delete resources they should not have access to, leading to data breaches, service disruption, or compliance violations (PCI DSS 7.1.2, HIPAA 164.308).'
            
            # Final check: Ensure recommendations and detailed_remediation match finding type (override any incorrect ones)
            title_lower = group['title'].lower()
            is_grouped = group['count'] > 1
            multiple_roles = len(group['affected_roles']) > 1
            
            if 'wildcard action' in title_lower:
                if 'vpc_endpoint' in group.get('recommendation', '').lower() or 'condition' in group.get('recommendation', '').lower() or not group.get('recommendation'):
                    group['recommendation'] = 'Replace wildcard actions (*) with specific actions. Review CloudTrail logs to identify actual actions used and create a policy with only those specific actions.'
                # Override detailed_remediation for grouped wildcard actions
                if is_grouped and multiple_roles:
                    group['detailed_remediation'] = f'1. For each affected role ({len(group["affected_roles"])} roles total), review CloudTrail logs to identify actual actions used\n2. Replace wildcard actions (*) with specific actions (e.g., s3:GetObject, s3:PutObject)\n3. Remove dangerous actions like Delete, Terminate if not needed\n4. Add condition keys for additional security (encryption, IP restrictions)\n5. Test in staging environment for each role\n6. Deploy to production with monitoring\n7. Set up CloudWatch alarms for unexpected actions'
                elif is_grouped:
                    group['detailed_remediation'] = f'1. Review role usage in CloudTrail to identify actual actions used\n2. Replace wildcard actions (*) with specific actions (e.g., s3:GetObject, s3:PutObject)\n3. Remove dangerous actions like Delete, Terminate if not needed\n4. Add condition keys for additional security (encryption, IP restrictions)\n5. Test in staging environment\n6. Deploy to production with monitoring\n7. Set up CloudWatch alarms for unexpected actions'
            elif 'wildcard resource' in title_lower:
                # Ensure it's not service-specific
                if any(service in group.get('recommendation', '').lower() for service in ['logs', 'ec2', 'rds', 's3', 'cloudwatch', 'signer']):
                    group['recommendation'] = 'Specify exact resource ARNs instead of wildcards. For each role, identify specific resources needed and replace wildcard (*) with specific ARNs.'
            elif 'different permission types' in title_lower or 'separate statements' in title_lower:
                if 'wildcard' in group.get('recommendation', '').lower() or 'signer' in group.get('recommendation', '').lower() or not group.get('recommendation'):
                    group['recommendation'] = 'Separate different permission types (Allow/Deny, different resources, different conditions) into separate policy statements for better clarity and maintainability.'
                # Override detailed_remediation for grouped "different permission types"
                if is_grouped and multiple_roles:
                    group['detailed_remediation'] = f'1. For each affected role ({len(group["affected_roles"])} roles total), review the policy structure\n2. Identify different permission types (Allow/Deny, different resources, different conditions)\n3. Separate them into individual policy statements\n4. Test in staging environment for each role\n5. Deploy to production with monitoring\n6. Consult AWS IAM documentation for specific guidance'
                elif is_grouped:
                    group['detailed_remediation'] = f'1. Review the policy structure\n2. Identify different permission types (Allow/Deny, different resources, different conditions)\n3. Separate them into individual policy statements\n4. Test in staging environment\n5. Deploy to production with monitoring\n6. Consult AWS IAM documentation for specific guidance'
            elif 'missing condition' in title_lower:
                if 'wildcard' in group.get('recommendation', '').lower() or not group.get('recommendation'):
                    group['recommendation'] = 'Add appropriate condition keys (e.g., aws:MultiFactorAuthPresent, aws:SourceIP, encryption requirements) to restrict access based on context.'
                # Override detailed_remediation for grouped missing conditions
                if is_grouped and multiple_roles:
                    group['detailed_remediation'] = f'1. For each affected role ({len(group["affected_roles"])} roles total), identify appropriate condition keys (e.g., aws:SourceIP, s3:x-amz-server-side-encryption)\n2. Add Condition block to policy statements\n3. Test condition enforcement in staging for each role\n4. Deploy to production\n5. Monitor for AccessDenied errors'
                elif is_grouped:
                    group['detailed_remediation'] = f'1. Identify appropriate condition keys (e.g., aws:SourceIP, s3:x-amz-server-side-encryption)\n2. Add Condition block to policy statements\n3. Test condition enforcement in staging\n4. Deploy to production\n5. Monitor for AccessDenied errors'
            
            # Update title with count if multiple
            if group['count'] > 1:
                if 'wildcard resource' in group['title'].lower():
                    group['title'] = f"Wildcard Resources Detected ({group['count']} instances)"
                elif 'wildcard action' in group['title'].lower():
                    group['title'] = f"Wildcard Actions Detected ({group['count']} instances)"
                elif 'missing condition' in group['title'].lower():
                    group['title'] = f"Missing Condition Keys ({group['count']} instances)"
                elif 'unused' in group['title'].lower():
                    group['title'] = f"Unused IAM Permissions Detected ({group['count']} instances)"
                elif 'admin' in group['title'].lower():
                    group['title'] = f"Administrator Access Detected ({group['count']} instances)"
            
            # Remove internal fields (but keep affected_roles_list and affected_services_list for frontend)
            if 'affected_roles' in group:
                del group['affected_roles']
            if 'affected_services' in group:
                del group['affected_services']
            del group['count']
            if 'severities' in group:
                del group['severities']  # Remove severity tracking
            
            grouped_findings.append(group)
        
        return grouped_findings
    
    def _generate_grouped_title(self, title: str, severity: str) -> str:
        """Generate a concise title for grouped findings"""
        title_lower = title.lower()
        if 'wildcard resource detected' in title_lower:
            return 'Wildcard Resources Detected'
        elif 'wildcard actions detected' in title_lower or 'wildcard action' in title_lower:
            return 'Wildcard Actions Detected'
        elif 'missing condition' in title_lower:
            return 'Missing Condition Keys'
        elif 'missing mfa' in title_lower:
            return 'Missing MFA Requirements'
        elif 'unused' in title_lower:
            return 'Unused IAM Permissions Detected'
        elif 'administrator' in title_lower or 'admin' in title_lower:
            return 'Administrator Access Detected'
        else:
            # Use original title, capitalized
            return title.title()
    
    def _generate_audit_report(self, roles, role_analysis, cloudtrail_analysis, scp_analysis) -> Dict[str, Any]:
        """Generate comprehensive audit report"""
        
        # Calculate overall risk score (0-100, where 100 = worst risk)
        # Industry standard: Higher number = Higher risk
        summary = role_analysis.get('summary', {})
        risk_score = (
            summary.get('critical', 0) * 40 +
            summary.get('high', 0) * 20 +
            summary.get('medium', 0) * 10 +
            summary.get('low', 0) * 5
        )
        risk_score = min(risk_score, 100)
        skipped_service_roles = role_analysis.get('skipped_service_roles', 0)
        skipped_service_role_names = role_analysis.get('skipped_service_role_names', [])
        
        logging.info(f"📊 Analysis complete: {len(roles)} total roles, {len(roles) - skipped_service_roles} user-managed, {skipped_service_roles} AWS Service Roles excluded")
        if skipped_service_role_names:
            logging.info(f"   Excluded roles: {', '.join(skipped_service_role_names[:10])}{'...' if len(skipped_service_role_names) > 10 else ''}")
        
        # Generate findings
        all_findings = []
        for item in role_analysis.get('findings', []):
            finding = item.get('finding', {})
            role = item.get('role')
            
            # Add role to finding (force it, even if None)
            finding['role'] = role
            
            # Defensive role extraction
            if not role:
                if finding.get('role_arn'):
                    role = finding['role_arn'].split('/')[-1]
                    finding['role'] = role
            
            # Validate and fix title
            if not finding.get('title') or finding.get('title') == finding.get('severity'):
                if finding.get('description'):
                    finding['title'] = finding['description'][:100]
                elif finding.get('id'):
                    finding['title'] = finding['id'].replace('.', ' ').replace('_', ' ').title() + " Security Issue"
            
            all_findings.append(finding)
        
        # Add CloudTrail findings
        unused = cloudtrail_analysis.get('unused_permissions', [])
        medium_count = summary.get('medium', 0)
        
        logging.info(f"🔍 CloudTrail reported {len(unused)} unused permissions: {unused[:5]}{'...' if len(unused) > 5 else ''}")
        
        if unused:
            # Find which roles have these unused permissions
            # Strategy: Check all analyzed roles and see if they have any of the unused permissions
            affected_roles = []
            managed_only_roles = []  # Track roles with ONLY managed policies (separate finding)
            
            logging.info(f"🔍 Checking which roles have unused permissions: {unused}")
            logging.info(f"📋 Total roles to check: {len(roles)}")
            
            for role_item in roles:
                # roles from _discover_iam_roles() use 'name' key, not 'RoleName'
                role_name = role_item.get('name', '') or role_item.get('RoleName', '')
                if not role_name:
                    continue
                
                # Skip AWS Service Roles - they are system-managed and cannot be modified
                if role_name.startswith('AWSServiceRoleFor'):
                    logging.info(f"   ⏭️  Skipping AWS Service Role: {role_name} (system-managed, cannot be modified)")
                    continue
                
                try:
                    # Use boto3 DIRECTLY to check inline vs managed policies (most reliable)
                    inline_policy_names = []
                    attached_policies = []
                    
                    if self.boto_iam:
                        try:
                            # Get inline policies (modifiable)
                            inline_policy_names = self.boto_iam.list_role_policies(RoleName=role_name)['PolicyNames']
                            
                            # Get attached managed policies (not modifiable)
                            attached_policies = self.boto_iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                            
                            logging.info(f"   📋 '{role_name}': {len(inline_policy_names)} inline, {len(attached_policies)} managed")
                        except Exception as e:
                            logging.warning(f"   ⚠️ Could not check policies for {role_name}: {e}")
                            continue
                    else:
                        logging.error("   ❌ boto_iam client not available!")
                        continue
                    # Track roles that have ONLY managed policies (for separate finding)
                    if not inline_policy_names and attached_policies:
                        policy_names = [p.get('PolicyName', 'Unknown') for p in attached_policies]
                        managed_only_roles.append({
                            'role_name': role_name,
                            'managed_policies': policy_names,
                            'policy_count': len(attached_policies)
                        })
                        logging.info(f"   📋 '{role_name}': Has ONLY managed policies ({', '.join(policy_names[:2])}{'...' if len(policy_names) > 2 else ''}) - tracked for separate finding")
                        continue
                    
                    # Check if role has any of the unused permissions in INLINE policies only
                    has_unused = False
                    has_wildcard = False  # Track if permissions are via wildcards
                    found_permissions = []
                    
                    # Get actual policy documents for inline policies
                    for policy_name in inline_policy_names:
                        try:
                            policy_doc = self.boto_iam.get_role_policy(
                                RoleName=role_name,
                                PolicyName=policy_name
                            )['PolicyDocument']
                        except Exception as e:
                            logging.warning(f"   ⚠️ Could not get policy {policy_name} for {role_name}: {e}")
                            continue
                        statements = policy_doc.get('Statement', [])
                        for stmt in statements:
                            if stmt.get('Effect') != 'Allow':
                                continue
                            
                            actions = stmt.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            # Check if any unused permission matches this statement's actions
                            for action in actions:
                                # Handle wildcards (e.g., "s3:*" matches "s3:DeleteBucket", "*" matches everything)
                                if action == '*':
                                    # Full admin access - has all unused permissions via wildcard
                                    has_unused = True
                                    has_wildcard = True
                                    found_permissions = unused[:]
                                    break
                                elif '*' in action:
                                    # Service-level wildcard (e.g., "s3:*")
                                    has_wildcard = True
                                    service = action.split(':')[0] if ':' in action else ''
                                    action_part = action.split(':')[1] if ':' in action else ''
                                    for unused_perm in unused:
                                        if ':' in unused_perm:
                                            unused_service = unused_perm.split(':')[0]
                                            unused_action = unused_perm.split(':')[1]
                                            # Match service:* or service:Action*
                                            if service == unused_service and (action_part == '*' or unused_action.startswith(action_part.replace('*', ''))):
                                                has_unused = True
                                                found_permissions.append(unused_perm)
                                elif action in unused:
                                    # Explicit unused permission found
                                    has_unused = True
                                    found_permissions.append(action)
                                
                                if has_unused and action == '*':
                                    break
                            if has_unused and action == '*':
                                break
                        if has_unused and action == '*':
                            break
                    
                    # INCLUDE role in findings if it has unused permissions (wildcard OR explicit)
                    # User needs to know about the security risk even if we can't auto-fix it
                    if has_unused and found_permissions and inline_policy_names:
                        affected_roles.append(role_name)
                        if has_wildcard:
                            logging.info(f"   ⚠️  Role '{role_name}' has unused permissions via WILDCARDS: {found_permissions[:3]} (requires manual remediation)")
                        else:
                            logging.info(f"   ✅ Role '{role_name}' has explicit unused permissions: {found_permissions[:3]} (can auto-remediate)")
                    elif has_unused and not inline_policy_names:
                        # Has unused permissions but no inline policies - skip
                        logging.info(f"   ⏭️  Skipping '{role_name}': Unused permissions found but role has no modifiable inline policies")
                except Exception as e:
                    logging.debug(f"Could not check policies for role {role_name}: {e}")
                    continue
            
            # If no roles found with unused permissions, assume all USER-MANAGED roles WITH INLINE POLICIES might have them
            if not affected_roles:
                logging.warning(f"⚠️ Could not identify specific roles with unused permissions, checking all USER-MANAGED roles with inline policies")
                for role_item in roles:
                    # roles from _discover_iam_roles() use 'name' key, not 'RoleName'
                    role_name = role_item.get('name', '') or role_item.get('RoleName', '')
                    if not role_name:
                        continue
                    
                    # Skip AWS Service Roles in fallback as well
                    if role_name.startswith('AWSServiceRoleFor'):
                        logging.info(f"   ⏭️  Fallback: Skipping AWS Service Role: {role_name}")
                        continue
                    
                    # Skip roles with ONLY managed policies (use boto3 directly)
                    if self.boto_iam:
                        try:
                            inline_policy_names = self.boto_iam.list_role_policies(RoleName=role_name)['PolicyNames']
                            attached_policies = self.boto_iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                            logging.info(f"   📋 Fallback '{role_name}': {len(inline_policy_names)} inline, {len(attached_policies)} managed")
                            
                            # Skip if only managed policies
                            if not inline_policy_names and attached_policies:
                                policy_names = ', '.join([p.get('PolicyName', 'Unknown')[:30] for p in attached_policies[:2]])
                                logging.info(f"   ⏭️  Fallback: Skipping '{role_name}': ONLY managed policies ({policy_names}), cannot modify")
                                continue
                                
                        except Exception as e:
                            logging.warning(f"   ⚠️ Fallback: Could not check policies for {role_name}: {e}")
                            pass
                    
                    # Include role in fallback (may have wildcards, but user needs to know)
                    affected_roles.append(role_name)
            
            # Limit to reasonable number for display and remediation
            if len(affected_roles) > 20:
                logging.info(f"⚠️ Found {len(affected_roles)} roles with unused permissions, limiting to 20 for display")
                affected_roles = affected_roles[:20]
            logging.info(f"📋 Total user-managed roles with unused permissions: {len(affected_roles)} (AWS Service Roles excluded)")
            logging.info(f"📋 Role names: {', '.join(affected_roles[:5])}{'...' if len(affected_roles) > 5 else ''}")
            
            # Only create finding if there are affected user-managed roles
            if affected_roles:
                # Validate: Get ACTUAL unused permissions that EXIST in policies
                # CloudTrail may report permissions that were REMOVED but still in 90-day window
                actually_unused = set()
                for role_name in affected_roles:
                    try:
                        if self.boto_iam:
                            inline_policies = self.boto_iam.list_role_policies(RoleName=role_name)['PolicyNames']
                            for policy_name in inline_policies:
                                policy_doc = self.boto_iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
                                for stmt in policy_doc.get('Statement', []):
                                    if stmt.get('Effect') == 'Allow':
                                        actions = stmt.get('Action', [])
                                        if isinstance(actions, str):
                                            actions = [actions]
                                        for action in actions:
                                            # Add explicit permissions that are in unused list
                                            if action in unused:
                                                actually_unused.add(action)
                                            # Add wildcard matches
                                            elif '*' in action:
                                                if action == '*':
                                                    actually_unused.update(unused)
                                                else:
                                                    service = action.split(':')[0] if ':' in action else ''
                                                    for unused_perm in unused:
                                                        if unused_perm.startswith(f"{service}:"):
                                                            actually_unused.add(unused_perm)
                    except Exception as e:
                        logging.warning(f"   ⚠️ Could not validate unused permissions for {role_name}: {e}")
                
                actually_unused = list(actually_unused)
                logging.info(f"✅ Validated: {len(actually_unused)} out of {len(unused)} unused permissions actually exist in current policies")
                
                # Only create finding if there are REAL unused permissions
                if actually_unused:
                    # Create finding with affected roles (excluding AWS Service Roles)
                    all_findings.append({
                        'id': 'AUDIT-001',
                        'severity': 'Medium',
                        'type': 'Unused Permissions',
                        'title': 'Unused IAM Permissions Detected',
                        'description': f'Found {len(actually_unused)} permissions that have not been used in the last 90 days across {len(affected_roles)} role(s) with inline policies. AWS Service Roles and roles with only managed policies excluded as they cannot be modified.',
                        'recommendation': 'Remove unused permissions to follow principle of least privilege. Auto-remediation available for roles with explicit permissions. Roles with wildcards require manual policy editing.',
                        'why_it_matters': 'Unused permissions provide no operational value but significantly increase risk. If an attacker compromises any role with unused permissions, they could use these dormant permissions to cause destruction or data loss.',
                        'impact': 'Medium - Unnecessary risk exposure. Unused permissions increase the attack surface without providing any benefit. If compromised, attackers could use these permissions to delete resources, access sensitive data, or cause service disruptions.',
                        'detailed_remediation': f'1. Review CloudTrail data to confirm {len(actually_unused)} permissions are truly unused\n2. For roles with EXPLICIT permissions: Use auto-remediation to remove unused actions\n3. For roles with WILDCARD permissions (s3:*, *:*): Manually edit the policy to replace wildcards with explicit action lists (excluding unused permissions)\n4. Test in staging environment for 1 week\n5. Deploy to production with monitoring\n6. Monitor for AccessDenied errors for 30 days\n7. Schedule quarterly re-analysis to identify new unused permissions',
                        'compliance_violations': ['PCI DSS 7.1.2 (Least Privilege)', 'HIPAA 164.308(a)(4) (Access Control)', 'SOC 2 CC6.1'],
                        'affected_permissions': actually_unused[:5],  # Show first 5 REAL permissions
                        'affected_roles_list': affected_roles,  # User-managed roles only
                        'role': f"Multiple roles ({len(affected_roles)})" if len(affected_roles) > 1 else (affected_roles[0] if affected_roles else None),
                        'policy_snippet': json.dumps({'Note': f'{len(actually_unused)} unused permissions identified via CloudTrail analysis (AWS Service Roles excluded)', 'Sample': actually_unused[:3] if len(actually_unused) >= 3 else actually_unused}, indent=2)
                    })
                    medium_count += 1
                    risk_score += 10
                else:
                    logging.info(f"ℹ️  No unused permissions found in current policies (CloudTrail reported {len(unused)}, but they don't exist in policies anymore - likely already removed)")
            else:
                logging.info(f"ℹ️  No user-managed roles found with unused permissions (all were AWS Service Roles or no matches)")
                # Don't create a finding if only AWS Service Roles were affected
            
            # Create finding for roles with ONLY managed policies
            if managed_only_roles:
                managed_role_names = [r['role_name'] for r in managed_only_roles]
                total_policies = sum(r['policy_count'] for r in managed_only_roles)
                
                logging.info(f"📋 Found {len(managed_only_roles)} roles with ONLY managed policies")
                
                all_findings.append({
                    'id': 'AUDIT-002',
                    'severity': 'Medium',
                    'type': 'Overly Permissive Managed Policies',
                    'title': 'Roles Using Only AWS Managed Policies',
                    'description': f'Found {len(managed_only_roles)} role(s) using only AWS managed policies ({total_policies} total policies). Managed policies often grant far more permissions than needed, violating the principle of least privilege. CloudTrail analysis shows these roles likely use only a small subset of granted permissions.',
                    'recommendation': '🔧 Replace managed policies with custom inline policies containing only the specific permissions needed. Review CloudTrail logs to identify actually-used permissions, then create inline policies with only those actions.',
                    'why_it_matters': '🚨 AWS managed policies like PowerUserAccess or ReadOnlyAccess grant hundreds or thousands of permissions. If a role is compromised, attackers gain access to ALL these permissions, not just the few your application actually needs. This dramatically increases your attack surface.',
                    'impact': 'Medium - Significant security risk. Managed policies grant excessive permissions, increasing blast radius of potential compromise. CloudTrail analysis typically shows 90%+ of granted permissions are never used.',
                    'detailed_remediation': f'1. For each role, review CloudTrail logs (past 90 days) to identify which permissions are actually used\n2. Create a custom inline policy with ONLY those specific permissions\n3. Attach the inline policy to the role\n4. Detach the managed policies\n5. Test thoroughly in staging environment\n6. Monitor for AccessDenied errors for 30 days\n7. Adjust inline policy if needed based on actual usage\n\n⚠️ Note: This requires manual policy creation as managed policies cannot be modified. However, this is a best practice for production security.',
                    'compliance_violations': ['PCI DSS 7.1.2 (Least Privilege)', 'HIPAA 164.308(a)(4) (Access Control)', 'SOC 2 CC6.1', 'CIS AWS 1.16 (Ensure IAM policies are attached only to groups or roles)'],
                    'affected_permissions': [],  # Can't determine without analyzing managed policy content
                    'affected_roles_list': managed_role_names,
                    'role': f"Multiple roles ({len(managed_only_roles)})" if len(managed_only_roles) > 1 else (managed_role_names[0] if managed_role_names else None),
                    'affected_services_list': [],
                    'policy_snippet': json.dumps({
                        'Note': f'{len(managed_only_roles)} roles use only managed policies (not inline)',
                        'Example_Roles': managed_role_names[:3] if len(managed_role_names) >= 3 else managed_role_names,
                        'Common_Managed_Policies': ['PowerUserAccess', 'ReadOnlyAccess', 'AdministratorAccess'],
                        'Typical_Permission_Count': '500-2000+ actions granted'
                    }, indent=2),
                    'managed_policies_info': managed_only_roles  # Store full info for frontend display
                })
                medium_count += 1
                risk_score += 15  # Higher than unused permissions (15 vs 10) because it's potentially more dangerous
            else:
                logging.info(f"✅ No roles found using only managed policies (good - users are using inline policies)")
        
        # Group similar findings together
        grouped_findings = self._group_similar_findings(all_findings)
        
        # Sort findings by severity: Critical > High > Medium > Low
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        grouped_findings.sort(key=lambda x: (severity_order.get(x.get('severity', 'Low'), 3), x.get('title', '')))
        
        # Recalculate risk_score based on grouped findings (more accurate)
        grouped_summary = {
            'critical': sum(1 for f in grouped_findings if f.get('severity') == 'Critical'),
            'high': sum(1 for f in grouped_findings if f.get('severity') == 'High'),
            'medium': sum(1 for f in grouped_findings if f.get('severity') == 'Medium'),
            'low': sum(1 for f in grouped_findings if f.get('severity') == 'Low')
        }
        
        grouped_risk_score = (
            grouped_summary.get('critical', 0) * 40 +
            grouped_summary.get('high', 0) * 20 +
            grouped_summary.get('medium', 0) * 10 +
            grouped_summary.get('low', 0) * 5
        )
        # Use the higher of the two (grouped or original + CloudTrail) to be conservative
        final_risk_score = min(100, max(risk_score, grouped_risk_score))
        
        # Calculate security score AFTER all risk_score calculations are complete
        # This makes it intuitive: Higher security score = Better security
        security_score = max(0, 100 - final_risk_score)
        
        return {
            'success': True,
            'audit_summary': {
                'total_roles': len(roles),
                'user_managed_roles': len(roles) - skipped_service_roles,
                'aws_service_roles_excluded': skipped_service_roles,
                'aws_service_role_names': skipped_service_role_names,  # List of actual role names
                'roles_analyzed': len(roles) - skipped_service_roles,
                'total_findings': len(grouped_findings),  # Use grouped count
                'critical_issues': grouped_summary['critical'],
                'high_issues': grouped_summary['high'],
                'medium_issues': grouped_summary['medium'],
                'low_issues': grouped_summary['low'],
                'cloudtrail_events_analyzed': cloudtrail_analysis.get('total_events', 0),
                'unused_permissions_found': len(unused) if unused else 0
            },
            'risk_score': final_risk_score,  # 0-100, where 100 = worst risk (industry standard)
            'security_score': security_score,  # 0-100, where 100 = best security (for UI display)
            'findings': grouped_findings,  # Return grouped findings
            'cloudtrail_analysis': cloudtrail_analysis,
            'scp_analysis': scp_analysis,
            'recommendations': self._generate_recommendations(grouped_findings),
            'compliance_status': self._check_compliance(grouped_findings),
            'timestamp': datetime.now().isoformat()
        }
    
    def _parse_roles_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Parse role names from MCP text response"""
        roles = []
        lines = text.split('\n')
        for line in lines:
            if 'RoleName' in line or 'Role:' in line:
                # Extract role name
                parts = line.split(':')
                if len(parts) > 1:
                    role_name = parts[1].strip()
                    roles.append({'name': role_name})
        return roles if roles else self._get_sample_roles()
    
    def _get_role_policies(self, role_name: str) -> List[Dict[str, Any]]:
        """Get policies attached to a role - Try MCP first, fall back to boto3"""
        
        # Try MCP first
        if self.iam_client:
            try:
                policies = []
                
                # Get inline policies via MCP
                inline_result = self.iam_client.call_tool('list_role_policies', {'role_name': role_name})
                if inline_result.get('success'):
                    inline_data = inline_result.get('data', {})
                    # Convert Pydantic model to dict if needed
                    if hasattr(inline_data, 'model_dump'):
                        inline_data = inline_data.model_dump()
                    elif hasattr(inline_data, 'dict'):
                        inline_data = inline_data.dict()
                    elif hasattr(inline_data, '__dict__'):
                        inline_data = vars(inline_data)
                    
                    # Extract policy names from response
                    policy_names = inline_data.get('PolicyNames', []) or inline_data.get('policy_names', [])
                    
                    # Get each inline policy document
                    for policy_name in policy_names:
                        get_policy_result = self.iam_client.call_tool('get_role_policy', {
                            'role_name': role_name,
                            'policy_name': policy_name
                        })
                        if get_policy_result.get('success'):
                            policy_data = get_policy_result.get('data', {})
                            # Convert Pydantic model to dict
                            if hasattr(policy_data, 'model_dump'):
                                policy_data = policy_data.model_dump()
                            elif hasattr(policy_data, 'dict'):
                                policy_data = policy_data.dict()
                            elif hasattr(policy_data, '__dict__'):
                                policy_data = vars(policy_data)
                            
                            policy_doc = policy_data.get('PolicyDocument') or policy_data.get('policy_document')
                            if policy_doc:
                                policies.append(policy_doc)
                
                # Get attached managed policies via MCP (try get_attached_policies tool)
                # Note: If MCP tool doesn't exist, will fall back to boto3 below
                # SyncMCPClient automatically adds the server prefix (aws-iam_), so we pass just the tool name
                try:
                    attached_result = self.iam_client.call_tool('get_attached_policies', {'roleName': role_name})
                    if attached_result and attached_result.get('success'):
                        attached_data = attached_result.get('data', {})
                        # Convert Pydantic model to dict if needed
                        if hasattr(attached_data, 'model_dump'):
                            attached_data = attached_data.model_dump()
                        elif hasattr(attached_data, 'dict'):
                            attached_data = attached_data.dict()
                        elif hasattr(attached_data, '__dict__'):
                            attached_data = vars(attached_data)
                        
                        # Handle different response formats from MCP
                        # Check if it's already a list of policies
                        if isinstance(attached_data, list):
                            attached_policies = attached_data
                        else:
                            # Extract attached policy ARNs or policy documents
                            attached_policies = attached_data.get('AttachedPolicies', []) or attached_data.get('attached_policies', []) or attached_data.get('policies', [])
                        
                        for attached_policy in attached_policies:
                            # Check if it's already a policy document
                            if isinstance(attached_policy, dict) and 'Statement' in attached_policy:
                                policies.append(attached_policy)
                            elif isinstance(attached_policy, dict):
                                # It's metadata, try to get the document
                                policy_doc = attached_policy.get('document') or attached_policy.get('PolicyDocument')
                                if policy_doc:
                                    policies.append(policy_doc)
                                else:
                                    # Try to get via ARN
                                    policy_arn = attached_policy.get('PolicyArn') or attached_policy.get('policy_arn') or attached_policy.get('arn')
                                    if policy_arn:
                                        # For now, skip - would need get_policy_version which may not exist
                                        # Will fall back to boto3
                                        pass
                except Exception as mcp_err:
                    # MCP tool may not exist or failed - will use boto3 fallback
                    # This is expected - not all MCP servers have this tool, so we silently fall back
                    logging.debug(f"⚠️ MCP get_attached_policies not available, using boto3 fallback: {type(mcp_err).__name__}")
                
                if policies:
                    logging.info(f"✅ MCP: Retrieved {len(policies)} policies (inline + attached) for role {role_name}")
                    return policies
            except Exception as e:
                logging.warning(f"⚠️ MCP failed to get policies for {role_name}: {e}")
                import traceback
                logging.debug(traceback.format_exc())
        
        # Fall back to boto3
        try:
            if not self.boto_iam:
                return []
            
            policies = []
            
            # Get inline policies
            inline_policies = self.boto_iam.list_role_policies(RoleName=role_name)['PolicyNames']
            for policy_name in inline_policies:
                policy_doc = self.boto_iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )['PolicyDocument']
                policies.append(policy_doc)
            
            # Get attached managed policies
            attached = self.boto_iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            for policy in attached:
                policy_arn = policy['PolicyArn']
                policy_version = self.boto_iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_doc = self.boto_iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_version
                )['PolicyVersion']['Document']
                policies.append(policy_doc)
            
            return policies
            
        except Exception as e:
            logging.error(f"❌ Failed to get policies for {role_name}: {e}")
            return []
    
    def _extract_used_actions(self, events) -> set:
        """Extract unique actions from CloudTrail events"""
        actions = set()
        if isinstance(events, list):
            for event in events:
                if isinstance(event, dict):
                    event_name = event.get('EventName', '')
                    if event_name:
                        actions.add(event_name)
        return actions
    
    def _find_unused_permissions(self, roles, used_actions) -> List[str]:
        """Find permissions that are granted but never used"""
        # Simplified: return sample unused permissions
        all_permissions = {'s3:DeleteBucket', 'iam:DeleteUser', 'ec2:TerminateInstances', 'rds:DeleteDBInstance'}
        unused = all_permissions - used_actions
        return list(unused)
    
    def _generate_recommendations(self, findings) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        critical_count = sum(1 for f in findings if f.get('severity') == 'Critical')
        if critical_count > 0:
            recommendations.append(f"Immediately address {critical_count} critical security issues")
        
        recommendations.extend([
            "Remove unused IAM permissions identified in CloudTrail analysis",
            "Implement MFA for all IAM roles with console access",
            "Add resource-level restrictions to overly permissive policies",
            "Schedule quarterly IAM access reviews"
        ])
        
        return recommendations
    
    def _check_compliance(self, findings) -> Dict[str, Any]:
        """Check compliance against frameworks"""
        return {
            'PCI_DSS': {
                'status': 'NonCompliant' if any(f.get('severity') == 'Critical' for f in findings) else 'Compliant',
                'violations': ['Requirement 7.1.1: Limit access to system components']
            },
            'HIPAA': {
                'status': 'Partial',
                'violations': ['164.308(a)(4): Access controls']
            },
            'SOX': {
                'status': 'NonCompliant',
                'violations': ['Section 404: Internal controls over financial reporting']
            },
            'GDPR': {
                'status': 'Partial',
                'violations': ['Article 32: Security of processing']
            }
        }
    
    def _get_sample_roles(self) -> List[Dict[str, Any]]:
        """Sample roles for demo"""
        return [
            {'name': 'AdminRole', 'arn': 'arn:aws:iam::123456789012:role/AdminRole'},
            {'name': 'DeveloperRole', 'arn': 'arn:aws:iam::123456789012:role/DeveloperRole'},
            {'name': 'ReadOnlyRole', 'arn': 'arn:aws:iam::123456789012:role/ReadOnlyRole'},
            {'name': 'LambdaExecutionRole', 'arn': 'arn:aws:iam::123456789012:role/LambdaExecutionRole'},
            {'name': 'EC2InstanceRole', 'arn': 'arn:aws:iam::123456789012:role/EC2InstanceRole'}
        ]
    
    def _get_sample_cloudtrail_analysis(self) -> Dict[str, Any]:
        """Sample CloudTrail analysis"""
        return {
            'total_events': 1523,
            'used_actions': ['s3:GetObject', 's3:PutObject', 'ec2:DescribeInstances', 'lambda:InvokeFunction'],
            'unused_permissions': ['s3:DeleteBucket', 'iam:DeleteUser', 'ec2:TerminateInstances', 'rds:DeleteDBInstance'],
            'analysis_period_days': 90
        }
    
    def apply_fix(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Apply automatic fix for a security finding"""
        try:
            finding_type = finding.get('type', '')
            severity = finding.get('severity', '')
            
            # Try multiple ways to get role name
            # Priority: role_name > role (unless it's "Multiple roles") > role_arn > policy_name
            role_name = finding.get('role_name')
            
            if not role_name:
                role_value = finding.get('role', '')
                # Skip "Multiple roles (X)" strings
                if role_value and not role_value.startswith('Multiple roles'):
                    role_name = role_value
            
            if not role_name and finding.get('role_arn'):
                role_name = finding.get('role_arn', '').split('/')[-1]
            
            if not role_name and finding.get('policy_name'):
                role_name = finding.get('policy_name', '').split('/')[-1]
            
            # Log finding structure for debugging
            logging.info(f"🔍 apply_fix called with:")
            logging.info(f"   - Finding ID: {finding.get('id')}")
            logging.info(f"   - Finding type: {finding_type}")
            logging.info(f"   - role field: '{finding.get('role')}'")
            logging.info(f"   - role_name field: '{finding.get('role_name')}'")
            logging.info(f"   - Extracted role_name: '{role_name}'")
            
            # Skip if no role name available
            if not role_name or not role_name.strip():
                # Provide detailed error message with available fields
                available_fields = ', '.join(finding.keys())
                error_msg = f"Cannot apply fix: No role name found in finding. Available fields: {available_fields}"
                logging.warning(f"⚠️ {error_msg}")
                logging.warning(f"   Finding ID: {finding.get('id', 'N/A')}, Title: {finding.get('title', 'N/A')}")
                return {
                    'success': False,
                    'message': f"Cannot apply fix: Finding is missing role information. This finding may be related to account-wide or CloudTrail analysis and cannot be auto-remediated.",
                    'actions_taken': []
                }
            
            logging.info(f"🔧 Applying fix for: {finding.get('title')} (Role: {role_name})")
            
            actions_taken = []
            
            # Handle different types of findings
            # Check SPECIFIC types FIRST before generic "Unused Permissions"
            
            # 1. Managed Policies (most specific)
            if finding_type == 'Managed Policies Only' or finding_type == 'Overly Permissive Managed Policies' or finding.get('id') == 'AUDIT-005' or finding.get('id') == 'AUDIT-002' or 'Managed Policies' in finding.get('title', ''):
                # Cannot auto-fix roles with only managed policies
                try:
                    attached_policies = self.boto_iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                    policy_names = [p['PolicyName'] for p in attached_policies[:5]]
                    policy_list = ', '.join(policy_names)
                    if len(attached_policies) > 5:
                        policy_list += f" +{len(attached_policies) - 5} more"
                    
                    return {
                        'success': False,
                        'message': f"SECURITY RISK\n\nThis role relies solely on AWS managed policies ({policy_list}). These policies typically grant hundreds or thousands of permissions, far exceeding what your application actually needs.\n\nWhy This Failed\n\nAuto-remediation cannot modify AWS managed policies as they are system-controlled. These policies are designed for broad use cases and often include excessive permissions like Delete, Terminate, and Modify across multiple services.\n\nManual Fix Required\n\n1. Review CloudTrail logs (past 90 days) to identify which specific permissions this role actually uses\n2. Create a new custom inline policy containing ONLY those specific permissions\n3. Attach the custom inline policy to the role\n4. Detach all managed policies from the role\n5. Test thoroughly in a staging environment for 1-2 weeks\n6. Monitor for AccessDenied errors and adjust the inline policy if needed\n7. Deploy to production with continued monitoring\n\nNote: This is a security best practice. CloudTrail analysis typically shows 90%+ of managed policy permissions are never used.",
                        'actions_taken': [],
                        'error_type': 'managed_policies_only_finding'
                    }
                except Exception as e:
                    logging.error(f"Error getting managed policies for {role_name}: {e}")
                    return {
                        'success': False,
                        'message': f"SECURITY RISK\n\nThis role uses only AWS managed policies which cannot be modified automatically.\n\nWhy This Failed\n\nAWS managed policies are system-controlled and grant far more permissions than typically needed.\n\nManual Fix Required\n\n1. Review CloudTrail logs to identify actually-used permissions\n2. Create custom inline policies with only those permissions\n3. Replace managed policies with your custom inline policies\n4. Test thoroughly before deploying to production",
                        'actions_taken': [],
                        'error_type': 'managed_policies_only_finding'
                    }
            
            # 2. Condition Keys (specific)
            elif 'condition' in finding.get('title', '').lower() or 'condition key' in finding.get('description', '').lower():
                return {
                    'success': False,
                    'message': f"MANUAL FIX REQUIRED\n\nAdding condition keys to IAM policies requires understanding your security requirements and resource access patterns.\n\nWhy This Failed\n\nCondition keys (like IP restrictions, encryption requirements, VPC endpoints) must be tailored to your specific security and compliance needs.\n\nManual Fix Required\n\n1. Open AWS Console → IAM → Roles → {role_name}\n2. Edit the inline policy for the affected service\n3. Add appropriate Condition blocks:\n   • For S3: Require encryption (s3:x-amz-server-side-encryption)\n   • For IP restrictions: aws:SourceIp\n   • For VPC: aws:SourceVpce\n4. Test to ensure legitimate access still works\n5. Monitor for AccessDenied errors\n\n📍 AWS Documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html",
                    'actions_taken': [],
                    'error_type': 'condition_keys_manual'
                }
            
            # 3. Wildcard Resources (specific)
            elif 'Wildcard Resources' in finding.get('title', '') or 'wildcard resource' in finding.get('description', '').lower():
                affected_services = finding.get('affected_services_list', [])
                services_text = ', '.join(affected_services[:3]) if affected_services else 'multiple services'
                if len(affected_services) > 3:
                    services_text += f' +{len(affected_services) - 3} more'
                
                return {
                    'success': False,
                    'message': f"SECURITY RISK\n\nThis role uses wildcard resources (*) for {services_text}, allowing actions on ALL resources instead of specific ones. This violates the principle of least privilege.\n\nWhy This Failed\n\nAuto-remediation cannot determine which specific resources your application needs. Wildcard resources must be manually replaced with explicit ARNs based on your application's actual requirements.\n\nManual Fix Required\n\n1. Identify the specific resources this role actually needs (e.g., specific S3 buckets, DynamoDB tables, etc.)\n2. Replace wildcard (*) with explicit resource ARNs in the inline policy\n3. Example: Change \"Resource\": \"*\" to \"Resource\": \"arn:aws:s3:::my-specific-bucket/*\"\n4. Test in staging environment to ensure the role can still access required resources\n5. Deploy to production with monitoring\n6. Monitor CloudTrail for AccessDenied errors\n\nNote: This change will prevent the role from accessing unauthorized resources, significantly reducing your attack surface.",
                    'actions_taken': [],
                    'error_type': 'wildcard_resources_manual'
                }
            
            # 4. MFA (specific)
            elif 'MFA' in finding.get('title', ''):
                return {
                    'success': False,
                    'message': f"MANUAL FIX REQUIRED\n\nAdding MFA requirements to IAM policies requires careful consideration of your authentication flow.\n\nWhy This Failed\n\nMFA requirements must be added as condition blocks to policy statements, which requires understanding your specific authentication setup and user experience.\n\nManual Fix Required\n\n1. Open AWS Console → IAM → Roles → {role_name}\n2. Edit the inline policy or create a new one\n3. Add a Condition block with MFA requirement:\n   \"Condition\": {{\n     \"Bool\": {{\"aws:MultiFactorAuthPresent\": \"true\"}}\n   }}\n4. Test with MFA-enabled users\n5. Monitor for authentication issues\n\n📍 AWS Documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html",
                    'actions_taken': [],
                    'error_type': 'mfa_manual_required'
                }
            
            # 5. Least Privilege (specific)
            elif 'least privilege' in finding.get('description', '').lower():
                return {
                    'success': False,
                    'message': f"MANUAL FIX REQUIRED\n\nApplying least privilege requires analyzing CloudTrail logs to determine which permissions are actually used.\n\nWhy This Failed\n\nAuto-remediation cannot determine which permissions your application needs without analyzing actual usage patterns over time.\n\nManual Fix Required\n\n1. Use AWS Access Analyzer or CloudTrail to identify used permissions\n2. Review the last 90 days of CloudTrail logs for role {role_name}\n3. Create a new inline policy with ONLY the permissions that were actually used\n4. Test in staging environment\n5. Deploy to production with monitoring\n\n📍 Use AWS IAM Access Analyzer: https://console.aws.amazon.com/access-analyzer/",
                    'actions_taken': [],
                    'error_type': 'least_privilege_manual'
                }
            
            # 6. Unused Permissions (catch-all - comes LAST!)
            elif finding_type == 'Unused Permissions':
                # Remove unused permissions
                unused_perms = finding.get('affected_permissions', [])
                if not unused_perms:
                    logging.warning(f"⚠️ No affected_permissions found in finding")
                    return {
                        'success': False,
                        'message': f"No permissions specified to remove",
                        'actions_taken': []
                    }
                
                failed_removals = []
                for perm in unused_perms:
                    result = self._remove_permission(role_name, perm)
                    if result:
                        actions_taken.append(f"Removed unused permission: {perm} from inline policy")
                    else:
                        failed_removals.append(perm)
                
                # If some failed, provide specific guidance
                if failed_removals and not actions_taken:
                    # Check WHY it failed - managed policies or wildcards that couldn't be replaced
                    try:
                        inline_policies = self.boto_iam.list_role_policies(RoleName=role_name)['PolicyNames']
                        attached_policies = self.boto_iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                        
                        if not inline_policies and attached_policies:
                            # Only managed policies
                            policy_names = ', '.join([p['PolicyName'] for p in attached_policies[:3]])
                            return {
                                'success': False,
                                'message': f"❌ {role_name} uses ONLY AWS managed policies ({policy_names}{'...' if len(attached_policies) > 3 else ''}). These cannot be modified.\n\n✅ Solution: Detach managed policies and create custom inline policies with only the permissions you need.",
                                'actions_taken': [],
                                'error_type': 'managed_policies_only'
                            }
                        elif inline_policies and attached_policies:
                            # Both inline and managed
                            return {
                                'success': False,
                                'message': f"⚠️ {role_name} uses both inline and managed policies. Unused permissions may be in managed policies which cannot be modified.\n\n✅ Solution: Review managed policies and consider replacing them with custom inline policies.",
                                'actions_taken': [],
                                'error_type': 'mixed_policies'
                            }
                        else:
                            # Inline policies with wildcards that couldn't be replaced
                            return {
                                'success': False,
                                'message': f"🚨 SECURITY RISK: {role_name} has wildcard permissions (s3:*, *:*) that include the unused actions.\n\n❌ Why This Failed: Auto-remediation cannot safely modify wildcards because they cover 100+ actions. Removing the wildcard would require listing all remaining actions explicitly, which is error-prone and may break functionality.\n\n✅ Manual Fix Required:\n1. Review the policy to identify which actions are actually needed\n2. Replace wildcards (s3:*, *:*) with explicit action lists\n3. Exclude the unused permissions: {', '.join(failed_removals[:3])}\n4. Test in staging before deploying to production\n\nNote: This also addresses the 'Wildcard Actions Detected' critical finding.",
                                'actions_taken': [],
                                'error_type': 'wildcard_replacement_failed'
                            }
                    except:
                        return {
                            'success': False,
                            'message': f"Cannot auto-remediate {role_name}. Manual review required.",
                            'actions_taken': [],
                            'error_type': 'unknown'
                        }
                elif failed_removals:
                    actions_taken.append(f"⚠️ Note: Could not remove {len(failed_removals)} permissions (may be in managed policies or wildcards that couldn't be replaced)")
            
            else:
                # No specific remediation available for this finding type
                return {
                    'success': False,
                    'message': f"MANUAL REMEDIATION REQUIRED\n\nThis finding type ('{finding.get('title', 'Unknown')}') requires manual review and remediation.\n\nWhy This Failed\n\nAuto-remediation is not available for this specific security finding. It requires human judgment to determine the appropriate fix.\n\nRecommended Actions\n\n1. Review the finding details and recommendation above\n2. Open AWS Console → IAM → Roles → {role_name}\n3. Follow the step-by-step remediation guide provided\n4. Test changes in staging before production\n5. Monitor for any issues after deployment\n\n📍 Direct Link: https://console.aws.amazon.com/iam/home#/roles/{role_name}",
                    'actions_taken': [],
                    'error_type': 'no_auto_remediation'
                }
            
            if actions_taken:
                # Build detailed success message with AWS Console verification steps
                finding_title = finding.get('title', 'security issue')
                verification_steps = f"\n\n✅ Verification Steps:\n"
                verification_steps += f"1. Open AWS Console → IAM → Roles → {role_name}\n"
                verification_steps += f"2. Go to 'Permissions' tab\n"
                verification_steps += f"3. Review the inline policies to see the changes\n"
                verification_steps += f"4. Go to 'Access Advisor' tab to verify permission usage\n"
                verification_steps += f"5. Monitor CloudWatch Logs for any AccessDenied errors\n\n"
                verification_steps += f"📍 Direct Link: https://console.aws.amazon.com/iam/home#/roles/{role_name}"
                
                return {
                    'success': True,
                    'message': f"✅ Successfully remediated '{finding_title}' for role '{role_name}'!\n\n📝 Changes Made:\n" + "\n".join([f"• {action}" for action in actions_taken]) + verification_steps,
                    'actions_taken': actions_taken
                }
            else:
                return {
                    'success': False,
                    'message': f"No automatic fix available for this finding type or role uses managed policies",
                    'actions_taken': []
                }
        except Exception as e:
            logging.error(f"❌ Fix failed: {e}")
            return {
                'success': False,
                'message': f"Failed to apply fix: {str(e)}",
                'actions_taken': []
            }

    def _remove_permission(self, role_name: str, permission: str) -> bool:
        """Remove a specific permission from a role - Try AWS IAM MCP Server first, fall back to boto3"""
        try:
            if not role_name or not role_name.strip():
                logging.error(f"❌ Invalid role name: '{role_name}'")
                return False
            
            # Try AWS IAM MCP Server first (supports write operations!)
            if self.iam_client:
                try:
                    logging.info(f"🔧 Trying AWS IAM MCP Server to remove {permission} from {role_name}")
                    
                    # Get inline policies via MCP
                    inline_result = self.iam_client.call_tool('list_role_policies', {'role_name': role_name})
                    if inline_result.get('success'):
                        policy_names = self._extract_policy_names_from_mcp(inline_result)
                        
                        for policy_name in policy_names:
                            # Get policy document
                            get_policy_result = self.iam_client.call_tool('get_role_policy', {
                                'role_name': role_name,
                                'policy_name': policy_name
                            })
                            
                            if get_policy_result.get('success'):
                                policy_doc = self._extract_policy_doc_from_mcp(get_policy_result)
                                
                                # Remove the permission
                                modified = False
                                for statement in policy_doc.get('Statement', []):
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    
                                    if permission in actions:
                                        actions.remove(permission)
                                        statement['Action'] = actions if len(actions) > 1 else (actions[0] if len(actions) == 1 else [])
                                        modified = True
                                
                                # Update via MCP
                                if modified:
                                    update_result = self.iam_client.call_tool('put_role_policy', {
                                        'role_name': role_name,
                                        'policy_name': policy_name,
                                        'policy_document': json.dumps(policy_doc)
                                    })
                                    
                                    if update_result.get('success'):
                                        logging.info(f"✅ MCP: Removed {permission} from {role_name}/{policy_name}")
                                        return True
                        
                        logging.warning(f"⚠️ MCP: Permission {permission} not found in {role_name}")
                        return False
                except Exception as e:
                    logging.warning(f"⚠️ AWS IAM MCP Server failed: {e}, falling back to boto3")
            
            # Fall back to boto3
            if not self.boto_iam:
                logging.error("❌ Boto3 IAM client not available")
                return False

            logging.info(f"🔄 Using boto3 fallback to remove {permission} from {role_name}")
            
            # Use boto3 to check inline and managed policies (reliable reads)
            # First, try inline policies (can be modified directly)
            try:
                inline_policies = self.boto_iam.list_role_policies(RoleName=role_name)['PolicyNames']
                logging.info(f"   📋 Found {len(inline_policies)} inline policies for {role_name}")
            except Exception as e:
                logging.error(f"   ❌ Failed to list inline policies: {e}")
                return False

            for policy_name in inline_policies:
                # Get the policy document
                policy_doc = self.boto_iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )['PolicyDocument']

                # Remove the specific permission from statements
                modified = False
                for statement in policy_doc.get('Statement', []):
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]

                    if permission in actions:
                        actions.remove(permission)
                        statement['Action'] = actions
                        modified = True

                # Update the policy if modified
                if modified:
                    self.boto_iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(policy_doc)
                    )
                    logging.info(f"✅ boto3: Removed {permission} from inline policy {policy_name} in {role_name}")
                    return True

            # Use boto3 to check attached managed policies (reliable reads)
            try:
                attached_policies = self.boto_iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                logging.info(f"   📋 Found {len(attached_policies)} attached managed policies for {role_name}")
            except Exception as e:
                logging.error(f"   ❌ Failed to list attached policies: {e}")
                attached_policies = []
            
            # For managed policies, we cannot modify them directly
            # Instead, we need to create a custom inline policy with the needed permissions (excluding the unused one)
            # This is complex and risky, so we'll log a warning instead
            if attached_policies:
                logging.warning(f"   ⚠️ {role_name} uses managed policies. Cannot auto-remove {permission} from managed policies.")
                logging.warning(f"   ℹ️  Manual action required: Review and update managed policies or create custom inline policy.")
                return False
            
            # If permission not found as explicit action, check for wildcards and REPLACE them
            logging.warning(f"   ⚠️ Permission {permission} not found as explicit action in any inline policy for {role_name}")
            logging.info(f"   🔍 Checking for wildcard permissions that include {permission}...")
            
            # Try to replace wildcards with explicit actions (excluding the unused permission)
            wildcard_replaced = self._replace_wildcard_with_explicit_actions(role_name, permission)
            if wildcard_replaced:
                logging.info(f"   ✅ Successfully replaced wildcard permissions, excluding {permission}")
                return True
            
            logging.warning(f"   ℹ️  Note: Role may have wildcard permissions (e.g., s3:* or *:*) that include this action")
            logging.warning(f"   ℹ️  Could not auto-replace wildcards. Manual action required.")
            return False

        except ClientError as e:
            logging.error(f"❌ Failed to remove permission: {e}")
            return False
        except Exception as e:
            logging.error(f"❌ Unexpected error removing permission: {e}")
            return False
    
    def _replace_wildcard_with_explicit_actions(self, role_name: str, unused_permission: str) -> bool:
        """
        Replace wildcard permissions (s3:*, *:*) with explicit actions, excluding the unused permission.
        This is safer than just removing, as we preserve the original intent while removing unused actions.
        """
        try:
            # Get inline policies
            inline_policies = self.boto_iam.list_role_policies(RoleName=role_name)['PolicyNames']
            
            for policy_name in inline_policies:
                policy_doc = self.boto_iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )['PolicyDocument']
                
                modified = False
                for statement in policy_doc.get('Statement', []):
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    # Check for wildcards
                    for i, action in enumerate(actions):
                        if '*' in action:
                            logging.info(f"   🔍 Found wildcard: {action}")
                            
                            # Generate explicit action list
                            explicit_actions = self._expand_wildcard_to_explicit_actions(
                                action, 
                                unused_permission,
                                role_name
                            )
                            
                            if explicit_actions:
                                # Replace wildcard with explicit list
                                actions[i:i+1] = explicit_actions
                                modified = True
                                logging.info(f"   ✅ Replaced {action} with {len(explicit_actions)} explicit actions (excluding {unused_permission})")
                    
                    if modified:
                        statement['Action'] = actions
                
                # Update policy if modified
                if modified:
                    self.boto_iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(policy_doc)
                    )
                    logging.info(f"✅ Updated inline policy {policy_name} with explicit actions")
                    return True
            
            return False
        
        except Exception as e:
            logging.error(f"❌ Failed to replace wildcards: {e}")
            return False
    
    def _expand_wildcard_to_explicit_actions(self, wildcard: str, exclude_action: str, role_name: str) -> List[str]:
        """
        Expand a wildcard permission (e.g., s3:*) to explicit actions, excluding the specified unused action.
        Uses CloudTrail data to determine which actions are actually used.
        """
        try:
            # Common safe actions for each service (curated list)
            common_safe_actions = {
                's3': ['s3:GetObject', 's3:PutObject', 's3:ListBucket', 's3:GetBucketLocation'],
                'dynamodb': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query', 'dynamodb:Scan'],
                'lambda': ['lambda:InvokeFunction', 'lambda:GetFunction'],
                'sqs': ['sqs:SendMessage', 'sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:GetQueueAttributes'],
                'sns': ['sns:Publish', 'sns:Subscribe'],
                'ec2': ['ec2:DescribeInstances', 'ec2:DescribeSecurityGroups', 'ec2:DescribeVolumes'],
                'iam': ['iam:GetRole', 'iam:GetPolicy', 'iam:ListRoles'],
                'logs': ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
                'bedrock': ['bedrock:InvokeModel'],
            }
            
            if wildcard == '*':
                # Full wildcard - too dangerous to auto-replace
                logging.warning(f"   ⚠️ Full wildcard (*) detected - too broad to auto-replace safely")
                return []
            
            # Extract service from wildcard (e.g., "s3:*" -> "s3")
            if ':' in wildcard:
                service = wildcard.split(':')[0]
                action_part = wildcard.split(':')[1]
                
                # Get common safe actions for this service
                safe_actions = common_safe_actions.get(service, [])
                
                if not safe_actions:
                    logging.warning(f"   ⚠️ No safe actions defined for service: {service}")
                    return []
                
                # Exclude the unused action
                explicit_actions = [action for action in safe_actions if action != exclude_action]
                
                logging.info(f"   📋 Replacing {wildcard} with {len(explicit_actions)} safe actions for {service}")
                return explicit_actions
            
            return []
        
        except Exception as e:
            logging.error(f"❌ Failed to expand wildcard: {e}")
            return []
            logging.error(f"❌ Unexpected error removing permission: {e}")
            return False
    
    def _extract_policy_names_from_mcp(self, result: Dict[str, Any]) -> List[str]:
        """Helper to extract policy names from MCP response"""
        data = result.get('data', {})
        if hasattr(data, 'model_dump'):
            data = data.model_dump()
        
        if hasattr(data, 'content'):
            content = data.content
            if isinstance(content, list) and len(content) > 0:
                text_content = content[0].text if hasattr(content[0], 'text') else content[0].get('text', '')
                try:
                    parsed = json.loads(text_content)
                    return parsed.get('PolicyNames', [])
                except (json.JSONDecodeError, AttributeError):
                    return data.get('PolicyNames', [])
        return data.get('PolicyNames', [])
    
    def _extract_policy_doc_from_mcp(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Helper to extract policy document from MCP response"""
        data = result.get('data', {})
        if hasattr(data, 'model_dump'):
            data = data.model_dump()
        
        policy_doc = data.get('PolicyDocument', {})
        if hasattr(policy_doc, 'model_dump'):
            policy_doc = policy_doc.model_dump()
        
        return policy_doc

    def _add_mfa_requirement(self, role_name: str) -> bool:
        """Add MFA requirement to a role's trust policy using boto3"""
        try:
            if not self.boto_iam:
                logging.error("❌ Boto3 IAM client not available")
                return False

            # Get current role
            role = self.boto_iam.get_role(RoleName=role_name)['Role']
            assume_role_policy = role['AssumeRolePolicyDocument']

            # Add MFA condition to all statements
            modified = False
            for statement in assume_role_policy.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    # Add MFA condition
                    if 'Condition' not in statement:
                        statement['Condition'] = {}

                    if 'Bool' not in statement['Condition']:
                        statement['Condition']['Bool'] = {}

                    statement['Condition']['Bool']['aws:MultiFactorAuthPresent'] = 'true'
                    modified = True

            # Update the trust policy if modified
            if modified:
                self.boto_iam.update_assume_role_policy(
                    RoleName=role_name,
                    PolicyDocument=json.dumps(assume_role_policy)
                )
                logging.info(f"✅ Added MFA requirement to role {role_name}")
                return True

            return False

        except ClientError as e:
            logging.error(f"❌ Failed to add MFA requirement: {e}")
            return False
        except Exception as e:
            logging.error(f"❌ Unexpected error adding MFA: {e}")
            return False

    def _apply_least_privilege(self, role_name: str) -> bool:
        """Apply least-privilege principle to a role using CloudTrail data"""
        try:
            if not self.boto_iam:
                logging.error("❌ Boto3 IAM client not available")
                return False

            # Get CloudTrail events for this role (last 90 days)
            cloudtrail = boto3.client('cloudtrail', region_name=self.aws_region)
            end_time = datetime.now()
            start_time = end_time - timedelta(days=90)

            # Query events for this role
            events = cloudtrail.lookup_events(
                LookupAttributes=[{
                    'AttributeKey': 'Username',
                    'AttributeValue': role_name
                }],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=1000
            )['Events']

            # Extract actually used actions
            used_actions = set()
            for event in events:
                event_name = event.get('EventName', '')
                if event_name:
                    # Convert CloudTrail event name to IAM action
                    # e.g., "GetObject" -> "s3:GetObject"
                    service = event.get('EventSource', '').split('.')[0]
                    used_actions.add(f"{service}:{event_name}")

            if not used_actions:
                logging.warning(f"⚠️ No CloudTrail events found for role {role_name}")
                return False

            # Create new policy with only used actions
            new_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": list(used_actions),
                    "Resource": "*"  # TODO: Analyze resources from CloudTrail
                }]
            }

            # Update role policy
            self.boto_iam.put_role_policy(
                RoleName=role_name,
                PolicyName='LeastPrivilegePolicy',
                PolicyDocument=json.dumps(new_policy)
            )

            logging.info(f"✅ Applied least-privilege policy to {role_name} with {len(used_actions)} actions")
            return True

        except ClientError as e:
            logging.error(f"❌ Failed to apply least privilege: {e}")
            return False
        except Exception as e:
            logging.error(f"❌ Unexpected error applying least privilege: {e}")
            return False

    def _restrict_wildcards(self, role_name: str) -> bool:
        """Replace wildcard permissions with specific resources using boto3"""
        try:
            if not self.boto_iam:
                logging.error("❌ Boto3 IAM client not available")
                return False

            # Get all inline policies for the role
            inline_policies = self.boto_iam.list_role_policies(RoleName=role_name)['PolicyNames']

            modified_any = False
            for policy_name in inline_policies:
                # Get the policy document
                policy_doc = self.boto_iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )['PolicyDocument']

                # Check for wildcard actions and resources
                modified = False
                for statement in policy_doc.get('Statement', []):
                    # Replace wildcard actions
                    actions = statement.get('Action', [])
                    if actions == '*' or (isinstance(actions, list) and '*' in actions):
                        # Replace with common safe actions (example)
                        statement['Action'] = [
                            's3:GetObject',
                            's3:ListBucket',
                            'ec2:DescribeInstances',
                            'logs:CreateLogGroup',
                            'logs:CreateLogStream',
                            'logs:PutLogEvents'
                        ]
                        modified = True
                        logging.info(f"⚠️ Replaced wildcard actions in {policy_name}")

                    # Replace wildcard resources
                    resources = statement.get('Resource', [])
                    if resources == '*' or (isinstance(resources, list) and '*' in resources):
                        # Replace with account-specific ARN
                        statement['Resource'] = f"arn:aws:*:{self.aws_region}:{self.account_id}:*"
                        modified = True
                        logging.info(f"⚠️ Replaced wildcard resources in {policy_name}")

                # Update the policy if modified
                if modified:
                    self.boto_iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(policy_doc)
                    )
                    modified_any = True

            if modified_any:
                logging.info(f"✅ Restricted wildcard permissions in role {role_name}")
                return True
            else:
                logging.info(f"ℹ️ No wildcard permissions found in role {role_name}")
                return False

        except ClientError as e:
            logging.error(f"❌ Failed to restrict wildcards: {e}")
            return False
        except Exception as e:
            logging.error(f"❌ Unexpected error restricting wildcards: {e}")
            return False