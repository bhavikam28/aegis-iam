"""
IAM Deployer - Deploy IAM roles and policies to AWS using MCP servers only
"""
import logging
import json
import boto3
from botocore.exceptions import ClientError
from typing import Dict, Any, Optional
from core.fastmcp_client import get_mcp_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IAMDeployer:
    """Deploy IAM roles and policies to AWS using MCP servers only"""
    
    def __init__(self, aws_region: str = "us-east-1"):
        """
        Initialize IAM Deployer
        
        Args:
            aws_region: AWS region for deployment
        """
        self.aws_region = aws_region
        self.iam_client = None
        self.boto_iam = None
        self._initialize_clients()
    
    def _initialize_clients(self) -> bool:
        """Initialize MCP IAM client with boto3 fallback"""
        # Try MCP first (preferred method - uses same servers as audit)
        try:
            logger.info("🚀 Initializing MCP IAM client for deployment...")
            self.iam_client = get_mcp_client('aws-iam')
            
            if self.iam_client:
                logger.info("✅ MCP IAM client initialized (preferred)")
                # Try to list tools (may be empty if MCP servers not fully connected)
                tools = self.iam_client.list_tools()
                if tools:
                    tool_names = [t.get('name', '') for t in tools]
                    logger.info(f"   Available IAM tools: {tool_names}")
                else:
                    logger.warning("   ⚠️ MCP connected but no tools listed - will try tool names directly")
                
                # IMPORTANT: Even if list_tools() is empty, MCP might still work
                # SyncMCPClient automatically adds 'aws-iam_' prefix when calling tools
                # We'll try using MCP first, and fall back to boto3 if it fails
                logger.info("   ✅ Will attempt to use MCP tools (auto-prefixed with 'aws-iam_')")
                return True
        except Exception as e:
            logger.warning(f"⚠️ MCP IAM client initialization failed: {e}")
            logger.warning(f"   Error details: {type(e).__name__}: {str(e)}")
        
        # Fallback to boto3 for operations not exposed by MCP (e.g., delete role, detach managed policies)
        logger.warning("⚠️ MCP IAM tools not fully available. Enabling boto3 fallback for delete/detach operations.")
        try:
            self.boto_iam = boto3.client('iam', region_name=self.aws_region)
            return True
        except Exception as e:
            logger.error(f"❌ Failed to initialize boto3 IAM client: {e}")
            return False
    
    def create_role(
        self,
        role_name: str,
        trust_policy: Dict[str, Any],
        description: Optional[str] = None,
        max_session_duration: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Create an IAM role using MCP or boto3
        
        Args:
            role_name: Name of the role to create
            trust_policy: Trust policy document (JSON dict)
            description: Optional role description
            max_session_duration: Optional max session duration in seconds (3600-43200)
        
        Returns:
            Dict with 'success', 'role_arn', and 'role_name' or 'error'
        """
        if not self.iam_client:
            return {
                "success": False,
                "error": "IAM MCP client not initialized. Please ensure MCP servers are installed and configured."
            }
        
        try:
            logger.info(f"🔧 Creating IAM role: {role_name}")
            
            # Prepare arguments for MCP tool
            # Note: Tool name may vary based on MCP server implementation
            # Common names: 'create_role', 'iam_create_role', 'aws-iam_create_role'
            arguments = {
                "role_name": role_name,
                "assume_role_policy_document": json.dumps(trust_policy),
            }
            
            if description:
                arguments["description"] = description
            if max_session_duration:
                arguments["max_session_duration"] = max_session_duration
            
            # Try different possible tool names
            # Note: SyncMCPClient.call_tool() automatically adds 'aws-iam_' prefix
            # So we use unprefixed names here
            tool_names = ['create_role', 'iam_create_role']
            result = None
            
            for tool_name in tool_names:
                try:
                    logger.debug(f"   Trying MCP tool: {tool_name}")
                    result = self.iam_client.call_tool(tool_name, arguments)
                    if result and result.get('success'):
                        logger.info(f"   ✅ Successfully called MCP tool: {tool_name}")
                        break
                except Exception as e:
                    logger.debug(f"   Tool {tool_name} failed: {e}")
                    continue
            
            if not result or not result.get('success'):
                # If MCP fails, try boto3 if available
                error_msg = result.get('error', 'Unknown error') if result else 'Tool not found'
                if self.boto_iam:
                    return self._create_role_boto3(role_name, trust_policy, description, max_session_duration)
                return {
                    "success": False,
                    "error": f"Failed to create role via MCP: {error_msg}. Please ensure the MCP server supports role creation."
                }
            
            # Extract role ARN from result
            data = result.get('data', {})
            role_arn = None
            
            # Try to extract ARN from various possible response formats
            if isinstance(data, dict):
                role_arn = (
                    data.get('role_arn') or
                    data.get('Arn') or
                    data.get('Role', {}).get('Arn') or
                    data.get('Role', {}).get('RoleArn')
                )
                
                # If ARN not directly available, construct it
                if not role_arn:
                    # Try to get account ID from STS or construct ARN
                    # Format: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME
                    role_arn = f"arn:aws:iam::ACCOUNT_ID:role/{role_name}"
                    logger.warning(f"⚠️ Could not extract ARN from response, using placeholder: {role_arn}")
            
            logger.info(f"✅ Successfully created IAM role: {role_name}")
            return {
                "success": True,
                "role_arn": role_arn or f"arn:aws:iam::ACCOUNT_ID:role/{role_name}",
                "role_name": role_name,
                "message": f"IAM role '{role_name}' created successfully"
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to create role: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def create_policy(
        self,
        policy_name: str,
        policy_document: Dict[str, Any],
        description: Optional[str] = None,
        path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create an IAM managed policy using MCP, fallback to boto3 if MCP fails
        """
        if not self.iam_client and not self.boto_iam:
            return {
                "success": False,
                "error": "IAM clients not initialized. Please ensure MCP servers are configured or boto3 is available."
            }
        
        try:
            logger.info(f"🔧 Creating IAM policy: {policy_name}")
            
            arguments = {
                "policy_name": policy_name,
                "policy_document": json.dumps(policy_document),
            }
            
            if description:
                arguments["description"] = description
            if path:
                arguments["path"] = path
            
            # Try MCP first
            result = None
            if self.iam_client:
                tool_names = ['create_policy', 'iam_create_policy']
                for tool_name in tool_names:
                    try:
                        logger.debug(f"   Trying tool: {tool_name}")
                        result = self.iam_client.call_tool(tool_name, arguments)
                        if result and result.get('success'):
                            break
                    except Exception as e:
                        logger.debug(f"   Tool {tool_name} failed: {e}")
                        continue
            
            # If MCP failed, fallback to boto3
            if not result or not result.get('success'):
                if self.boto_iam:
                    return self._create_policy_boto3(policy_name, policy_document, description, path)
                error_msg = result.get('error', 'Unknown error') if result else 'Tool not found'
                return {
                    "success": False,
                    "error": f"Failed to create policy via MCP: {error_msg}. Please ensure the MCP server supports policy creation."
                }
            
            # Extract policy ARN from result
            data = result.get('data', {})
            policy_arn = None
            
            if isinstance(data, dict):
                policy_arn = (
                    data.get('policy_arn') or
                    data.get('Arn') or
                    data.get('Policy', {}).get('Arn') or
                    data.get('Policy', {}).get('PolicyArn')
                )
                
                if not policy_arn:
                    policy_arn = f"arn:aws:iam::ACCOUNT_ID:policy/{policy_name}"
                    logger.warning(f"⚠️ Could not extract ARN from response, using placeholder: {policy_arn}")
            
            logger.info(f"✅ Successfully created IAM policy: {policy_name}")
            return {
                "success": True,
                "policy_arn": policy_arn or f"arn:aws:iam::ACCOUNT_ID:policy/{policy_name}",
                "policy_name": policy_name,
                "message": f"IAM policy '{policy_name}' created successfully"
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to create policy: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    
    def attach_policy_to_role(
        self,
        role_name: str,
        policy_arn: str
    ) -> Dict[str, Any]:
        """
        Attach a managed policy to a role using MCP or boto3
        
        Args:
            role_name: Name of the role
            policy_arn: ARN of the policy to attach
        
        Returns:
            Dict with 'success' and 'message' or 'error'
        """
        if not self.iam_client:
            return {
                "success": False,
                "error": "IAM client not initialized. You need iam:AttachRolePolicy permission."
            }
        
        try:
            logger.info(f"🔧 Attaching policy {policy_arn} to role {role_name}")
            
            arguments = {
                "role_name": role_name,
                "policy_arn": policy_arn
            }
            
            tool_names = ['attach_role_policy', 'iam_attach_role_policy']
            result = None
            
            for tool_name in tool_names:
                try:
                    result = self.iam_client.call_tool(tool_name, arguments)
                    if result.get('success'):
                        break
                except Exception as e:
                    logger.debug(f"   Tool {tool_name} failed: {e}")
                    continue
            
            if not result or not result.get('success'):
                error_msg = result.get('error', 'Unknown error') if result else 'Tool not found'
                return {
                    "success": False,
                    "error": f"Failed to attach policy via MCP: {error_msg}"
                }
            
            logger.info(f"✅ Successfully attached policy to role")
            return {
                "success": True,
                "message": f"Policy {policy_arn} attached to role {role_name} successfully"
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to attach policy: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def put_role_policy(
        self,
        role_name: str,
        policy_name: str,
        policy_document: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Attach an inline policy to a role using MCP or boto3
        
        Args:
            role_name: Name of the role
            policy_name: Name of the inline policy
            policy_document: Policy document (JSON dict)
        
        Returns:
            Dict with 'success' and 'message' or 'error'
        """
        # Try MCP first; fallback to boto3 if MCP unavailable
        if not self.iam_client and not self.boto_iam:
            return {
                "success": False,
                "error": "No IAM client available (MCP/boto3)."
            }
        
        try:
            logger.info(f"🔧 Adding inline policy {policy_name} to role {role_name}")
            
            arguments = {
                "role_name": role_name,
                "policy_name": policy_name,
                "policy_document": json.dumps(policy_document)
            }
            
            result = None
            if self.iam_client:
                tool_names = ['put_role_policy', 'iam_put_role_policy']
                for tool_name in tool_names:
                    try:
                        result = self.iam_client.call_tool(tool_name, arguments)
                        if result and result.get('success'):
                            break
                    except Exception as e:
                        logger.debug(f"   Tool {tool_name} failed: {e}")
                        continue
            
            if (not result or not result.get('success')) and self.boto_iam:
                # fallback to boto3
                try:
                    self.boto_iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(policy_document)
                    )
                    return {
                        "success": True,
                        "message": f"Inline policy '{policy_name}' added to role {role_name} via boto3"
                    }
                except ClientError as e:
                    error_msg = e.response.get('Error', {}).get('Message', str(e))
                    return {"success": False, "error": f"boto3 put_role_policy failed: {error_msg}"}
            
            if not result or not result.get('success'):
                error_msg = result.get('error', 'Unknown error') if result else 'Tool not found'
                return {
                    "success": False,
                    "error": f"Failed to add inline policy via MCP: {error_msg}"
                }
            
            logger.info(f"✅ Successfully added inline policy to role")
            return {
                "success": True,
                "message": f"Inline policy '{policy_name}' added to role {role_name} successfully"
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to add inline policy: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def deploy_role_with_policy(
        self,
        role_name: str,
        trust_policy: Dict[str, Any],
        permissions_policy: Dict[str, Any],
        description: Optional[str] = None,
        deploy_as_inline: bool = True
    ) -> Dict[str, Any]:
        """
        Deploy a complete IAM role with policy (one-step deployment)
        
        Args:
            role_name: Name of the role to create
            trust_policy: Trust policy document
            permissions_policy: Permissions policy document
            description: Optional role description
            deploy_as_inline: If True, attach as inline policy. If False, create managed policy and attach.
        
        Returns:
            Dict with deployment results
        """
        results = {
            "success": False,
            "role_created": False,
            "policy_attached": False,
            "role_arn": None,
            "policy_arn": None,
            "errors": []
        }
        
        # Step 1: Create role
        role_result = self.create_role(role_name, trust_policy, description)
        if not role_result.get('success'):
            results["errors"].append(f"Failed to create role: {role_result.get('error')}")
            return results
        
        results["role_created"] = True
        results["role_arn"] = role_result.get('role_arn')
        
        # Step 2: Attach policy
        if deploy_as_inline:
            # Attach as inline policy
            policy_result = self.put_role_policy(
                role_name,
                f"{role_name}-Policy",
                permissions_policy
            )
        else:
            # Create managed policy first, then attach
            policy_name = f"{role_name}-Policy"
            policy_result = self.create_policy(policy_name, permissions_policy, description)
            
            if policy_result.get('success'):
                policy_arn = policy_result.get('policy_arn')
                results["policy_arn"] = policy_arn
                
                # Attach the managed policy
                attach_result = self.attach_policy_to_role(role_name, policy_arn)
                if attach_result.get('success'):
                    policy_result = attach_result
                else:
                    results["errors"].append(f"Failed to attach policy: {attach_result.get('error')}")
        
        if policy_result.get('success'):
            results["policy_attached"] = True
            if not results.get("policy_arn") and not deploy_as_inline:
                results["policy_arn"] = policy_result.get('policy_arn')
        else:
            results["errors"].append(f"Failed to attach policy: {policy_result.get('error')}")
        
        # Overall success if both steps succeeded
        results["success"] = results["role_created"] and results["policy_attached"]
        
        if results["success"]:
            logger.info(f"✅ Successfully deployed role {role_name} with policy")
        else:
            logger.error(f"❌ Failed to deploy role {role_name}: {results['errors']}")
        
        return results
    
    def delete_role(self, role_name: str) -> Dict[str, Any]:
        """
        Delete an IAM role and all attached policies
        
        Args:
            role_name: Name of the role to delete
            
        Returns:
            Dictionary with deletion status and details
        """
        logger.info(f"🗑️ Deleting IAM role: {role_name}")
        
        results = {
            "success": False,
            "role_name": role_name,
            "inline_policies_deleted": [],
            "managed_policies_detached": [],
            "role_deleted": False,
            "errors": []
        }
        
        try:
            # Using MCP only
            try:
                if not self.iam_client:
                    raise Exception("MCP IAM client not initialized")
                
                # Step 1: List and delete inline policies
                try:
                    # Inline policies
                    list_result = self.iam_client.call_tool('list_role_policies', {'role_name': role_name})
                    inline_policies = list_result.get('content', [{}])[0].get('text', '{}')
                    if isinstance(inline_policies, str):
                        try:
                            inline_policies = json.loads(inline_policies)
                        except Exception:
                            inline_policies = {}
                    if not inline_policies and list_result.get('data'):
                        inline_policies = getattr(list_result['data'], '__dict__', {})
                    for policy_name in inline_policies.get('policy_names', inline_policies.get('PolicyNames', [])):
                        delete_result = self.iam_client.call_tool(
                            'delete_role_policy',
                            {'role_name': role_name, 'policy_name': policy_name}
                        )
                        if delete_result and delete_result.get('success'):
                            results["inline_policies_deleted"].append(policy_name)
                            logger.info(f"   ✅ Deleted inline policy: {policy_name}")
                        else:
                            results["errors"].append(f"Could not delete inline policy {policy_name}: {delete_result.get('error') if delete_result else 'unknown error'}")
                except Exception as e:
                    logger.warning(f"Could not list/delete inline policies via MCP: {e}")
                
                # Managed policies
                try:
                    list_attached = self.iam_client.call_tool(
                        'list_attached_role_policies',
                        {'role_name': role_name}
                    )
                    attached_policies = list_attached.get('content', [{}])[0].get('text', '{}')
                    if isinstance(attached_policies, str):
                        try:
                            attached_policies = json.loads(attached_policies)
                        except Exception:
                            attached_policies = {}
                    if not attached_policies and list_attached.get('data'):
                        attached_policies = getattr(list_attached['data'], '__dict__', {})
                    for policy in attached_policies.get('AttachedPolicies', attached_policies.get('attached_policies', [])):
                        policy_arn = policy.get('PolicyArn') or policy.get('policy_arn')
                        if not policy_arn:
                            continue
                        detach_result = self.iam_client.call_tool(
                            'detach_role_policy',
                            {'role_name': role_name, 'policy_arn': policy_arn}
                        )
                        if detach_result and detach_result.get('success'):
                            results["managed_policies_detached"].append(policy_arn)
                            logger.info(f"   ✅ Detached managed policy: {policy_arn}")
                        else:
                            results["errors"].append(f"Could not detach {policy_arn}: {detach_result.get('error') if detach_result else 'unknown error'}")
                except Exception as e:
                    logger.warning(f"Could not list/detach managed policies via MCP: {e}")
                
                # Delete role
                delete_result = self.iam_client.call_tool(
                    'delete_role',
                    {'role_name': role_name}
                )
                if delete_result and delete_result.get('success'):
                    results["role_deleted"] = True
                    results["success"] = True
                    logger.info(f"✅ Successfully deleted role via MCP: {role_name}")
                else:
                    results["errors"].append(f"Delete role failed: {delete_result.get('error') if delete_result else 'unknown error'}")
                    results["success"] = False
                    logger.error(f"❌ Delete role failed via MCP: {delete_result}")
                
            except Exception as e:
                results["errors"].append(f"MCP error: {str(e)}")
                logger.error(f"❌ Failed to delete role via MCP: {e}")
        
        except Exception as e:
            results["errors"].append(f"Unexpected error: {str(e)}")
            logger.error(f"❌ Unexpected error deleting role: {e}")
        
        return results

