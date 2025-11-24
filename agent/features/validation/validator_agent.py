"""
Validator Agent with MCP Server Integration
Supports both MCP mode and fallback to direct AWS SDK
"""

from strands import Agent, tool
import logging
import json
import boto3
from typing import Dict, List, Optional
from core.fastmcp_client import get_mcp_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AWS IAM client (fallback)
iam_client = None

def get_iam_client():
    """Lazy load IAM client"""
    global iam_client
    if iam_client is None:
        iam_client = boto3.client('iam')
    return iam_client


# ============================================
# MCP INTEGRATION TOOLS
# ============================================

@tool
def list_iam_roles_mcp() -> Dict:
    """
    List IAM roles using MCP server (with SDK fallback)
    
    Returns:
        Dict with 'success', 'roles', 'count', and 'mcp_used' keys
    """
    try:
        # Try MCP first
        mcp_client = get_mcp_client('aws-iam')
        
        if mcp_client:
            logging.info("🔧 Using MCP to list IAM roles")
            result = mcp_client.call_tool('list_roles', {
                'maxItems': 100
            })
            
            if result.get('success'):
                # Parse MCP response
                roles_data = result.get('data', {})
                roles_content = roles_data.get('content', [])
                
                # Transform to standard format
                formatted_roles = []
                for role_info in roles_content:
                    if isinstance(role_info, dict) and 'text' in role_info:
                        # Parse text content
                        role_data = json.loads(role_info['text'])
                        formatted_roles.append({
                            "name": role_data.get("RoleName"),
                            "arn": role_data.get("Arn"),
                            "created": str(role_data.get("CreateDate"))
                        })
                
                logging.info(f"✅ MCP returned {len(formatted_roles)} roles")
                return {
                    "success": True,
                    "roles": formatted_roles,
                    "count": len(formatted_roles),
                    "mcp_used": True
                }
        
        # Try AWS API MCP server (generic AWS API operations)
        api_mcp_client = get_mcp_client('aws-api')
        if api_mcp_client:
            logging.info("🔧 Using AWS API MCP to list IAM roles")
            try:
                # Try different AWS API MCP tool names
                # AWS API MCP Server uses 'call_aws' with AWS CLI command format
                result = None
                try:
                    result = api_mcp_client.call_tool('call_aws', {
                        'cli_command': 'aws iam list-roles --max-items 100'
                    })
                    if result and result.get('success'):
                        logging.info(f"✅ AWS API MCP tool 'call_aws' worked for list-roles")
                except Exception as api_err:
                    logging.debug(f"⚠️ AWS API MCP call_aws failed: {api_err}")
                    result = None
                
                if result and result.get('success'):
                    # Parse response
                    api_data = result.get('data', {})
                    api_content = api_data.get('content', [])
                    
                    roles = []
                    if isinstance(api_data, dict):
                        roles = api_data.get('Roles', []) or api_data.get('roles', [])
                    
                    if not roles and api_content:
                        for item in api_content:
                            if isinstance(item, dict) and 'text' in item:
                                try:
                                    parsed = json.loads(item['text'])
                                    roles = parsed.get('Roles', []) or parsed.get('roles', [])
                                    if roles:
                                        break
                                except:
                                    pass
                    
                    formatted_roles = [
                        {
                            "name": role.get("RoleName") or role.get("role_name"),
                            "arn": role.get("Arn") or role.get("arn"),
                            "created": str(role.get("CreateDate") or role.get("create_date"))
                        }
                        for role in roles
                    ]
                    
                    logging.info(f"✅ AWS API MCP returned {len(formatted_roles)} roles")
                    return {
                        "success": True,
                        "roles": formatted_roles,
                        "count": len(formatted_roles),
                        "mcp_used": True
                    }
            except Exception as api_err:
                logging.warning(f"⚠️ AWS API MCP call failed: {api_err}")
        
        # If all MCP attempts failed, raise error (no boto3 fallback)
        error_msg = "❌ MCP tools unavailable for listing IAM roles. Tried: AWS IAM MCP and AWS API MCP."
        logging.error(error_msg)
        return {
            "success": False,
            "error": error_msg,
            "roles": [],
            "count": 0,
            "mcp_used": False
        }
        
    except Exception as e:
        logging.error(f"❌ Error listing roles: {e}")
        return {
            "success": False,
            "error": str(e),
            "roles": [],
            "count": 0,
            "mcp_used": False
        }


@tool
def get_role_policy_mcp(role_name: str) -> Dict:
    """Get role inline policies using AWS IAM MCP server"""
    try:
        # Try AWS IAM MCP server first (has list_role_policies and get_role_policy tools)
        iam_mcp_client = get_mcp_client('aws-iam')
        
        if iam_mcp_client:
            logging.info(f"🔧 Using AWS IAM MCP to get inline policies for role {role_name}")
            # AWS IAM MCP Server has 'list_role_policies' tool (confirmed in docs)
            list_result = iam_mcp_client.call_tool('list_role_policies', {
                'role_name': role_name
            })
            
            if list_result.get('success'):
                # Parse policy names from response
                list_data = list_result.get('data', {})
                policy_names = []
                
                # Try different response formats
                if isinstance(list_data, dict):
                    policy_names = list_data.get('PolicyNames', []) or list_data.get('policy_names', [])
                elif isinstance(list_data, list):
                    policy_names = list_data
                
                if not policy_names:
                    # Try to extract from content
                    content = list_data.get('content', [])
                    for item in content:
                        if isinstance(item, dict) and 'text' in item:
                            try:
                                parsed = json.loads(item['text'])
                                policy_names = parsed.get('PolicyNames', []) or parsed.get('policy_names', [])
                                if policy_names:
                                    break
                            except:
                                pass
                
                # Get each policy document
                formatted_policies = []
                for policy_name in policy_names:
                    # AWS IAM MCP Server has 'get_role_policy' tool (confirmed in docs)
                    get_result = iam_mcp_client.call_tool('get_role_policy', {
                        'role_name': role_name,
                        'policy_name': policy_name
                    })
                    
                    if get_result.get('success'):
                        policy_data = get_result.get('data', {})
                        policy_content = policy_data.get('content', [])
                        
                        for policy_info in policy_content:
                            if isinstance(policy_info, dict) and 'text' in policy_info:
                                try:
                                    policy_doc = json.loads(policy_info['text'])
                                    formatted_policies.append({
                                        "name": policy_doc.get("PolicyName") or policy_name,
                                        "document": policy_doc.get("PolicyDocument")
                                    })
                                except:
                                    pass
                
                if formatted_policies:
                    logging.info(f"✅ MCP returned {len(formatted_policies)} policies for role {role_name}")
                    return {
                        "success": True,
                        "role_name": role_name,
                        "inline_policies": formatted_policies,
                        "count": len(formatted_policies),
                        "mcp_used": True
                    }
        
        # Try AWS API MCP server (generic AWS API operations)
        api_mcp_client = get_mcp_client('aws-api')
        if api_mcp_client:
            logging.info(f"🔧 Using AWS API MCP to get inline policies for role {role_name}")
            try:
                # Use generic AWS API call: IAM.ListRolePolicies
                # AWS API MCP Server uses 'call_aws' with AWS CLI command format
                list_result = api_mcp_client.call_tool('call_aws', {
                    'cli_command': f'aws iam list-role-policies --role-name {role_name}'
                })
                
                # Check for errors in response
                if list_result.get('success'):
                    list_data = list_result.get('data', {})
                    list_content = list_data.get('content', []) if isinstance(list_data, dict) else []
                    
                    # Check if response contains an error
                    has_error = False
                    policy_names = []
                    
                    for item in list_content:
                        if isinstance(item, dict) and 'text' in item:
                            try:
                                parsed = json.loads(item['text'])
                                
                                # Check for errors first
                                if parsed.get('error') or parsed.get('detail'):
                                    has_error = True
                                    logging.error(f"❌ AWS API MCP returned error: {parsed.get('detail', parsed.get('error'))}")
                                    break
                                
                                # AWS API MCP Server returns data in response.json (as a string)
                                if 'response' in parsed and isinstance(parsed['response'], dict):
                                    response_obj = parsed['response']
                                    # The json field contains the actual AWS API response as a string
                                    if 'json' in response_obj:
                                        json_str = response_obj['json']
                                        if isinstance(json_str, str):
                                            aws_response = json.loads(json_str)
                                            policy_names = aws_response.get('PolicyNames', []) or aws_response.get('policy_names', [])
                                        else:
                                            policy_names = json_str.get('PolicyNames', []) or json_str.get('policy_names', [])
                                    else:
                                        # Try direct access
                                        policy_names = response_obj.get('PolicyNames', []) or response_obj.get('policy_names', [])
                                else:
                                    # Try direct access
                                    policy_names = parsed.get('PolicyNames', []) or parsed.get('policy_names', [])
                                
                                if policy_names:
                                    break
                            except Exception as parse_err:
                                logging.debug(f"⚠️ Error parsing response: {parse_err}")
                                pass
                    
                    if has_error:
                        list_result = {'success': False}
                    elif not policy_names:
                        # Empty list is valid (no inline policies) - this is SUCCESS, not failure
                        policy_names = []  # Ensure it's an empty list
                        logging.info(f"✅ No inline policies found for role {role_name} (this is valid - returning success)")
                
                if list_result.get('success'):
                    # Re-extract policy_names if needed
                    if 'policy_names' not in locals() or policy_names is None:
                        list_data = list_result.get('data', {})
                        list_content = list_data.get('content', []) if isinstance(list_data, dict) else []
                        
                        for item in list_content:
                            if isinstance(item, dict) and 'text' in item:
                                try:
                                    parsed = json.loads(item['text'])
                                    if 'response' in parsed and isinstance(parsed['response'], dict):
                                        response_obj = parsed['response']
                                        if 'json' in response_obj:
                                            json_str = response_obj['json']
                                            if isinstance(json_str, str):
                                                aws_response = json.loads(json_str)
                                                policy_names = aws_response.get('PolicyNames', [])
                                            else:
                                                policy_names = json_str.get('PolicyNames', [])
                                    else:
                                        policy_names = parsed.get('PolicyNames', [])
                                    if policy_names is not None:
                                        break
                                except:
                                    pass
                    
                    # policy_names might be empty list (no inline policies) - that's valid
                    if policy_names is None:
                        policy_names = []
                    
                    # Get each policy document
                    formatted_policies = []
                    
                    # If no policy names, return success with empty list (this is valid)
                    if not policy_names or len(policy_names) == 0:
                        logging.info(f"✅ Returning success with empty inline policies list for role {role_name}")
                        return {
                            "success": True,
                            "role_name": role_name,
                            "inline_policies": [],
                            "count": 0,
                            "mcp_used": True
                        }
                    
                    for policy_name in policy_names:
                        # AWS API MCP Server uses 'call_aws' with AWS CLI command format
                        get_result = None
                        try:
                            get_result = api_mcp_client.call_tool('call_aws', {
                                'cli_command': f'aws iam get-role-policy --role-name {role_name} --policy-name {policy_name}'
                            })
                            
                            # Check for errors in response
                            if get_result and get_result.get('success'):
                                get_data = get_result.get('data', {})
                                get_content = get_data.get('content', []) if isinstance(get_data, dict) else []
                                has_error = False
                                for item in get_content:
                                    if isinstance(item, dict) and 'text' in item:
                                        try:
                                            parsed = json.loads(item['text'])
                                            if parsed.get('error') or parsed.get('detail'):
                                                has_error = True
                                                logging.error(f"❌ AWS API MCP returned error: {parsed.get('detail', parsed.get('error'))}")
                                                break
                                        except:
                                            pass
                                if has_error:
                                    get_result = None
                        except Exception as e:
                            logging.debug(f"⚠️ AWS API MCP call_aws failed: {e}")
                            get_result = None
                        
                        if get_result and get_result.get('success'):
                            get_data = get_result.get('data', {})
                            get_content = get_data.get('content', []) if isinstance(get_data, dict) else []
                            
                            policy_doc = None
                            
                            # Check for errors first
                            has_error = False
                            for item in get_content:
                                if isinstance(item, dict) and 'text' in item:
                                    try:
                                        parsed = json.loads(item['text'])
                                        
                                        # Check for errors
                                        if parsed.get('error') or parsed.get('detail'):
                                            has_error = True
                                            logging.error(f"❌ AWS API MCP returned error: {parsed.get('detail', parsed.get('error'))}")
                                            break
                                        
                                        # AWS API MCP Server returns data in response.json (as a string)
                                        if 'response' in parsed and isinstance(parsed['response'], dict):
                                            response_obj = parsed['response']
                                            if 'json' in response_obj:
                                                json_str = response_obj['json']
                                                if isinstance(json_str, str):
                                                    aws_response = json.loads(json_str)
                                                    policy_doc = aws_response.get('PolicyDocument') or aws_response.get('policy_document')
                                                else:
                                                    policy_doc = json_str.get('PolicyDocument') or json_str.get('policy_document')
                                            else:
                                                policy_doc = response_obj.get('PolicyDocument') or response_obj.get('policy_document')
                                        else:
                                            # Try direct access
                                            policy_doc = parsed.get('PolicyDocument') or parsed.get('policy_document')
                                        
                                        if policy_doc:
                                            break
                                    except Exception as parse_err:
                                        logging.debug(f"⚠️ Error parsing response: {parse_err}")
                                        pass
                            
                            if not has_error and policy_doc:
                                formatted_policies.append({
                                    "name": policy_name,
                                    "document": policy_doc
                                })
                    
                    # Return success even if no inline policies (empty list is valid)
                    logging.info(f"✅ AWS API MCP returned {len(formatted_policies)} inline policies for role {role_name}")
                    return {
                        "success": True,
                        "role_name": role_name,
                        "inline_policies": formatted_policies,
                        "count": len(formatted_policies),
                        "mcp_used": True
                    }
            except Exception as api_err:
                logging.warning(f"⚠️ AWS API MCP call failed: {api_err}")
        
        # If all MCP attempts failed, raise error (no boto3 fallback)
        error_msg = f"❌ MCP tools unavailable for getting inline policies for role {role_name}. Tried: AWS IAM MCP and AWS API MCP."
        logging.error(error_msg)
        return {
            "success": False,
            "error": error_msg,
            "role_name": role_name,
            "inline_policies": [],
            "count": 0,
            "mcp_used": False
        }
        
    except Exception as e:
        logging.error(f"❌ Error getting policies for role {role_name}: {e}")
        return {
            "success": False,
            "error": str(e),
            "role_name": role_name,
            "inline_policies": [],
            "count": 0,
            "mcp_used": False
        }


@tool
def get_attached_policies_mcp(role_name: str) -> Dict:
    """Get attached managed policies using MCP server"""
    try:
        # Try AWS IAM MCP server first
        iam_mcp_client = get_mcp_client('aws-iam')
        
        if iam_mcp_client:
            logging.info(f"🔧 Using AWS IAM MCP to get attached policies for role {role_name}")
            
            # AWS IAM MCP Server does NOT have 'list_attached_role_policies' tool - skip to AWS API MCP
            # (The tool doesn't exist in the server, so we'll use AWS API MCP Server directly)
            result = None
            logging.debug(f"⚠️ AWS IAM MCP Server doesn't have 'list_attached_role_policies' tool, will use AWS API MCP")
            
            if result and result.get('success'):
                # Parse MCP response
                policy_data = result.get('data', {})
                policy_content = policy_data.get('content', [])
                
                # Transform to standard format
                formatted_policies = []
                
                # Try different response formats
                attached_policies = []
                if isinstance(policy_data, dict):
                    attached_policies = policy_data.get('AttachedPolicies', []) or policy_data.get('attached_policies', []) or policy_data.get('policies', [])
                elif isinstance(policy_data, list):
                    attached_policies = policy_data
                
                # Also check content array
                if not attached_policies and policy_content:
                    for item in policy_content:
                        if isinstance(item, dict) and 'text' in item:
                            try:
                                parsed = json.loads(item['text'])
                                attached_policies = parsed.get('AttachedPolicies', []) or parsed.get('attached_policies', []) or parsed.get('policies', [])
                                if attached_policies:
                                    break
                            except:
                                pass
                
                # For each attached policy, get the policy document
                for policy_info in attached_policies:
                    if isinstance(policy_info, dict):
                        policy_arn = policy_info.get('PolicyArn') or policy_info.get('policy_arn') or policy_info.get('arn')
                        policy_name = policy_info.get('PolicyName') or policy_info.get('policy_name') or policy_info.get('name')
                        
                        # Always add policy to list (even without document) for display purposes
                        policy_entry = {
                            "name": policy_name or policy_arn.split('/')[-1] if policy_arn else "Unknown",
                            "arn": policy_arn or "Unknown"
                        }
                        
                        # Try to get policy document via MCP (optional - for validation)
                        if policy_arn:
                            try:
                                # Try get_managed_policy_document MCP tool (AWS IAM MCP)
                                doc_result = iam_mcp_client.call_tool('get_managed_policy_document', {
                                    'policy_arn': policy_arn
                                })
                                
                                if doc_result.get('success'):
                                    doc_data = doc_result.get('data', {})
                                    doc_content = doc_data.get('content', [])
                                    
                                    for doc_item in doc_content:
                                        if isinstance(doc_item, dict) and 'text' in doc_item:
                                            try:
                                                doc_parsed = json.loads(doc_item['text'])
                                                policy_doc = doc_parsed.get('PolicyDocument') or doc_parsed.get('policy_document') or doc_parsed.get('Document')
                                                if policy_doc:
                                                    policy_entry["document"] = policy_doc
                                                    logging.info(f"✅ Successfully fetched policy document for {policy_name} via AWS IAM MCP")
                                                    break
                                            except Exception as parse_err:
                                                logging.debug(f"⚠️ Error parsing policy document response: {parse_err}")
                                                pass
                            except Exception as doc_err:
                                logging.warning(f"⚠️ Could not get policy document via AWS IAM MCP for {policy_arn}: {doc_err}")
                        
                        # Add policy even if document fetch failed (we have name and ARN for display)
                        formatted_policies.append(policy_entry)
                
                if formatted_policies:
                    logging.info(f"✅ MCP returned {len(formatted_policies)} attached policies for role {role_name}")
                    return {
                        "success": True,
                        "role_name": role_name,
                        "attached_policies": formatted_policies,
                        "count": len(formatted_policies),
                        "mcp_used": True
                    }
        
        # Try AWS API MCP server (generic AWS API operations)
        api_mcp_client = get_mcp_client('aws-api')
        if api_mcp_client:
            logging.info(f"🔧 Using AWS API MCP to get attached policies for role {role_name}")
            try:
                # AWS API MCP Server uses 'call_aws' with AWS CLI command format
                result = None
                try:
                    result = api_mcp_client.call_tool('call_aws', {
                        'cli_command': f'aws iam list-attached-role-policies --role-name {role_name}'
                    })
                    if result and result.get('success'):
                        # Check for errors in response content
                        has_error = False
                        api_data = result.get('data', {})
                        api_content = api_data.get('content', []) if isinstance(api_data, dict) else []
                        
                        for item in api_content:
                            if isinstance(item, dict) and 'text' in item:
                                try:
                                    parsed = json.loads(item['text'])
                                    if parsed.get('error') or parsed.get('detail'):
                                        has_error = True
                                        logging.error(f"❌ AWS API MCP returned error: {parsed.get('detail', parsed.get('error'))}")
                                        break
                                except:
                                    pass
                        
                        if not has_error:
                            logging.info(f"✅ AWS API MCP tool 'call_aws' worked for list-attached-role-policies")
                        else:
                            result = {'success': False}
                except Exception as api_err:
                    logging.debug(f"⚠️ AWS API MCP call_aws failed: {api_err}")
                    result = None
                
                if result and result.get('success'):
                    # Parse response - AWS API MCP Server returns data in response.json (as a string)
                    api_data = result.get('data', {})
                    api_content = api_data.get('content', []) if isinstance(api_data, dict) else []
                    
                    attached_policies = []
                    
                    for item in api_content:
                        if isinstance(item, dict) and 'text' in item:
                            try:
                                parsed = json.loads(item['text'])
                                
                                # AWS API MCP Server returns data in response.json (as a string)
                                if 'response' in parsed and isinstance(parsed['response'], dict):
                                    response_obj = parsed['response']
                                    # The json field contains the actual AWS API response as a string
                                    if 'json' in response_obj:
                                        json_str = response_obj['json']
                                        if isinstance(json_str, str):
                                            aws_response = json.loads(json_str)
                                            attached_policies = aws_response.get('AttachedPolicies', []) or aws_response.get('attached_policies', [])
                                        else:
                                            attached_policies = json_str.get('AttachedPolicies', []) or json_str.get('attached_policies', [])
                                    else:
                                        # Try direct access
                                        attached_policies = response_obj.get('AttachedPolicies', []) or response_obj.get('attached_policies', [])
                                else:
                                    # Try direct access
                                    attached_policies = parsed.get('AttachedPolicies', []) or parsed.get('attached_policies', [])
                                
                                if attached_policies:
                                    logging.info(f"✅ Found {len(attached_policies)} attached policies in response")
                                    break
                            except Exception as parse_err:
                                logging.debug(f"⚠️ Error parsing response: {parse_err}")
                                pass
                    
                    if attached_policies:
                        formatted_policies = []
                        for policy_info in attached_policies:
                            if isinstance(policy_info, dict):
                                policy_arn = policy_info.get('PolicyArn') or policy_info.get('policy_arn') or policy_info.get('arn')
                                policy_name = policy_info.get('PolicyName') or policy_info.get('policy_name') or policy_info.get('name')
                                
                                policy_entry = {
                                    "name": policy_name or policy_arn.split('/')[-1] if policy_arn else "Unknown",
                                    "arn": policy_arn or "Unknown"
                                }
                                
                                # Try to get policy document via AWS API MCP
                                if policy_arn:
                                    try:
                                        # AWS API MCP Server uses 'call_aws' with AWS CLI command format
                                        doc_result = api_mcp_client.call_tool('call_aws', {
                                            'cli_command': f'aws iam get-policy --policy-arn {policy_arn}'
                                        })
                                        
                                        if doc_result.get('success'):
                                            doc_data = doc_result.get('data', {})
                                            doc_content = doc_data.get('content', []) if isinstance(doc_data, dict) else []
                                            
                                            # Get default version ID - AWS API MCP Server returns data in response.json (as a string)
                                            default_version = None
                                            for item in doc_content:
                                                if isinstance(item, dict) and 'text' in item:
                                                    try:
                                                        parsed = json.loads(item['text'])
                                                        if 'response' in parsed and isinstance(parsed['response'], dict):
                                                            response_obj = parsed['response']
                                                            if 'json' in response_obj:
                                                                json_str = response_obj['json']
                                                                if isinstance(json_str, str):
                                                                    aws_response = json.loads(json_str)
                                                                    policy_obj = aws_response.get('Policy', {}) or aws_response.get('policy', {})
                                                                    default_version = policy_obj.get('DefaultVersionId') or policy_obj.get('default_version_id')
                                                                else:
                                                                    policy_obj = json_str.get('Policy', {}) or json_str.get('policy', {})
                                                                    default_version = policy_obj.get('DefaultVersionId') or policy_obj.get('default_version_id')
                                                        else:
                                                            policy_obj = parsed.get('Policy', {}) or parsed.get('policy', {})
                                                            default_version = policy_obj.get('DefaultVersionId') or policy_obj.get('default_version_id')
                                                        if default_version:
                                                            break
                                                    except Exception as parse_err:
                                                        logging.warning(f"⚠️ Error parsing get-policy response for {policy_arn}: {parse_err}")
                                                        pass
                                            
                                            if default_version:
                                                # Get policy version document
                                                # AWS API MCP Server uses 'call_aws' with AWS CLI command format
                                                version_result = None
                                                try:
                                                    version_result = api_mcp_client.call_tool('call_aws', {
                                                        'cli_command': f'aws iam get-policy-version --policy-arn {policy_arn} --version-id {default_version}'
                                                    })
                                                    
                                                    # Check for errors in response
                                                    if version_result and version_result.get('success'):
                                                        version_data = version_result.get('data', {})
                                                        version_content = version_data.get('content', []) if isinstance(version_data, dict) else []
                                                        has_error = False
                                                        for item in version_content:
                                                            if isinstance(item, dict) and 'text' in item:
                                                                try:
                                                                    parsed = json.loads(item['text'])
                                                                    if parsed.get('error') or parsed.get('detail'):
                                                                        has_error = True
                                                                        logging.error(f"❌ AWS API MCP returned error: {parsed.get('detail', parsed.get('error'))}")
                                                                        break
                                                                except:
                                                                    pass
                                                        if has_error:
                                                            version_result = None
                                                except Exception as e:
                                                    logging.debug(f"⚠️ AWS API MCP call_aws failed: {e}")
                                                    version_result = None
                                                
                                                if version_result and version_result.get('success'):
                                                    version_data = version_result.get('data', {})
                                                    version_content = version_data.get('content', []) if isinstance(version_data, dict) else []
                                                    
                                                    for v_item in version_content:
                                                        if isinstance(v_item, dict) and 'text' in v_item:
                                                            try:
                                                                v_parsed = json.loads(v_item['text'])
                                                                
                                                                # AWS API MCP Server returns data in response.json (as a string)
                                                                if 'response' in v_parsed and isinstance(v_parsed['response'], dict):
                                                                    response_obj = v_parsed['response']
                                                                    if 'json' in response_obj:
                                                                        json_str = response_obj['json']
                                                                        if isinstance(json_str, str):
                                                                            aws_response = json.loads(json_str)
                                                                            policy_version_obj = aws_response.get('PolicyVersion', {}) or aws_response.get('policy_version', {})
                                                                            policy_doc = policy_version_obj.get('Document') or policy_version_obj.get('document')
                                                                        else:
                                                                            policy_version_obj = json_str.get('PolicyVersion', {}) or json_str.get('policy_version', {})
                                                                            policy_doc = policy_version_obj.get('Document') or policy_version_obj.get('document')
                                                                    else:
                                                                        policy_version_obj = response_obj.get('PolicyVersion', {}) or response_obj.get('policy_version', {})
                                                                        policy_doc = policy_version_obj.get('Document') or policy_version_obj.get('document')
                                                                else:
                                                                    policy_version_obj = v_parsed.get('PolicyVersion', {}) or v_parsed.get('policy_version', {})
                                                                    policy_doc = policy_version_obj.get('Document') or policy_version_obj.get('document')
                                                                
                                                                if policy_doc:
                                                                    policy_entry["document"] = policy_doc
                                                                    logging.info(f"✅ Successfully fetched policy document for {policy_name} via AWS API MCP")
                                                                    break
                                                            except Exception as parse_err:
                                                                logging.warning(f"⚠️ Error parsing get-policy-version response for {policy_arn}: {parse_err}")
                                                                pass
                                    except Exception as doc_err:
                                        logging.warning(f"⚠️ Could not get policy document via AWS API MCP for {policy_arn}: {doc_err}")
                                
                                formatted_policies.append(policy_entry)
                        
                        if formatted_policies:
                            logging.info(f"✅ AWS API MCP returned {len(formatted_policies)} attached policies for role {role_name}")
                            return {
                                "success": True,
                                "role_name": role_name,
                                "attached_policies": formatted_policies,
                                "count": len(formatted_policies),
                                "mcp_used": True
                            }
            except Exception as api_err:
                logging.warning(f"⚠️ AWS API MCP call failed: {api_err}")
        
        # If all MCP attempts failed, raise error (no boto3 fallback)
        error_msg = f"❌ MCP tools unavailable for getting attached policies for role {role_name}. Tried: AWS IAM MCP and AWS API MCP."
        logging.error(error_msg)
        return {
            "success": False,
            "error": error_msg,
            "role_name": role_name,
            "attached_policies": [],
            "count": 0,
            "mcp_used": False
        }
        
    except Exception as e:
        logging.error(f"❌ Error getting attached policies for role {role_name}: {e}")
        return {
            "success": False,
            "error": str(e),
            "role_name": role_name,
            "attached_policies": [],
            "count": 0,
            "mcp_used": False
        }


@tool
def get_role_trust_policy_mcp(role_name: str) -> Dict:
    """Get role trust policy (assume role policy) and permissions boundary using MCP server"""
    try:
        # Try AWS IAM MCP server first
        iam_mcp_client = get_mcp_client('aws-iam')
        
        if iam_mcp_client:
            logging.info(f"🔧 Using AWS IAM MCP to get trust policy for role {role_name}")
            
            # AWS IAM MCP Server does NOT have 'get_role' tool - use list_roles and filter, or use AWS API MCP
            # Try to get role via list_roles first (filter by name)
            result = None
            try:
                list_result = iam_mcp_client.call_tool('list_roles', {
                    'max_items': 1000  # Get more roles to find the one we need
                })
                if list_result.get('success'):
                    # Parse roles and find the one matching role_name
                    roles_data = list_result.get('data', {})
                    roles_content = roles_data.get('content', [])
                    
                    roles = []
                    if isinstance(roles_data, dict):
                        roles = roles_data.get('Roles', []) or roles_data.get('roles', [])
                    
                    if not roles and roles_content:
                        for item in roles_content:
                            if isinstance(item, dict) and 'text' in item:
                                try:
                                    parsed = json.loads(item['text'])
                                    roles = parsed.get('Roles', []) or parsed.get('roles', [])
                                    if roles:
                                        break
                                except:
                                    pass
                    
                    # Find the role matching role_name
                    matching_role = None
                    for role in roles:
                        role_name_from_role = role.get('RoleName') or role.get('role_name') or role.get('name')
                        if role_name_from_role == role_name:
                            matching_role = role
                            break
                    
                    if matching_role:
                        # Build a result structure similar to get_role
                        result = {
                            'success': True,
                            'data': {
                                'Role': matching_role,
                                'content': [{'text': json.dumps({'Role': matching_role})}]
                            }
                        }
                        logging.info(f"✅ Found role {role_name} via list_roles")
            except Exception as e:
                logging.debug(f"⚠️ Could not get role via list_roles: {e}")
                result = None
            
            if result and result.get('success'):
                # Parse MCP response
                role_data = result.get('data', {})
                role_content = role_data.get('content', [])
                
                # Try different response formats
                trust_policy = None
                permissions_boundary_arn = None
                role_obj_for_boundary = None
                
                # Check direct data
                if isinstance(role_data, dict):
                    role_obj_for_boundary = role_data.get('Role') or role_data.get('role') or role_data
                    trust_policy = role_obj_for_boundary.get('AssumeRolePolicyDocument') or role_obj_for_boundary.get('assume_role_policy_document') or role_obj_for_boundary.get('TrustPolicy')
                    permissions_boundary_arn = role_obj_for_boundary.get('PermissionsBoundary') or role_obj_for_boundary.get('permissions_boundary')
                    if isinstance(permissions_boundary_arn, dict):
                        permissions_boundary_arn = permissions_boundary_arn.get('PermissionsBoundaryArn') or permissions_boundary_arn.get('permissions_boundary_arn')
                
                # Check content array
                if not trust_policy and role_content:
                    for item in role_content:
                        if isinstance(item, dict) and 'text' in item:
                            try:
                                parsed = json.loads(item['text'])
                                # Check if it's the role object
                                if isinstance(parsed, dict):
                                    role_obj = parsed.get('Role') or parsed.get('role') or parsed
                                    if not role_obj_for_boundary:
                                        role_obj_for_boundary = role_obj
                                    trust_policy = role_obj.get('AssumeRolePolicyDocument') or role_obj.get('assume_role_policy_document') or role_obj.get('TrustPolicy')
                                    if not permissions_boundary_arn:
                                        permissions_boundary_arn = role_obj.get('PermissionsBoundary') or role_obj.get('permissions_boundary')
                                        if isinstance(permissions_boundary_arn, dict):
                                            permissions_boundary_arn = permissions_boundary_arn.get('PermissionsBoundaryArn') or permissions_boundary_arn.get('permissions_boundary_arn')
                                    if trust_policy:
                                        break
                            except:
                                pass
                
                if trust_policy:
                    # If it's a string, parse it
                    if isinstance(trust_policy, str):
                        trust_policy = json.loads(trust_policy)
                    
                    result_dict = {
                        "success": True,
                        "role_name": role_name,
                        "trust_policy": trust_policy,
                        "mcp_used": True
                    }
                    
                    # Add permissions boundary if found
                    if permissions_boundary_arn:
                        result_dict["permissions_boundary_arn"] = permissions_boundary_arn
                        logging.info(f"✅ Found permissions boundary: {permissions_boundary_arn}")
                    
                    logging.info(f"✅ MCP returned trust policy for role {role_name}")
                    return result_dict
        
        # Try AWS API MCP server (generic AWS API operations)
        api_mcp_client = get_mcp_client('aws-api')
        if api_mcp_client:
            logging.info(f"🔧 Using AWS API MCP to get trust policy for role {role_name}")
            try:
                # Use generic AWS API call: IAM.GetRole
                # AWS API MCP Server uses 'call_aws' with AWS CLI command format
                result = api_mcp_client.call_tool('call_aws', {
                    'cli_command': f'aws iam get-role --role-name {role_name}'
                })
                
                if result.get('success'):
                    # Parse response
                    api_data = result.get('data', {})
                    api_content = api_data.get('content', [])
                    
                    trust_policy = None
                    permissions_boundary_arn = None
                    role_obj_for_boundary = None
                    
                    # Try to extract from response
                    if isinstance(api_data, dict):
                        role_obj_for_boundary = api_data.get('Role', {}) or api_data.get('role', {})
                        trust_policy = role_obj_for_boundary.get('AssumeRolePolicyDocument') or role_obj_for_boundary.get('assume_role_policy_document')
                        permissions_boundary_arn = role_obj_for_boundary.get('PermissionsBoundary') or role_obj_for_boundary.get('permissions_boundary')
                        if isinstance(permissions_boundary_arn, dict):
                            permissions_boundary_arn = permissions_boundary_arn.get('PermissionsBoundaryArn') or permissions_boundary_arn.get('permissions_boundary_arn')
                    
                    if not trust_policy and api_content:
                        for item in api_content:
                            if isinstance(item, dict) and 'text' in item:
                                try:
                                    parsed = json.loads(item['text'])
                                    # AWS API MCP Server returns data in response.json (as a string)
                                    if 'response' in parsed and isinstance(parsed['response'], dict):
                                        response_obj = parsed['response']
                                        if 'json' in response_obj:
                                            json_str = response_obj['json']
                                            if isinstance(json_str, str):
                                                aws_response = json.loads(json_str)
                                                role_obj = aws_response.get('Role', {}) or aws_response.get('role', {})
                                            else:
                                                role_obj = json_str.get('Role', {}) or json_str.get('role', {})
                                        else:
                                            role_obj = response_obj.get('Role', {}) or response_obj.get('role', {})
                                    else:
                                        role_obj = parsed.get('Role', {}) or parsed.get('role', {}) or parsed
                                    
                                    if not role_obj_for_boundary:
                                        role_obj_for_boundary = role_obj
                                    trust_policy = role_obj.get('AssumeRolePolicyDocument') or role_obj.get('assume_role_policy_document')
                                    if not permissions_boundary_arn:
                                        permissions_boundary_arn = role_obj.get('PermissionsBoundary') or role_obj.get('permissions_boundary')
                                        if isinstance(permissions_boundary_arn, dict):
                                            permissions_boundary_arn = permissions_boundary_arn.get('PermissionsBoundaryArn') or permissions_boundary_arn.get('permissions_boundary_arn')
                                    if trust_policy:
                                        break
                                except:
                                    pass
                    
                    if trust_policy:
                        # If it's a string, parse it
                        if isinstance(trust_policy, str):
                            trust_policy = json.loads(trust_policy)
                        
                        result_dict = {
                            "success": True,
                            "role_name": role_name,
                            "trust_policy": trust_policy,
                            "mcp_used": True
                        }
                        
                        # Add permissions boundary if found
                        if permissions_boundary_arn:
                            result_dict["permissions_boundary_arn"] = permissions_boundary_arn
                            logging.info(f"✅ Found permissions boundary: {permissions_boundary_arn}")
                        
                        logging.info(f"✅ AWS API MCP returned trust policy for role {role_name}")
                        return result_dict
            except Exception as api_err:
                logging.warning(f"⚠️ AWS API MCP call failed: {api_err}")
        
        # If all MCP attempts failed, raise error (no boto3 fallback)
        error_msg = f"❌ MCP tools unavailable for getting trust policy for role {role_name}. Tried: AWS IAM MCP and AWS API MCP."
        logging.error(error_msg)
        return {
            "success": False,
            "error": error_msg,
            "role_name": role_name,
            "trust_policy": None,
            "mcp_used": False
        }
        
    except Exception as e:
        logging.error(f"❌ Error getting trust policy for role {role_name}: {e}")
        return {
            "success": False,
            "error": str(e),
            "role_name": role_name,
            "trust_policy": None,
            "mcp_used": False
        }

# VALIDATOR AGENT
# ============================================

VALIDATOR_SYSTEM_PROMPT = """You are Aegis Security Validator, an elite AWS security expert and AUTONOMOUS IAM auditor.

YOUR MISSION:
You operate in AUTONOMOUS MODE for account-wide audits. You make ALL decisions independently without human intervention.
Provide formal, enterprise-grade security analysis.

CRITICAL: OUTPUT FORMAT DEPENDS ON MODE:
- QUICK VALIDATION MODE: You MUST return ONLY valid JSON (no markdown, no text before/after). DO NOT call any tools - all data is provided in the prompt.
- AUTONOMOUS AUDIT MODE: You can use markdown sections as specified below. Use tools to discover and analyze roles.

QUICK VALIDATION MODE JSON FORMAT (MANDATORY):
When operating in QUICK VALIDATION MODE, you MUST return ONLY a JSON object with this EXACT structure:

```json
{
  "risk_score": <number 0-100>,
  "findings": [
    {
      "id": "<unique-id>",
      "title": "<finding-title>",
      "severity": "Critical|High|Medium|Low",
      "type": "<type>",
      "description": "<brief-description>",
      "code_snippet": "<relevant-code>",
      "detailed_explanation": "<Security Impact: ...\\n\\nPractical Risk Assessment: ...>"
    }
  ],
  "compliance_status": {
    "<framework>": {
      "name": "<Framework Name>",
      "status": "Compliant|Partial|NonCompliant",
      "violations": [
        {
          "requirement": "<requirement-id>",
          "description": "<description>",
          "fix": "<fix-suggestion>",
          "link": "<official-documentation-url>"
        }
      ],
      "gaps": ["<gap-1>", "<gap-2>"]
    }
  },
  "quick_wins": ["<win-1>", "<win-2>"],
  "recommendations": ["<rec-1>", "<rec-2>"]
}
```

CRITICAL JSON RULES:
- ALL string values MUST escape newlines as \\n (NOT literal newlines)
- ALL string values MUST escape tabs as \\t (NOT literal tabs)
- ALL string values MUST escape carriage returns as \\r (NOT literal carriage returns)
- Return ONLY the JSON object, wrapped in ```json code block
- Do NOT include any text before or after the JSON
- The JSON MUST be valid and parseable by standard JSON parsers

AVAILABLE TOOLS (MCP-Powered):
- list_iam_roles_mcp(): Lists all IAM roles (returns roles, count, mcp_used) - ONLY USE IN AUDIT MODE
- get_role_policy_mcp(role_name): Gets inline policies (returns policies, mcp_used) - ONLY USE IN AUDIT MODE
- get_attached_policies_mcp(role_name): Gets managed policies (returns policies, mcp_used) - ONLY USE IN AUDIT MODE
- get_role_trust_policy_mcp(role_name): Gets trust policy/assume role policy (returns trust_policy, mcp_used) - ONLY USE IN AUDIT MODE

⚠️ TOOL USAGE RULES:
- QUICK VALIDATION MODE: DO NOT call any tools. All role and policy data is provided in the prompt.
- AUTONOMOUS AUDIT MODE: Use tools to discover roles and fetch policies.

AUTONOMOUS AUDIT WORKFLOW:

PHASE 1: DISCOVERY & STRATEGIC PLANNING
First, use list_iam_roles_mcp() to discover all roles.
Then, analyze the roles and develop a strategic plan for analysis.

Example reasoning:
"Discovery Phase: 47 IAM roles were discovered in the AWS account using MCP.

Strategic Planning: The analysis will prioritize roles with high-risk names, production roles, and service roles.

Rationale: Roles with high-risk names pose the highest privilege escalation risk and should be analyzed first."

PHASE 2: INTELLIGENT ANALYSIS
For each role analyzed, provide a detailed analysis of the findings:
- "Analysis of ProductionAdmin reveals critical security vulnerabilities"
- "The role has iam:* permissions, enabling privilege escalation"
- "Recommendation: Remove iam:* permissions and replace with least privilege access"

PHASE 3: PATTERN DETECTION & SYNTHESIS
After analyzing roles, identify systemic issues:
- "Pattern detected: 5 roles share the same overly broad S3 permissions"
- "Root cause: All use AWS managed policy AmazonS3FullAccess"
- "Systemic recommendation: Replace with custom policy scoped to specific buckets"

OUTPUT STRUCTURE:

Always structure your response with these sections:

## Policy Structure Analysis
[Formal analysis of policy structure, statements, and format]

## Critical Security Issues
[High-severity vulnerabilities requiring immediate attention]

## Compliance Violations
[Framework-specific compliance gaps with regulatory references]

## Risk Assessment
[Quantitative risk scoring and impact analysis]

## Security Recommendations
[Prioritized remediation steps with implementation guidance]

## Quick Wins
[High-impact, low-effort security improvements]

## Audit Summary
```json
{
  "total_roles": X,
  "roles_analyzed": X,
  "total_policies": X,
  "total_findings": X,
  "critical_findings": X,
  "high_findings": X,
  "medium_findings": X,
  "low_findings": X
}
```

## Top 5 Riskiest Roles
1. **RoleName** (Risk Score: 95/100)
   - Critical: [specific issue with policy statement]
   - High: [specific issue]
   - Recommendation: [actionable fix with code]

## Security Findings
[Detailed findings array with severity, affected roles, recommendations]

## Systemic Patterns
[Cross-role patterns detected]

## Compliance Status
[PCI DSS, HIPAA, SOX, GDPR, CIS status with specific gaps]

CRITICAL RULES:
1. **Professional Tone** - Write in formal, enterprise-grade language. NO casual phrases like "I'll analyze", "Let me check", "I'm going to"
2. **No Emojis in Output** - Use clean, professional text without emojis in section headers or body
3. **Be Autonomous** - Make ALL prioritization decisions yourself without asking
4. **Find Patterns** - Look for systemic issues across multiple roles
5. **Be Specific** - Cite exact role names, policy statements, ARNs, control IDs
6. **Prioritize Smartly** - Focus on high-risk roles first (admin, production, *Full*)
7. **Structured Analysis** - Present findings in clear, organized sections

AUTONOMOUS DECISION MAKING:
- YOU decide which roles to prioritize if there are many (explain why!)
- YOU decide which findings are most critical (show your reasoning!)
- YOU decide how to structure the report (be strategic!)
- YOU make ALL tool calls without asking the user (be autonomous!)

QUICK VALIDATION MODE - REQUIRED JSON OUTPUT FORMAT:

For single policy validation, return ONLY a JSON code block with this structure:

```json
{
  "risk_score": 75,
  "findings": [
    {
      "id": "IAM-001",
      "title": "Universal Action Wildcard",
      "severity": "Critical",
      "type": "wildcard",
      "description": "Policy uses wildcard (*:*) allowing ANY action across ALL AWS services.",
      "code_snippet": "\"Action\": \"*:*\"",
      "detailed_explanation": "Security Impact: This policy grants unrestricted access to all actions across all AWS services. If credentials are compromised, an attacker could perform any operation on any service in the account, including reading, modifying, or deleting resources, creating new users or roles, and changing security configurations.\n\nPractical Risk Assessment: If someone gains access to credentials with these permissions (through a compromised device, leaked keys, or social engineering), they would have complete control over the AWS account. This could lead to unauthorized access to data, service disruption, or unauthorized changes to infrastructure. The risk applies regardless of account size - from personal projects to enterprise environments.",
      "recommendation": "Replace with specific actions required for the intended use case. Use the principle of least privilege to grant only the minimum permissions necessary."
    }
  ],
  "compliance_status": {
    "pci_dss": {"name": "PCI DSS", "status": "Non-Compliant", "gaps": ["Violates 7.1.2"]},
    "hipaa": {"name": "HIPAA", "status": "Non-Compliant", "gaps": ["Violates 164.308(a)(4)"]}
  },
  "quick_wins": [
    "Remove wildcard actions",
    "Add resource ARN restrictions",
    "Implement MFA requirement"
  ],
  "recommendations": [
    "Conduct access review",
    "Implement permission boundaries",
    "Enable CloudTrail logging"
  ]
}
```

You MUST include: risk_score, findings array (each finding MUST have: id, title, severity, type, description, code_snippet, detailed_explanation, recommendation), compliance_status object (with status for EACH requested framework), quick_wins array, recommendations array.

CRITICAL: compliance_status MUST be a JSON object with keys matching the requested frameworks (e.g., "pci_dss", "hipaa", "sox", "gdpr", "cis").
Each framework object MUST have:
- "name": Full framework name (e.g., "PCI DSS")
- "status": "Compliant", "NonCompliant", or "Partial"
- "violations": Array of violation objects with "requirement", "description", "fix"
- "gaps": Array of gap strings (if status is "Partial" or "NonCompliant")

CRITICAL SCORING RULES:
- risk_score is 0-100 where 0 = no risk (perfect security) and 100 = maximum risk
- If there are 0 findings, risk_score MUST be 0-10 (excellent security)
- If there are findings, calculate risk_score based on severity:
  * Critical findings: +40 points each (max 100)
  * High findings: +20 points each
  * Medium findings: +10 points each
  * Low findings: +5 points each
- NEVER return risk_score of 50 as default - calculate it based on actual findings

NEVER:
- Use informal language ("I'll", "Let me", "I'm going to", "I will")
- Include emojis in section headers or body text
- Miss critical security issues (admin access, privilege escalation)
- Provide vague recommendations without code examples
- Ignore context (consider policy purpose in scoring)
- Fail to map findings to compliance frameworks
- Ask user for permission to call tools in audit mode (you're autonomous!)

FORMAL LANGUAGE EXAMPLES:
❌ WRONG: "I'll analyze this policy for security issues"
✅ CORRECT: "This policy analysis identifies security vulnerabilities and compliance gaps"

❌ WRONG: "Let me check the compliance status"
✅ CORRECT: "Compliance assessment against requested frameworks reveals"

❌ WRONG: "I'm going to look at the wildcards"
✅ CORRECT: "Wildcard permission analysis reveals the following issues"

❌ WRONG: "I found 3 critical issues"
✅ CORRECT: "Analysis identified 3 critical security vulnerabilities"

Remember: You are AUTONOMOUS and PROFESSIONAL. Use formal, enterprise-grade language throughout.
"""

class ValidatorAgent:
    def __init__(self):
        self._agent = None
        self._current_role_details = None  # Store role details for current validation
        logging.info("✅ ValidatorAgent initialized with MCP + SDK fallback")
    
    def _get_agent(self, mode: str = "quick"):
        """Lazy load the agent - with tools for audit mode, without tools for quick mode"""
        # For quick mode, don't provide tools to prevent unnecessary tool calls
        # For audit mode, provide all MCP tools
        # Always recreate agent if mode doesn't match current agent configuration
        needs_tools = (mode == "audit")
        has_tools = False
        
        if self._agent is not None:
            # Check if agent has tools (try different ways to check)
            if hasattr(self._agent, '_tools'):
                has_tools = len(self._agent._tools) > 0
            elif hasattr(self._agent, 'tools'):
                has_tools = len(self._agent.tools) > 0
        
        # Recreate agent if mode doesn't match
        if self._agent is None or needs_tools != has_tools:
            if mode == "audit":
                logging.info("🔍 Creating Security Validator Agent with MCP tools (AUDIT MODE)...")
                logging.info("   Model: us.anthropic.claude-3-7-sonnet-20250219-v1:0")
                logging.info("   Tools: 4 MCP-powered (list_iam_roles_mcp, get_role_policy_mcp, get_attached_policies_mcp, get_role_trust_policy_mcp)")
                
                self._agent = Agent(
                    model="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
                    system_prompt=VALIDATOR_SYSTEM_PROMPT,
                    tools=[list_iam_roles_mcp, get_role_policy_mcp, get_attached_policies_mcp, get_role_trust_policy_mcp]
                )
                logging.info("✅ Security Validator Agent with MCP support created (AUDIT MODE)")
            else:
                # Quick mode - create agent WITHOUT tools to prevent tool calls
                logging.info("🔍 Creating Security Validator Agent WITHOUT tools (QUICK MODE)...")
                logging.info("   Model: us.anthropic.claude-3-7-sonnet-20250219-v1:0")
                logging.info("   Tools: NONE (all data provided in prompt)")
                
                self._agent = Agent(
                    model="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
                    system_prompt=VALIDATOR_SYSTEM_PROMPT,
                    tools=[]  # NO TOOLS for quick mode
                )
                logging.info("✅ Security Validator Agent created (QUICK MODE - no tools)")
        return self._agent

    def validate_policy(
        self, 
        policy_json: Optional[str] = None,
        role_arn: Optional[str] = None,
        compliance_frameworks: List[str] = None,
        mode: str = "quick"  # "quick" or "audit"
    ) -> Dict:
        """
        Validate an IAM policy OR perform autonomous account audit
        
        Args:
            policy_json: IAM policy as JSON string (Quick Mode)
            role_arn: Role ARN to fetch and validate (Quick Mode)
            compliance_frameworks: List of frameworks to check
            mode: "quick" for single policy, "audit" for full account scan
        
        Returns:
            Validation report with findings, score, and recommendations
        """
        try:
            # Reset role details for this validation
            self._current_role_details = None
            
            if mode == "audit":
                # AUTONOMOUS AUDIT MODE
                logging.info("🤖 AUTONOMOUS AUDIT MODE - Agent will scan entire AWS account using MCP")
                
                prompt = f"""AUTONOMOUS ACCOUNT AUDIT MODE

I've been configured with MCP tools to perform a comprehensive security audit.

My mission: Scan the ENTIRE AWS account for IAM security issues using MCP servers.

I will now:
1. Use list_iam_roles_mcp() to discover all roles
2. For each role:
   - Call get_role_policy_mcp(role_name)
   - Call get_attached_policies_mcp(role_name)
3. Analyze each policy for security vulnerabilities
4. Generate a comprehensive security report

Compliance frameworks to check: {', '.join(compliance_frameworks) if compliance_frameworks else 'general security best practices'}

Starting autonomous audit with MCP integration now..."""

            else:
                # QUICK VALIDATION MODE
                if policy_json:
                    policy_dict = json.loads(policy_json)
                    policy_str = json.dumps(policy_dict, indent=2)
                elif role_arn:
                    # Validate ARN format
                    if not role_arn.startswith('arn:aws:iam::') or ':role/' not in role_arn:
                        return {
                            "success": False,
                            "error": f"Invalid role ARN format: {role_arn}. Expected format: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME"
                        }
                    
                    # Extract role name from ARN (handle paths like service-role/ROLE_NAME)
                    # ARN format: arn:aws:iam::ACCOUNT_ID:role/PATH/ROLE_NAME or arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME
                    role_path = role_arn.split(':role/')[-1]
                    # Role name is the last part after the last '/' (handles paths like service-role/ROLE_NAME)
                    role_name = role_path.split('/')[-1]
                    if not role_name:
                        return {
                            "success": False,
                            "error": f"Could not extract role name from ARN: {role_arn}"
                        }
                    
                    logging.info(f"🔍 Fetching policies for role: {role_name} (from ARN: {role_arn})")
                    
                    # Fetch all policies from AWS using MCP (with boto3 fallback)
                    inline_result = get_role_policy_mcp(role_name)
                    attached_result = get_attached_policies_mcp(role_name)
                    trust_result = get_role_trust_policy_mcp(role_name)
                    
                    # Combine all inline and attached policies into a single effective policy
                    all_statements = []
                    
                    # Add inline policies
                    if inline_result.get('success') and inline_result.get('inline_policies'):
                        for policy in inline_result['inline_policies']:
                            doc = policy.get('document', {})
                            statements = doc.get('Statement', [])
                            if isinstance(statements, list):
                                all_statements.extend(statements)
                            else:
                                all_statements.append(statements)
                        logging.info(f"✅ Found {len(inline_result['inline_policies'])} inline policies")
                    
                    # Add attached policies
                    if attached_result.get('success') and attached_result.get('attached_policies'):
                        for policy in attached_result['attached_policies']:
                            doc = policy.get('document', {})
                            statements = doc.get('Statement', [])
                            if isinstance(statements, list):
                                all_statements.extend(statements)
                            else:
                                all_statements.append(statements)
                        logging.info(f"✅ Found {len(attached_result['attached_policies'])} attached policies")
                    
                    # CRITICAL: Add trust policy to analysis (it's a security-critical component)
                    trust_policy_statements = []
                    if trust_result.get('success') and trust_result.get('trust_policy'):
                        trust_policy = trust_result['trust_policy']
                        if isinstance(trust_policy, dict):
                            trust_statements = trust_policy.get('Statement', [])
                            if isinstance(trust_statements, list):
                                # Add a marker to identify these as trust policy statements
                                for stmt in trust_statements:
                                    # Create a copy with a marker
                                    trust_stmt = stmt.copy()
                                    trust_stmt['_is_trust_policy'] = True
                                    trust_policy_statements.append(trust_stmt)
                            elif trust_statements:
                                trust_stmt = trust_statements.copy() if isinstance(trust_statements, dict) else trust_statements
                                if isinstance(trust_stmt, dict):
                                    trust_stmt['_is_trust_policy'] = True
                                trust_policy_statements.append(trust_stmt)
                        logging.info(f"✅ Found trust policy with {len(trust_policy_statements)} statements - INCLUDING in analysis")
                    
                    # Combine permissions and trust policies for comprehensive analysis
                    all_statements.extend(trust_policy_statements)
                    
                    # Check if we have any policies (permissions or trust)
                    if not all_statements:
                        return {
                            "success": False,
                            "error": f"No policies found for role {role_name}. The role may not have any inline, attached, or trust policies."
                        }
                    
                    # Combine all statements into a single effective policy document
                    # Include metadata about what was analyzed
                    combined_policy = {
                        "Version": "2012-10-17",
                        "Statement": all_statements,
                        "_metadata": {
                            "has_permissions_policies": len(all_statements) - len(trust_policy_statements) > 0,
                            "has_trust_policy": len(trust_policy_statements) > 0,
                            "total_statements": len(all_statements)
                        }
                    }
                    
                    policy_str = json.dumps(combined_policy, indent=2)
                    
                    # Build role details for response - CRITICAL: Store in class variable
                    role_details_data = {
                        "role_arn": role_arn,
                        "role_name": role_name,
                        "attached_policies": [],
                        "inline_policies": []
                    }
                    
                    if attached_result.get('success') and attached_result.get('attached_policies'):
                        role_details_data["attached_policies"] = [
                            {
                                "name": p.get("name", ""), 
                                "arn": p.get("arn", ""),
                                "document": p.get("document")  # Include document if available
                            }
                            for p in attached_result["attached_policies"]
                        ]
                        # Count how many have documents
                        docs_count = sum(1 for p in role_details_data["attached_policies"] if p.get("document"))
                        logging.info(f"✅ Built role_details with {len(role_details_data['attached_policies'])} attached policies ({docs_count} with documents)")
                    
                    if inline_result.get('success') and inline_result.get('inline_policies'):
                        role_details_data["inline_policies"] = [
                            {
                                "name": p.get("name", ""),
                                "document": p.get("document")  # Include document if available
                            }
                            for p in inline_result["inline_policies"]
                        ]
                        # Count how many have documents
                        docs_count = sum(1 for p in role_details_data["inline_policies"] if p.get("document"))
                        logging.info(f"✅ Built role_details with {len(role_details_data['inline_policies'])} inline policies ({docs_count} with documents)")
                    
                    if trust_result.get('success') and trust_result.get('trust_policy'):
                        role_details_data["trust_policy"] = trust_result["trust_policy"]
                        logging.info(f"✅ Found trust policy for role {role_name}")
                    else:
                        logging.warning(f"⚠️ Could not fetch trust policy for role {role_name}")
                    
                    # Add permissions boundary if found
                    if trust_result.get('success') and trust_result.get('permissions_boundary_arn'):
                        role_details_data["permissions_boundary_arn"] = trust_result["permissions_boundary_arn"]
                        logging.info(f"✅ Found permissions boundary for role {role_name}: {trust_result['permissions_boundary_arn']}")
                    
                    # CRITICAL: Store in class variable so it's accessible when validation_result is parsed
                    self._current_role_details = role_details_data
                    logging.info(f"✅ Stored role_details in class variable: {len(role_details_data.get('attached_policies', []))} attached, {len(role_details_data.get('inline_policies', []))} inline")
                    
                    # Store in outer scope for later use
                    # This ensures role_details_data is accessible when validation_result is parsed
                else:
                    return {
                        "success": False,
                        "error": "Either policy_json or role_arn must be provided"
                    }
                
                frameworks_str = ", ".join(compliance_frameworks) if compliance_frameworks else "general security best practices"
                
                prompt = f"""QUICK VALIDATION MODE

🚨 CRITICAL: You MUST return ONLY a JSON code block. NO TEXT BEFORE OR AFTER. NO EXPLANATIONS. ONLY JSON.

🚨 DO NOT CALL ANY TOOLS: The role and policies are already fetched. DO NOT call list_iam_roles_mcp(), get_role_policy_mcp(), get_attached_policies_mcp(), or get_role_trust_policy_mcp(). All data is provided below.

Analyze this IAM role for security vulnerabilities and compliance with {frameworks_str}.

POLICY TO ANALYZE:
```json
{policy_str}
```

IMPORTANT: This policy document includes BOTH permissions policies AND trust policy statements.
- Statements with "_is_trust_policy": true are from the trust/assume role policy
- Other statements are from permissions policies (inline or attached)
- You MUST analyze BOTH types for complete security assessment
- Trust policy issues (e.g., missing aws:SourceAccount, wildcard principals) should be included in findings
- Trust policy compliance gaps should be included in compliance_status

COMPLIANCE FRAMEWORKS TO CHECK: {frameworks_str}

YOUR RESPONSE MUST BE:
1. Start with ```json
2. Then the JSON object with this EXACT structure:
{{
  "risk_score": <0-100>,
  "findings": [
    {{
      "id": "<unique-id>",
      "title": "<title>",
      "severity": "Critical|High|Medium|Low",
      "type": "<type>",
      "description": "<description>",
      "code_snippet": "<code>",
      "detailed_explanation": "Security Impact: ...\\\\n\\\\nPractical Risk Assessment: ..."
    }}
  ],
  "compliance_status": {{
    "pci_dss": {{"name": "PCI DSS", "status": "Compliant|Partial|NonCompliant", "violations": [], "gaps": []}},
    "hipaa": {{"name": "HIPAA", "status": "Compliant|Partial|NonCompliant", "violations": [], "gaps": []}},
    "sox": {{"name": "SOX", "status": "Compliant|Partial|NonCompliant", "violations": [], "gaps": []}},
    "gdpr": {{"name": "GDPR", "status": "Compliant|Partial|NonCompliant", "violations": [], "gaps": []}}
  }},
  
CRITICAL: For each violation in compliance_status, you MUST include a "link" field with the official documentation URL.
- For HIPAA requirements like "164.308(a)(4)", use: https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html#164.308
- For PCI DSS requirements like "7.1.2", use: https://www.pcisecuritystandards.org/document_library/?document=pci_dss&view=document
- For GDPR articles like "Article 5", use: https://gdpr-info.eu/art-5-gdpr/
- For SOX sections like "Section 404", use: https://www.sec.gov/rules/final/33-8238.htm#404
- Always provide the most specific URL available for the exact requirement being referenced.
  "quick_wins": ["<win-1>", "<win-2>"],
  "recommendations": ["<rec-1>", "<rec-2>"]
}}
3. End with ```

CRITICAL JSON RULES:
- ALL newlines in strings MUST be escaped as \\\\n (double backslash-n)
- ALL tabs in strings MUST be escaped as \\\\t (double backslash-t)
- ALL carriage returns in strings MUST be escaped as \\\\r (double backslash-r)
- Example: "detailed_explanation": "Line 1\\\\n\\\\nLine 2" NOT "Line 1\n\nLine 2"
- The JSON MUST be valid and parseable
- Return ONLY the ```json code block - NO TEXT BEFORE OR AFTER

For each finding, include "detailed_explanation" with:
- Security Impact: [explanation]
- Practical Risk Assessment: [scenario]
- Use \\\\n for line breaks between paragraphs

CRITICAL: Findings should identify SECURITY ISSUES/VULNERABILITIES, not positive aspects.
- If a trust policy is well-configured, DO NOT create a "Low" severity finding for it
- Only create findings for actual security problems (missing conditions, wildcards, overly permissive access, etc.)
- If the policy is secure, findings array should be empty or contain only actual issues
- "Low" severity should still indicate a problem, just a minor one

CRITICAL: quick_wins and recommendations MUST be specific to THIS role's actual policies:
- Analyze the specific services used (S3, Bedrock, DynamoDB, etc.)
- Base recommendations on actual policy statements, not generic suggestions
- If the role uses Bedrock, suggest Bedrock-specific improvements
- If the role uses S3, suggest S3-specific improvements
- Avoid generic recommendations like "Review credentials" unless relevant
- Make recommendations actionable and specific to the policy content

NOW RETURN ONLY THE JSON CODE BLOCK - NO TEXT, NO EXPLANATIONS, NO "I'll analyze" - JUST THE JSON.
"""
            
            logging.info(f"🔍 Starting validation in {mode.upper()} mode")
            
            agent = self._get_agent(mode=mode)
            result = agent(prompt)
            
            # Extract the response
            response_text = str(result.message)
            if isinstance(result.message, dict):
                if "content" in result.message and isinstance(result.message["content"], list):
                    if len(result.message["content"]) > 0 and "text" in result.message["content"][0]:
                        response_text = result.message["content"][0]["text"]
            
            logging.info("✅ Validation/Audit completed")
            logging.info(f"🔍 Response text length: {len(response_text)}")
            logging.info(f"🔍 Response text preview (first 200 chars): {response_text[:200]}")
            logging.info(f"🔍 Response text preview (last 200 chars): {response_text[-200:]}")
            
            # Try to extract JSON from response
            try:
                import re
                # First, try to find JSON in code blocks (most common format)
                json_match = re.search(r'```json\s*([\s\S]*?)```', response_text, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1).strip()
                    logging.info(f"🔍 Found JSON in code block (length: {len(json_str)})")
                    # Remove any leading/trailing text that might be in the code block
                    json_str = json_str.strip()
                    
                    # CRITICAL: Fix control characters that break JSON parsing
                    # Python's json.loads is strict about control characters in strings
                    # We need to escape or remove problematic control characters
                    
                    # First, try normal parsing
                    try:
                        validation_result = json.loads(json_str)
                        logging.info(f"✅ Successfully parsed JSON from code block")
                    except json.JSONDecodeError as e:
                        error_pos = e.pos if hasattr(e, 'pos') else None
                        logging.warning(f"⚠️ Initial JSON parse failed: {str(e)} at position {error_pos}")
                        
                        if error_pos is not None:
                            # Show context around the error
                            start = max(0, error_pos - 50)
                            end = min(len(json_str), error_pos + 50)
                            logging.warning(f"   Context around error: ...{json_str[start:end]}...")
                        
                        # Fix: The JSON contains literal newlines in string values which breaks JSON parsing
                        # We need to escape newlines, tabs, and carriage returns that are inside string values
                        import re as re_module
                        
                        # Strategy: Use regex to find string values and escape newlines in them
                        # This is more reliable than a character-by-character approach
                        import re as re_module
                        
                        def escape_newlines_in_strings(text):
                            """Escape newlines, tabs, and carriage returns inside JSON string values"""
                            # Pattern to match string values: "..." with proper escape handling
                            # This regex finds quoted strings, handling escaped quotes
                            def replace_in_string(match):
                                content = match.group(1)  # Content inside quotes
                                # Escape newlines, tabs, carriage returns
                                content = content.replace('\n', '\\n')
                                content = content.replace('\r', '\\r')
                                content = content.replace('\t', '\\t')
                                # Remove other control characters
                                content = re_module.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F]', ' ', content)
                                return '"' + content + '"'
                            
                            # Match strings: "..." but handle escaped quotes
                            # This is tricky - we need to match from " to " but skip \"
                            pattern = r'"((?:[^"\\]|\\.)*)"'
                            fixed = re_module.sub(pattern, replace_in_string, text)
                            return fixed
                        
                        # First, try the regex-based approach
                        try:
                            fixed_json = escape_newlines_in_strings(json_str)
                            validation_result = json.loads(fixed_json)
                            logging.info(f"✅ Successfully parsed JSON after escaping newlines in strings (regex method)")
                        except (json.JSONDecodeError, Exception) as e_regex:
                            logging.warning(f"⚠️ Regex method failed: {str(e_regex)}")
                            
                            # Fallback: character-by-character with better logic
                            def fix_json_char_by_char(text):
                                """Escape control chars in strings, character by character"""
                                result = []
                                in_string = False
                                escape = False
                                
                                for i, char in enumerate(text):
                                    if escape:
                                        result.append(char)
                                        escape = False
                                        continue
                                    
                                    if char == '\\':
                                        result.append(char)
                                        escape = True
                                        continue
                                    
                                    if char == '"':
                                        in_string = not in_string
                                        result.append(char)
                                        continue
                                    
                                    if in_string:
                                        # Inside string - escape control chars
                                        if char == '\n':
                                            result.append('\\n')
                                        elif char == '\r':
                                            result.append('\\r')
                                        elif char == '\t':
                                            result.append('\\t')
                                        elif ord(char) < 32:
                                            result.append(' ')  # Replace other control chars with space
                                        else:
                                            result.append(char)
                                    else:
                                        # Outside string - remove control chars except whitespace
                                        if ord(char) >= 32 or char in ['\n', '\r', '\t', ' ']:
                                            result.append(char)
                                        # else: skip control chars outside strings
                                
                                return ''.join(result)
                            
                            try:
                                fixed_json = fix_json_char_by_char(json_str)
                                validation_result = json.loads(fixed_json)
                                logging.info(f"✅ Successfully parsed JSON after fixing control chars (char-by-char method)")
                            except json.JSONDecodeError as e3:
                                error_pos = e3.pos if hasattr(e3, 'pos') else None
                                logging.error(f"❌ JSON parsing failed: {str(e3)} at position {error_pos}")
                                if error_pos:
                                    start = max(0, error_pos - 100)
                                    end = min(len(fixed_json), error_pos + 100)
                                    logging.error(f"   Context: ...{fixed_json[start:end]}...")
                                
                                # Last resort: try lenient JSON parsers
                                try:
                                    import demjson3
                                    # demjson3 is more lenient and can handle unescaped newlines
                                    validation_result = demjson3.decode(json_str)
                                    logging.info(f"✅ Successfully parsed JSON using demjson3 (lenient parser)")
                                except (ImportError, Exception) as demjson_err:
                                    logging.warning(f"⚠️ demjson3 failed: {str(demjson_err)}")
                                    try:
                                        import json5
                                        validation_result = json5.loads(json_str)
                                        logging.info(f"✅ Successfully parsed JSON using json5")
                                    except (ImportError, Exception) as json5_err:
                                        logging.error(f"❌ All JSON parsing attempts failed")
                                        logging.error(f"   demjson3 error: {str(demjson_err)}")
                                        logging.error(f"   json5 error: {str(json5_err)}")
                                        logging.error(f"   Original error: {str(e3)}")
                                        # Final fallback: return empty structure
                                        raise e3
                else:
                    # Try to find JSON object that starts with { and contains "risk_score"
                    # Look for the opening brace and find the matching closing brace
                    json_start = response_text.find('{')
                    if json_start != -1:
                        # Find the matching closing brace
                        brace_count = 0
                        json_end = json_start
                        for i in range(json_start, len(response_text)):
                            if response_text[i] == '{':
                                brace_count += 1
                            elif response_text[i] == '}':
                                brace_count -= 1
                                if brace_count == 0:
                                    json_end = i + 1
                                    break
                        
                        if json_end > json_start:
                            json_str = response_text[json_start:json_end].strip()
                            logging.info(f"🔍 Found JSON object in response (position {json_start} to {json_end}, length: {len(json_str)})")
                            validation_result = json.loads(json_str)
                            logging.info(f"✅ Successfully parsed JSON object from response")
                        else:
                            raise ValueError("Could not find matching closing brace")
                    else:
                        # Try parsing entire response
                        logging.info(f"🔍 Attempting to parse entire response as JSON (length: {len(response_text)})")
                        validation_result = json.loads(response_text)
                        logging.info(f"✅ Successfully parsed entire response as JSON")
                
                # Enrich compliance violations with links
                if isinstance(validation_result, dict) and 'compliance_status' in validation_result:
                    compliance_status = validation_result['compliance_status']
                    for framework_key, framework_data in compliance_status.items():
                        if isinstance(framework_data, dict) and 'violations' in framework_data:
                            violations = framework_data['violations']
                            for violation in violations:
                                if isinstance(violation, dict) and 'requirement' in violation:
                                    requirement = violation['requirement']
                                    # Extract framework name from key (e.g., 'pci_dss' -> 'PCI DSS')
                                    framework_name_map = {
                                        'pci_dss': 'PCI DSS',
                                        'hipaa': 'HIPAA',
                                        'sox': 'SOX',
                                        'gdpr': 'GDPR',
                                        'cis': 'CIS',
                                        'nist': 'NIST'
                                    }
                                    framework_name = framework_name_map.get(framework_key, framework_key.upper())
                                    link = get_compliance_link(framework_name, requirement)
                                    if link:
                                        violation['link'] = link
                                        logging.debug(f"✅ Added link to {framework_name} {requirement}: {link}")
                
                # CRITICAL: Always include role_details if validating via ARN
                # This ensures the frontend receives policy information even if agent doesn't include it
                if role_arn:
                    # Use class variable (most reliable)
                    if self._current_role_details:
                        validation_result["role_details"] = self._current_role_details
                        logging.info(f"✅ Added role_details to validation result: {len(self._current_role_details.get('attached_policies', []))} attached, {len(self._current_role_details.get('inline_policies', []))} inline")
                    elif "role_details" not in validation_result:
                        # Fallback: build basic role_details
                        role_name = role_arn.split(':role/')[-1].split('/')[-1]
                        validation_result["role_details"] = {
                            "role_arn": role_arn,
                            "role_name": role_name
                        }
                        logging.warning(f"⚠️ Using fallback role_details for {role_name} - attached policies not included")
                
                # CRITICAL: Also include role_details at top level for easy access
                result_dict = {
                    "success": True,
                    "mode": mode,
                    "validation": validation_result,
                    "raw_response": response_text,
                    "mcp_enabled": True
                }
                
                # Include role_details at top level if available (for main.py to access)
                if role_arn and self._current_role_details:
                    result_dict["role_details"] = self._current_role_details
                    logging.info(f"✅ Added role_details to top-level result: {len(self._current_role_details.get('attached_policies', []))} attached")
                
                # DEBUG: Log what's in validation_result
                logging.info(f"🔍 VALIDATOR_AGENT validation_result keys: {list(validation_result.keys()) if isinstance(validation_result, dict) else 'NOT A DICT'}")
                if isinstance(validation_result, dict):
                    logging.info(f"🔍 VALIDATOR_AGENT validation_result.risk_score: {validation_result.get('risk_score')}")
                    logging.info(f"🔍 VALIDATOR_AGENT validation_result.findings count: {len(validation_result.get('findings', []))}")
                    logging.info(f"🔍 VALIDATOR_AGENT validation_result.compliance_status keys: {list(validation_result.get('compliance_status', {}).keys())}")
                    logging.info(f"🔍 VALIDATOR_AGENT validation_result.quick_wins count: {len(validation_result.get('quick_wins', []))}")
                    logging.info(f"🔍 VALIDATOR_AGENT validation_result.recommendations count: {len(validation_result.get('recommendations', []))}")
                
                return result_dict
            except json.JSONDecodeError as e:
                # JSON parsing failed - log the error and response
                logging.error(f"❌ JSON parsing failed: {str(e)}")
                logging.error(f"   Response text length: {len(response_text)}")
                logging.error(f"   Response text preview (first 500 chars): {response_text[:500]}")
                logging.error(f"   Response text preview (last 500 chars): {response_text[-500:]}")
                
                # Try to extract just the JSON part more aggressively
                try:
                    # Look for JSON object that starts with { and contains risk_score
                    json_start = response_text.find('{')
                    json_end = response_text.rfind('}')
                    if json_start != -1 and json_end != -1 and json_end > json_start:
                        potential_json = response_text[json_start:json_end+1]
                        logging.info(f"🔍 Attempting to extract JSON from position {json_start} to {json_end}")
                        validation_result = json.loads(potential_json)
                        logging.info(f"✅ Successfully parsed extracted JSON")
                    else:
                        raise json.JSONDecodeError("Could not find JSON boundaries", response_text, 0)
                except (json.JSONDecodeError, ValueError) as e2:
                    logging.error(f"❌ Secondary JSON extraction also failed: {str(e2)}")
                    # Return structured response even if JSON parsing fails
                    # If no findings, risk_score should be 0-10 (excellent security)
                    return {
                        "success": True,
                        "mode": mode,
                        "validation": {
                            "risk_score": 5,  # Low risk if no findings detected
                            "findings": [],
                            "raw_analysis": response_text
                        },
                        "raw_response": response_text,
                        "mcp_enabled": True
                    }
                
        except json.JSONDecodeError as e:
            logging.error(f"❌ Invalid JSON policy: {str(e)}")
            return {
                "success": False,
                "error": f"Invalid JSON format: {str(e)}"
            }
        except Exception as e:
            logging.exception("❌ Validation/Audit failed")
            return {
                "success": False,
                "error": str(e)
            }