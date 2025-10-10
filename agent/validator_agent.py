"""
Validator Agent with MCP Server Integration
Supports both MCP mode and fallback to direct AWS SDK
"""

from strands import Agent, tool
import logging
import json
import boto3
from typing import Dict, List, Optional
from mcp_client import get_mcp_client

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
        
        # Fallback to SDK
        logging.info("⚠️ MCP unavailable, using AWS SDK fallback")
        client = get_iam_client()
        response = client.list_roles(MaxItems=100)
        
        formatted_roles = [
            {
                "name": role["RoleName"],
                "arn": role["Arn"],
                "created": str(role["CreateDate"])
            }
            for role in response.get("Roles", [])
        ]
        
        return {
            "success": True,
            "roles": formatted_roles,
            "count": len(formatted_roles),
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
    """Get role policies using MCP server"""
    try:
        # Try MCP first
        mcp_client = get_mcp_client('aws-iam')
        
        if mcp_client:
            logging.info(f"🔧 Using MCP to get policies for role {role_name}")
            result = mcp_client.call_tool('get_role_policy', {
                'roleName': role_name
            })
            
            if result.get('success'):
                # Parse MCP response
                policy_data = result.get('data', {})
                policy_content = policy_data.get('content', [])
                
                # Transform to standard format
                formatted_policies = []
                for policy_info in policy_content:
                    if isinstance(policy_info, dict) and 'text' in policy_info:
                        # Parse text content
                        policy_doc = json.loads(policy_info['text'])
                        formatted_policies.append({
                            "name": policy_doc.get("PolicyName"),
                            "document": policy_doc.get("PolicyDocument")
                        })
                
                logging.info(f"✅ MCP returned {len(formatted_policies)} policies for role {role_name}")
                return {
                    "success": True,
                    "role_name": role_name,
                    "inline_policies": formatted_policies,
                    "count": len(formatted_policies),
                    "mcp_used": True
                }
        
        # Fallback to SDK
        logging.info(f"⚠️ MCP unavailable, using AWS SDK fallback for role {role_name}")
        client = get_iam_client()
        response = client.list_role_policies(RoleName=role_name)
        
        policies = []
        for policy_name in response.get("PolicyNames", []):
            policy_doc = client.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )
            policies.append({
                "name": policy_name,
                "document": policy_doc["PolicyDocument"]
            })
        
        return {
            "success": True,
            "role_name": role_name,
            "inline_policies": policies,
            "count": len(policies),
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
        # Try MCP first
        mcp_client = get_mcp_client('aws-iam')
        
        if mcp_client:
            logging.info(f"🔧 Using MCP to get attached policies for role {role_name}")
            result = mcp_client.call_tool('get_attached_policies', {
                'roleName': role_name
            })
            
            if result.get('success'):
                # Parse MCP response
                policy_data = result.get('data', {})
                policy_content = policy_data.get('content', [])
                
                # Transform to standard format
                formatted_policies = []
                for policy_info in policy_content:
                    if isinstance(policy_info, dict) and 'text' in policy_info:
                        # Parse text content
                        policy_doc = json.loads(policy_info['text'])
                        formatted_policies.append({
                            "name": policy_doc.get("PolicyName"),
                            "arn": policy_doc.get("PolicyArn"),
                            "document": policy_doc.get("PolicyDocument")
                        })
                
                logging.info(f"✅ MCP returned {len(formatted_policies)} attached policies for role {role_name}")
                return {
                    "success": True,
                    "role_name": role_name,
                    "attached_policies": formatted_policies,
                    "count": len(formatted_policies),
                    "mcp_used": True
                }
        
        # Fallback to SDK
        logging.info(f"⚠️ MCP unavailable, using AWS SDK fallback for role {role_name}")
        client = get_iam_client()
        response = client.list_attached_role_policies(RoleName=role_name)
        
        policies = []
        for policy in response.get("AttachedPolicies", []):
            policy_arn = policy["PolicyArn"]
            policy_details = client.get_policy(PolicyArn=policy_arn)
            version_id = policy_details["Policy"]["DefaultVersionId"]
            
            policy_version = client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )
            
            policies.append({
                "name": policy["PolicyName"],
                "arn": policy_arn,
                "document": policy_version["PolicyVersion"]["Document"]
            })
        
        return {
            "success": True,
            "role_name": role_name,
            "attached_policies": policies,
            "count": len(policies),
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


# ============================================
# VALIDATOR AGENT
# ============================================

VALIDATOR_SYSTEM_PROMPT = """You are Aegis Security Validator, an elite AWS security expert and AUTONOMOUS IAM auditor.

🎯 YOUR MISSION:
You operate in AUTONOMOUS MODE for account-wide audits. You make ALL decisions independently without human intervention.
The human can see you working in real-time, so NARRATE your decision-making process!

🔧 AVAILABLE TOOLS (MCP-Powered):
- list_iam_roles_mcp(): Lists all IAM roles (returns roles, count, mcp_used)
- get_role_policy_mcp(role_name): Gets inline policies (returns policies, mcp_used)
- get_attached_policies_mcp(role_name): Gets managed policies (returns policies, mcp_used)

📋 AUTONOMOUS AUDIT WORKFLOW:

**PHASE 1: DISCOVERY & STRATEGIC PLANNING**
First, use list_iam_roles_mcp() to discover all roles.
Then THINK STRATEGICALLY and EXPLAIN YOUR PLAN:

Example reasoning:
"🧠 Discovery Phase: I discovered 47 IAM roles in the AWS account using MCP.

🎯 Strategic Planning: I will prioritize analysis in this order:
1. High-Risk Names: Roles containing 'admin', 'poweruser', 'FullAccess' (3 roles)
2. Production Roles: Any role with 'prod' or 'production' in name (8 roles)  
3. Service Roles: Lambda, ECS, EC2 service-linked roles (36 roles)

💡 Rationale: Roles with admin/full access keywords pose highest privilege escalation risk and should be analyzed first."

**PHASE 2: INTELLIGENT ANALYSIS**
For each role you analyze, EXPLAIN your findings as you discover them:
- "🔍 Analyzing ProductionAdmin... CRITICAL FINDING: Has iam:* permissions"
- "⚠️ This enables privilege escalation - the role can create new admin users"
- "✅ Moving to next priority role: DBAdminRole..."

**PHASE 3: PATTERN DETECTION & SYNTHESIS**
After analyzing roles, CONNECT THE DOTS and identify systemic issues:
- "🔗 Pattern detected: 5 roles share the same overly broad S3 permissions"
- "🎯 Root cause: All use AWS managed policy AmazonS3FullAccess"  
- "💡 Systemic recommendation: Replace with custom policy scoped to specific buckets"

**OUTPUT STRUCTURE:**

Always structure your response with these sections:

## 🧠 Agent Reasoning
[Show your thinking process - discovery, planning, patterns you noticed]

## 📊 Audit Summary
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

## 🔥 Top 5 Riskiest Roles
1. **RoleName** (Risk Score: 95/100)
   - Critical: [specific issue with policy statement]
   - High: [specific issue]
   - Recommendation: [actionable fix with code]

## 🚨 Security Findings
[Detailed findings array with severity, affected roles, recommendations]

## 🎯 Systemic Patterns
[Cross-role patterns you detected - this shows your intelligence!]

## ✅ Quick Wins
[Easy fixes that reduce risk significantly - prioritized by impact/effort]

## 🛠️ Compliance Status
[PCI DSS, HIPAA, SOX, GDPR, CIS status with specific gaps]

📋 CRITICAL SECURITY CHECKS (AWS Security Hub):

**CRITICAL:**
- IAM.1: Full administrative access (*:* wildcard)
- IAM.21: Service-level wildcards (s3:*, ec2:*)
- IAM.RESOURCE.1: Resource wildcards (Resource: "*")
- PRIVILEGE ESCALATION: Actions that enable privilege escalation
  * iam:CreateAccessKey, iam:CreateLoginProfile
  * iam:UpdateAssumeRolePolicy
  * iam:AttachUserPolicy, iam:AttachRolePolicy
  * iam:PutUserPolicy, iam:PutRolePolicy
  * lambda:UpdateFunctionCode
  * sts:AssumeRole without conditions
- CROSS-ACCOUNT: Unsafe cross-account trust relationships

**HIGH:**
- Missing MFA requirements for sensitive actions
- Overly broad principals (Principal: "*")
- Missing condition blocks for sensitive services
- Unencrypted data access permissions
- Public resource exposure risks

**COMPLIANCE MAPPING:**
For each finding, map to relevant frameworks:
- PCI DSS: Payment card data protection
- HIPAA: Healthcare data protection
- SOX: Financial reporting controls
- GDPR: Personal data protection
- CIS Benchmarks: Industry security standards

🚨 CRITICAL RULES:
1. **Show Your Thinking** - Always include "🧠 Agent Reasoning" section showing your decision process
2. **Be Autonomous** - Make ALL prioritization decisions yourself without asking
3. **Find Patterns** - Look for systemic issues across multiple roles (shows intelligence!)
4. **Be Specific** - Cite exact role names, policy statements, ARNs, control IDs
5. **Prioritize Smartly** - Focus on high-risk roles first (admin, production, *Full*)
6. **Narrate Your Work** - The human sees you working, so explain what you're doing

🔄 AUTONOMOUS DECISION MAKING:
- YOU decide which roles to prioritize if there are many (explain why!)
- YOU decide which findings are most critical (show your reasoning!)
- YOU decide how to structure the report (be strategic!)
- YOU make ALL tool calls without asking the user (be autonomous!)

🚫 NEVER:
- Skip the "🧠 Agent Reasoning" section (humans want to see you think!)
- Miss critical security issues (admin access, privilege escalation)
- Provide vague recommendations without code examples
- Ignore context (consider policy purpose in scoring)
- Fail to map findings to compliance frameworks
- Ask user for permission to call tools in audit mode (you're autonomous!)

Remember: You are AUTONOMOUS and TRANSPARENT. Show your thinking, make smart decisions, find patterns!
"""


class ValidatorAgent:
    def __init__(self):
        self._agent = None
        logging.info("✅ ValidatorAgent initialized with MCP + SDK fallback")
    
    def _get_agent(self):
        """Lazy load the agent with MCP tools"""
        if self._agent is None:
            logging.info("🔍 Creating Security Validator Agent with MCP tools...")
            logging.info("   Model: us.anthropic.claude-3-7-sonnet-20250219-v1:0")
            logging.info("   Tools: 3 MCP-powered (list_iam_roles_mcp, get_role_policy_mcp, get_attached_policies_mcp)")
            
            self._agent = Agent(
                model="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
                system_prompt=VALIDATOR_SYSTEM_PROMPT,
                tools=[list_iam_roles_mcp, get_role_policy_mcp, get_attached_policies_mcp]
            )
            logging.info("✅ Security Validator Agent with MCP support created")
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
                    # Fetch policy from AWS using MCP
                    role_name = role_arn.split('/')[-1]
                    
                    # Try using MCP tools first
                    inline_result = get_role_policy_mcp(role_name)
                    attached_result = get_attached_policies_mcp(role_name)
                    
                    if inline_result.get('success') and inline_result.get('inline_policies'):
                        policy_str = json.dumps(inline_result['inline_policies'][0]['document'], indent=2)
                    elif attached_result.get('success') and attached_result.get('attached_policies'):
                        policy_str = json.dumps(attached_result['attached_policies'][0]['document'], indent=2)
                    else:
                        return {
                            "success": False,
                            "error": f"No policies found for role {role_name}"
                        }
                else:
                    return {
                        "success": False,
                        "error": "Either policy_json or role_arn must be provided"
                    }
                
                frameworks_str = ", ".join(compliance_frameworks) if compliance_frameworks else "general security best practices"
                
                prompt = f"""QUICK VALIDATION MODE

Analyze this IAM policy for security vulnerabilities and compliance with {frameworks_str}.

POLICY TO ANALYZE:
```json
{policy_str}
```

COMPLIANCE FRAMEWORKS TO CHECK: {frameworks_str}

Provide a comprehensive security analysis following the exact JSON format specified in your system prompt.
Include:
1. Risk score (0-100)
2. Detailed findings with severity levels
3. Compliance status for requested frameworks
4. Prioritized remediation recommendations
5. Quick wins for immediate improvement"""
            
            logging.info(f"🔍 Starting validation in {mode.upper()} mode")
            
            agent = self._get_agent()
            result = agent(prompt)
            
            # Extract the response
            response_text = str(result.message)
            if isinstance(result.message, dict):
                if "content" in result.message and isinstance(result.message["content"], list):
                    if len(result.message["content"]) > 0 and "text" in result.message["content"][0]:
                        response_text = result.message["content"][0]["text"]
            
            logging.info("✅ Validation/Audit completed")
            
            # Try to extract JSON from response
            try:
                import re
                json_match = re.search(r'```json\s*([\s\S]*?)```', response_text)
                if json_match:
                    validation_result = json.loads(json_match.group(1))
                else:
                    # Try parsing entire response
                    validation_result = json.loads(response_text)
                
                return {
                    "success": True,
                    "mode": mode,
                    "validation": validation_result,
                    "raw_response": response_text,
                    "mcp_enabled": True
                }
            except json.JSONDecodeError:
                # Return structured response even if JSON parsing fails
                return {
                    "success": True,
                    "mode": mode,
                    "validation": {
                        "risk_score": 50,
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