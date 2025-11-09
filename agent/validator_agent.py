"""
Validator Agent with MCP Server Integration
Supports both MCP mode and fallback to direct AWS SDK
"""

from strands import Agent, tool
import logging
import json
import boto3
from typing import Dict, List, Optional
from fastmcp_client import get_mcp_client

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

# VALIDATOR AGENT
# ============================================

VALIDATOR_SYSTEM_PROMPT = """You are Aegis Security Validator, an elite AWS security expert and AUTONOMOUS IAM auditor.

YOUR MISSION:
You operate in AUTONOMOUS MODE for account-wide audits. You make ALL decisions independently without human intervention.
Provide formal, enterprise-grade security analysis.

AVAILABLE TOOLS (MCP-Powered):
- list_iam_roles_mcp(): Lists all IAM roles (returns roles, count, mcp_used)
- get_role_policy_mcp(role_name): Gets inline policies (returns policies, mcp_used)
- get_attached_policies_mcp(role_name): Gets managed policies (returns policies, mcp_used)

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

You MUST include: risk_score, findings array (each finding MUST have: id, title, severity, type, description, code_snippet, detailed_explanation, recommendation), compliance_status object, quick_wins array, recommendations array.

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
2. Detailed findings with severity levels, type, and detailed_explanation
3. Compliance status for requested frameworks
4. Prioritized remediation recommendations
5. Quick wins for immediate improvement

CRITICAL: For each finding, you MUST include a "detailed_explanation" field with:
- Security Impact: Explain what this vulnerability means in practical terms (what could happen if exploited)
- Practical Risk Assessment: Describe the realistic risk scenario without fear-mongering or specific company breach examples
- Keep explanations universal and context-appropriate (works for personal projects, startups, and enterprises)
- Do NOT mention specific company names, breach examples, dollar amounts, or record counts
- Focus on the technical impact and practical consequences
- Be professional, clear, and educational

Example detailed_explanation format:
"Security Impact: [Clear explanation of what the vulnerability means]\n\nPractical Risk Assessment: [Realistic scenario without fear-mongering]"
"""
            
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