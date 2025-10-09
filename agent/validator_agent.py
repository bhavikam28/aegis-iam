from strands import Agent, tool
import logging
import json
import boto3
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)

# AWS IAM Tools for Autonomous Account Auditing
iam_client = None

def get_iam_client():
    """Lazy load IAM client"""
    global iam_client
    if iam_client is None:
        iam_client = boto3.client('iam')
    return iam_client

@tool
def list_iam_roles() -> Dict:
    """Lists all IAM roles in the AWS account"""
    try:
        client = get_iam_client()
        response = client.list_roles(MaxItems=100)
        return {
            "success": True,
            "roles": [
                {
                    "name": role["RoleName"],
                    "arn": role["Arn"],
                    "created": str(role["CreateDate"])
                }
                for role in response.get("Roles", [])
            ],
            "count": len(response.get("Roles", []))
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@tool
def get_role_policy(role_name: str) -> Dict:
    """Gets inline policies for a specific IAM role"""
    try:
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
            "count": len(policies)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@tool
def get_attached_policies(role_name: str) -> Dict:
    """Gets managed policies attached to a role"""
    try:
        client = get_iam_client()
        response = client.list_attached_role_policies(RoleName=role_name)
        
        policies = []
        for policy in response.get("AttachedPolicies", []):
            # Get policy version
            policy_arn = policy["PolicyArn"]
            policy_details = client.get_policy(PolicyArn=policy_arn)
            version_id = policy_details["Policy"]["DefaultVersionId"]
            
            # Get policy document
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
            "count": len(policies)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

VALIDATOR_SYSTEM_PROMPT = """You are Aegis Security Validator, an elite AWS security expert and autonomous IAM auditor.

🎯 YOUR MISSION:
You are a FULLY AUTONOMOUS security agent that can operate in two modes:

MODE 1: QUICK VALIDATION (User provides policy)
- User pastes a policy JSON or provides a role ARN
- You analyze it deeply for security issues
- You provide actionable remediation guidance

MODE 2: FULL AUTONOMOUS AUDIT (User provides AWS credentials)
- User provides AWS Access Key + Secret + Region
- You AUTONOMOUSLY use tools to:
  1. List all IAM roles in the account
  2. Fetch policies for each role
  3. Analyze each policy for security issues
  4. Prioritize findings by severity
  5. Generate comprehensive security report
  
🔧 AVAILABLE TOOLS (for Autonomous Audit):
- list_iam_roles(): Lists all IAM roles in the AWS account
- get_role_policy(role_name): Gets inline policies for a role
- get_attached_policies(role_name): Gets managed policies attached to a role

📋 ANALYSIS FRAMEWORK:

**1. CRITICAL SECURITY CHECKS (Must Flag)**
- IAM.1: Full administrative access (*:* wildcard)
- IAM.21: Service-level wildcards (s3:*, ec2:*)
- IAM.RESOURCE.1: Resource wildcards (Resource: "*")
- PRIVILEGE ESCALATION: Actions that could lead to privilege escalation
- CROSS-ACCOUNT: Unsafe cross-account trust relationships

**2. HIGH-PRIORITY CHECKS**
- Missing MFA requirements for sensitive actions
- Overly broad principals (Principal: "*")
- Missing condition blocks for sensitive services
- Unencrypted data access permissions
- Public resource exposure risks

**3. BEST PRACTICE CHECKS**
- Statement IDs (Sid) missing or non-descriptive
- Multiple statements that could be combined
- Deprecated actions or services
- Region restrictions missing for global services

**4. COMPLIANCE MAPPING**
For each finding, map to relevant frameworks:
- PCI DSS: Payment card data protection
- HIPAA: Healthcare data protection
- SOX: Financial reporting controls
- GDPR: Personal data protection
- CIS Benchmarks: Industry security standards

🔍 AUTONOMOUS AUDIT PROCESS (Mode 2):

When user provides AWS credentials:

1. **Discovery Phase**
   - Call list_iam_roles() to get all roles
   - Log: "Found X IAM roles in account"
   - Decide which roles to analyze (all if < 50, prioritize if more)

2. **Collection Phase**
   - For each role:
     - Call get_role_policy(role_name)
     - Call get_attached_policies(role_name)
   - Aggregate all policies

3. **Analysis Phase**
   - For each policy, check against all security controls
   - Classify findings by severity
   - Map to compliance frameworks

4. **Reporting Phase**
   - Generate comprehensive security report
   - Prioritize critical issues first
   - Provide role-by-role breakdown
   - Include quick wins and remediation steps

🔒 SECURITY SCORING (0-100):

Start at 100, deduct points:
- Full admin access (*:*): -50 points
- Service wildcards: -25 points per service
- Resource wildcards: -15 points per statement
- Missing conditions on sensitive services: -10 points
- No MFA on destructive actions: -20 points
- Overly broad principals: -15 points

📤 OUTPUT FORMAT:

For Quick Validation (Mode 1):
```json
{
  "risk_score": 75,
  "grade": "C",
  "findings": [
    {
      "id": "IAM.1",
      "severity": "Critical",
      "type": "Security",
      "title": "Full Administrative Access Granted",
      "description": "Policy contains Action: '*' and Resource: '*', granting complete control over all AWS resources.",
      "recommendation": "Replace wildcard with specific actions. Example:\\n{\\n  \\"Action\\": [\\n    \\"s3:GetObject\\",\\n    \\"s3:PutObject\\"\\n  ],\\n  \\"Resource\\": \\"arn:aws:s3:::specific-bucket/*\\"\\n}",
      "affected_statement": 0,
      "compliance_impact": {
        "pci_dss": "Violates Requirement 7 - Restrict access by business need-to-know"
      }
    }
  ],
  "compliance_status": {
    "pci_dss": {
      "status": "NonCompliant",
      "gaps": ["Excessive permissions violate least privilege principle"]
    }
  },
  "security_improvements": [
    "Implement least privilege by restricting actions to specific operations",
    "Add resource-level restrictions to limit scope"
  ],
  "quick_wins": [
    "Replace 's3:*' with specific actions - 5 min fix"
  ]
}
```

For Full Autonomous Audit (Mode 2):
```json
{
  "audit_summary": {
    "total_roles": 47,
    "roles_analyzed": 47,
    "total_policies": 89,
    "total_findings": 23,
    "critical_findings": 5,
    "high_findings": 8,
    "medium_findings": 7,
    "low_findings": 3
  },
  "risk_score": 68,
  "top_risks": [
    {
      "role_name": "ProductionAdminRole",
      "risk_score": 95,
      "critical_issues": 3,
      "findings": [...]
    }
  ],
  "findings": [...],
  "compliance_status": {...},
  "security_improvements": [...],
  "quick_wins": [...]
}
```

🚨 CRITICAL RULES:
1. **Be Autonomous** - In audit mode, make ALL decisions yourself
2. **Be Precise** - Cite exact AWS documentation for every finding
3. **Be Actionable** - Every recommendation must include example code
4. **Prioritize Safety** - When in doubt, recommend more restrictive
5. **Explain Impact** - Always explain WHY something is risky

🔄 DECISION MAKING (Autonomous Mode):
- YOU decide which roles to prioritize if there are many
- YOU decide which findings are most critical
- YOU decide how to structure the audit report
- YOU make ALL tool calls without asking the user

🚫 NEVER:
- Miss critical security issues (admin access, privilege escalation)
- Provide vague recommendations without code examples
- Ignore context (consider policy purpose in scoring)
- Fail to map findings to compliance frameworks
- Ask user for permission to call tools in audit mode
"""

class ValidatorAgent:
    def __init__(self):
        self._agent = None
        logging.info("✅ ValidatorAgent initialized with autonomous audit capabilities")
    
    def _get_agent(self):
        """Lazy load the agent with IAM tools"""
        if self._agent is None:
            logging.info("🔍 Creating Security Validator Agent with IAM tools...")
            logging.info("   Model: us.anthropic.claude-3-7-sonnet-20250219-v1:0")
            logging.info("   Tools: 4 (validate_policy + 3 IAM audit tools)")
            
            self._agent = Agent(
                model="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
                system_prompt=VALIDATOR_SYSTEM_PROMPT,
                tools=[list_iam_roles, get_role_policy, get_attached_policies]
            )
            logging.info("✅ Security Validator Agent with IAM audit tools created")
        return self._agent

    def validate_policy(
        self, 
        policy_json: Optional[str] = None,
        role_arn: Optional[str] = None,
        compliance_frameworks: List[str] = None,
        aws_credentials: Optional[Dict] = None
    ) -> Dict:
        """
        Validate an IAM policy OR perform autonomous account audit
        
        Args:
            policy_json: IAM policy as JSON string (Quick Mode)
            role_arn: Role ARN to fetch and validate (Quick Mode)
            compliance_frameworks: List of frameworks to check
            aws_credentials: Dict with access_key, secret_key, region (Audit Mode)
        
        Returns:
            Validation report with findings, score, and recommendations
        """
        try:
            # Determine mode
            is_audit_mode = aws_credentials is not None
            
            if is_audit_mode:
                # AUTONOMOUS AUDIT MODE
                logging.info("🤖 AUTONOMOUS AUDIT MODE - Agent will scan entire AWS account")
                
                # Configure AWS credentials
                if aws_credentials:
                    import os
                    os.environ['AWS_ACCESS_KEY_ID'] = aws_credentials.get('access_key')
                    os.environ['AWS_SECRET_ACCESS_KEY'] = aws_credentials.get('secret_key')
                    os.environ['AWS_DEFAULT_REGION'] = aws_credentials.get('region', 'us-east-1')
                
                prompt = f"""AUTONOMOUS ACCOUNT AUDIT MODE

I've been given AWS credentials to perform a comprehensive security audit.

My mission: Scan the ENTIRE AWS account for IAM security issues.

I will now:
1. List all IAM roles using list_iam_roles()
2. For each role, fetch policies using get_role_policy() and get_attached_policies()
3. Analyze each policy for security vulnerabilities
4. Generate a comprehensive security report

Compliance frameworks to check: {', '.join(compliance_frameworks) if compliance_frameworks else 'general security best practices'}

Starting autonomous audit now..."""
                
            else:
                # QUICK VALIDATION MODE
                if policy_json:
                    policy_dict = json.loads(policy_json)
                    policy_str = json.dumps(policy_dict, indent=2)
                elif role_arn:
                    # Fetch policy from AWS
                    role_name = role_arn.split('/')[-1]
                    client = get_iam_client()
                    
                    # Try inline policies first
                    inline_response = client.list_role_policies(RoleName=role_name)
                    if inline_response.get('PolicyNames'):
                        policy_name = inline_response['PolicyNames'][0]
                        policy_doc = client.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name
                        )
                        policy_str = json.dumps(policy_doc['PolicyDocument'], indent=2)
                    else:
                        # Try attached policies
                        attached_response = client.list_attached_role_policies(RoleName=role_name)
                        if attached_response.get('AttachedPolicies'):
                            policy_arn = attached_response['AttachedPolicies'][0]['PolicyArn']
                            policy_details = client.get_policy(PolicyArn=policy_arn)
                            version_id = policy_details['Policy']['DefaultVersionId']
                            policy_version = client.get_policy_version(
                                PolicyArn=policy_arn,
                                VersionId=version_id
                            )
                            policy_str = json.dumps(policy_version['PolicyVersion']['Document'], indent=2)
                        else:
                            return {
                                "success": False,
                                "error": f"No policies found for role {role_name}"
                            }
                else:
                    return {
                        "success": False,
                        "error": "Either policy_json, role_arn, or aws_credentials must be provided"
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
            
            logging.info(f"🔍 Starting validation in {'AUDIT' if is_audit_mode else 'QUICK'} mode")
            
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
                    "mode": "audit" if is_audit_mode else "validation",
                    "validation": validation_result,
                    "raw_response": response_text
                }
            except json.JSONDecodeError:
                # Return structured response even if JSON parsing fails
                return {
                    "success": True,
                    "mode": "audit" if is_audit_mode else "validation",
                    "validation": {
                        "risk_score": 50,
                        "findings": [],
                        "raw_analysis": response_text
                    },
                    "raw_response": response_text
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