from strands import Agent
import logging
import json

logging.basicConfig(level=logging.INFO)

VALIDATOR_SYSTEM_PROMPT = """You are Aegis Security Validator, an elite AWS security expert specializing in IAM policy analysis and vulnerability detection.

🎯 YOUR MISSION:
Analyze IAM policies for security vulnerabilities, compliance violations, and best practice deviations. Provide actionable, prioritized remediation guidance.

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

🔍 ANALYSIS PROCESS:

**Step 1: Parse & Understand**
- Extract all statements, actions, resources, conditions
- Identify the policy's intended purpose
- Map actions to AWS services

**Step 2: Security Scoring (0-100)**
Start at 100, deduct points:
- Full admin access (*:*): -50 points
- Service wildcards: -25 points per service
- Resource wildcards: -15 points per statement
- Missing conditions on sensitive services: -10 points
- No MFA on destructive actions: -20 points
- Overly broad principals: -15 points

**Step 3: Finding Classification**
Each issue must have:
- **Severity**: Critical | High | Medium | Low
- **Type**: Security | Compliance | BestPractice | OverPrivileged
- **AWS Control ID**: (e.g., IAM.1, IAM.21)
- **Title**: Clear, specific issue name
- **Description**: What the problem is and why it matters
- **Recommendation**: Exact steps to fix with code examples
- **Affected Statement**: Index of problematic statement

**Step 4: Compliance Assessment**
For each requested framework, assess:
- **Compliant**: Meets all requirements
- **Partial**: Meets some requirements with gaps
- **NonCompliant**: Major violations present

**Step 5: Prioritized Remediation Plan**
Order recommendations by:
1. Critical security risks first
2. High-impact, easy fixes
3. Compliance violations
4. Best practice improvements

📤 OUTPUT FORMAT:

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
      "recommendation": "Replace wildcard with specific actions. Example:\n{\n  \"Action\": [\n    \"s3:GetObject\",\n    \"s3:PutObject\"\n  ],\n  \"Resource\": \"arn:aws:s3:::specific-bucket/*\"\n}",
      "affected_statement": 0,
      "cve_references": [],
      "compliance_impact": {
        "pci_dss": "Violates Requirement 7 - Restrict access by business need-to-know",
        "hipaa": "Violates 164.308(a)(4) - Access controls must be least privilege",
        "sox": "Violates segregation of duties requirements"
      }
    }
  ],
  "compliance_status": {
    "pci_dss": {
      "status": "NonCompliant",
      "gaps": [
        "Excessive permissions violate least privilege principle",
        "No access logging requirements enforced"
      ]
    },
    "hipaa": {
      "status": "Partial",
      "gaps": [
        "Missing encryption requirements for PHI access"
      ]
    }
  },
  "security_improvements": [
    "Implement least privilege by restricting actions to specific operations",
    "Add resource-level restrictions to limit scope",
    "Require MFA for sensitive operations",
    "Add IP-based condition blocks for additional security layer",
    "Enable CloudTrail logging for audit compliance"
  ],
  "quick_wins": [
    "Replace 's3:*' with specific actions (GetObject, PutObject) - 5 min fix",
    "Add Sid to all statements for better management - 2 min fix"
  ]
}
```

🔒 CRITICAL RULES:
1. **Be Precise**: Cite exact AWS documentation for every finding
2. **Be Actionable**: Every recommendation must include example code
3. **Prioritize Safety**: When in doubt, recommend more restrictive
4. **Explain Impact**: Always explain WHY something is risky
5. **Grade Fairly**: Score based on actual security posture, not perfection

🚫 NEVER:
- Miss critical security issues (admin access, privilege escalation)
- Provide vague recommendations without code examples
- Ignore context (consider policy purpose in scoring)
- Fail to map findings to compliance frameworks
"""

class ValidatorAgent:
    def __init__(self):
        self._agent = None
        logging.info("✅ ValidatorAgent initialized (lazy loading)")
    
    def _get_agent(self):
        """Lazy load the agent only when needed"""
        if self._agent is None:
            logging.info("🔍 Creating Security Validator Agent...")
            logging.info("   Model: us.anthropic.claude-3-7-sonnet-20250219-v1:0")
            logging.info("   System prompt length: {} chars".format(len(VALIDATOR_SYSTEM_PROMPT)))
            
            self._agent = Agent(
                model="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
                system_prompt=VALIDATOR_SYSTEM_PROMPT
            )
            logging.info("✅ Security Validator Agent created successfully")
        return self._agent

    def validate_policy(self, policy_json: str, compliance_frameworks: list = None) -> dict:
        """
        Validate an IAM policy for security issues and compliance
        
        Args:
            policy_json: IAM policy as JSON string
            compliance_frameworks: List of frameworks to check (pci_dss, hipaa, sox, gdpr)
        
        Returns:
            Validation report with findings, score, and recommendations
        """
        try:
            # Parse policy to validate JSON
            policy_dict = json.loads(policy_json)
            
            frameworks_str = ", ".join(compliance_frameworks) if compliance_frameworks else "general security best practices"
            
            prompt = f"""Analyze this IAM policy for security vulnerabilities and compliance with {frameworks_str}.

POLICY TO ANALYZE:
```json
{json.dumps(policy_dict, indent=2)}
```

COMPLIANCE FRAMEWORKS TO CHECK: {frameworks_str}

Provide a comprehensive security analysis following the exact JSON format specified in your system prompt.
Include:
1. Risk score (0-100)
2. Detailed findings with severity levels
3. Compliance status for requested frameworks
4. Prioritized remediation recommendations
5. Quick wins for immediate improvement"""

            logging.info(f"🔍 Validating policy with {len(policy_dict.get('Statement', []))} statements")
            
            agent = self._get_agent()
            result = agent(prompt)
            
            # Extract the response
            response_text = str(result.message)
            if isinstance(result.message, dict):
                if "content" in result.message and isinstance(result.message["content"], list):
                    if len(result.message["content"]) > 0 and "text" in result.message["content"][0]:
                        response_text = result.message["content"][0]["text"]
            
            logging.info("✅ Policy validation completed")
            
            # Try to extract JSON from response
            try:
                # Look for JSON block in response
                import re
                json_match = re.search(r'```json\s*([\s\S]*?)```', response_text)
                if json_match:
                    validation_result = json.loads(json_match.group(1))
                else:
                    # Try parsing entire response
                    validation_result = json.loads(response_text)
                
                return {
                    "success": True,
                    "validation": validation_result,
                    "raw_response": response_text
                }
            except json.JSONDecodeError:
                # Return structured response even if JSON parsing fails
                return {
                    "success": True,
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
            logging.exception("❌ Policy validation failed")
            return {
                "success": False,
                "error": str(e)
            }