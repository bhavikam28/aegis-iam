from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Tuple
from policy_agent import PolicyAgent
import uuid
import json
import re

app = FastAPI(title="Aegis IAM Agent - Intelligent Conversational Server")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

conversations: Dict[str, List[Dict]] = {}

class GenerationRequest(BaseModel):
    description: str
    service: str
    conversation_id: Optional[str] = None
    is_followup: bool = False

@app.get("/")
def health():
    return {"status": "healthy", "message": "Aegis IAM Agent is running"}

aegis_agent = PolicyAgent()

def extract_policy_json(message: str) -> dict:
    """Extract JSON policy from agent's response"""
    match = re.search(r'```json\n([\s\S]*?)\n```', message)
    if match:
        try:
            return json.loads(match.group(1))
        except:
            return None
    return None

def calculate_detailed_security_score(policy_json: dict) -> Dict:
    """
    Comprehensive security scoring with detailed breakdown
    Returns: {score: int, issues: [], breakdown: {}}
    """
    if not policy_json:
        return {"score": 0, "issues": ["No policy provided"], "breakdown": {}}
    
    score = 100
    issues = []
    breakdown = {}
    
    statements = policy_json.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    # CRITICAL ISSUES (-25 points each)
    
    # Check for wildcard resources
    wildcard_resources = False
    for stmt in statements:
        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        if any(r == '*' for r in resources):
            wildcard_resources = True
            score -= 25
            issues.append("CRITICAL: Wildcard (*) resources allow access to ALL resources")
            breakdown['wildcard_resources'] = -25
            break
    
    # Check for wildcard actions
    wildcard_actions = False
    for stmt in statements:
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        if '*' in actions or any(':*' in str(a) for a in actions):
            wildcard_actions = True
            score -= 25
            issues.append("CRITICAL: Wildcard (*) actions grant overly broad permissions")
            breakdown['wildcard_actions'] = -25
            break
    
    # Check for full admin access (Action: *, Resource: *)
    for stmt in statements:
        actions = stmt.get('Action', [])
        resources = stmt.get('Resource', [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if '*' in actions and '*' in resources:
            score -= 30  # Extra penalty for full admin
            issues.append("CRITICAL: Full administrative access (Action: *, Resource: *)")
            breakdown['full_admin'] = -30
            break
    
    # HIGH SEVERITY ISSUES (-15 points each)
    
    # Check for dangerous actions
    dangerous_actions = [
        'iam:CreateAccessKey', 'iam:CreateUser', 'iam:DeleteUser',
        'iam:PutUserPolicy', 'iam:AttachUserPolicy',
        's3:DeleteBucket', 's3:DeleteBucketPolicy',
        'ec2:TerminateInstances', 'rds:DeleteDBInstance'
    ]
    has_dangerous = False
    for stmt in statements:
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if action in dangerous_actions:
                has_dangerous = True
                score -= 15
                issues.append(f"HIGH RISK: Dangerous action '{action}' allowed without conditions")
                breakdown['dangerous_actions'] = -15
                break
        if has_dangerous:
            break
    
    # MEDIUM SEVERITY ISSUES (-10 points each)
    
    # Check for missing conditions
    has_any_condition = any('Condition' in stmt for stmt in statements)
    if not has_any_condition:
        score -= 10
        issues.append("Missing conditions: No IP, MFA, or time-based restrictions")
        breakdown['no_conditions'] = -10
    
    # Check for missing MFA on sensitive operations
    has_mfa = any('aws:MultiFactorAuthPresent' in str(stmt.get('Condition', {})) for stmt in statements)
    has_sensitive_actions = any(
        any(action in str(stmt.get('Action', [])) for action in ['Delete', 'Put', 'Create', 'Update'])
        for stmt in statements
    )
    if has_sensitive_actions and not has_mfa:
        score -= 10
        issues.append("No MFA requirement for sensitive actions (Put, Delete, Create, Update)")
        breakdown['no_mfa_on_sensitive'] = -10
    
    # LOW SEVERITY ISSUES (-5 points each)
    
    # Check for missing IP restrictions
    has_ip = any('IpAddress' in str(stmt.get('Condition', {})) for stmt in statements)
    if not has_ip:
        score -= 5
        issues.append("No IP address restrictions defined")
        breakdown['no_ip_restriction'] = -5
    
    # Check for missing time restrictions
    has_time = any('aws:CurrentTime' in str(stmt.get('Condition', {})) for stmt in statements)
    if not has_time and not has_ip:  # Only flag if also missing IP (one or the other is ok)
        score -= 5
        issues.append("No time-based access restrictions")
        breakdown['no_time_restriction'] = -5
    
    # Check for missing VPC endpoint restrictions (S3 specific)
    is_s3_policy = any('s3:' in str(stmt.get('Action', [])) for stmt in statements)
    has_vpc_endpoint = any('aws:SourceVpce' in str(stmt.get('Condition', {})) for stmt in statements)
    if is_s3_policy and not has_vpc_endpoint:
        score -= 5
        issues.append("S3 policy without VPC endpoint restriction (allows public internet access)")
        breakdown['no_vpc_endpoint'] = -5
    
    # Check for missing encryption requirements (S3 specific)
    has_encryption = any('s3:x-amz-server-side-encryption' in str(stmt.get('Condition', {})) for stmt in statements)
    if is_s3_policy and not has_encryption:
        score -= 5
        issues.append("S3 policy without encryption requirements")
        breakdown['no_encryption'] = -5
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    # Add positive notes if score is high
    if score >= 95:
        issues.insert(0, "✓ Excellent security posture")
    elif score >= 85:
        issues.insert(0, "✓ Good security with minor improvements needed")
    elif score >= 70:
        issues.insert(0, "⚠ Acceptable but needs security improvements")
    else:
        issues.insert(0, "❌ Significant security issues detected")
    
    return {
        "score": score,
        "issues": issues,
        "breakdown": breakdown
    }

def extract_user_intent(message: str) -> Dict:
    """
    Analyze user's message to understand what they're trying to achieve
    Returns: {intent: str, service: str, missing_info: []}
    """
    msg_lower = message.lower()
    
    intent = {
        "type": None,
        "service": None,
        "action": None,
        "resource": None,
        "missing_info": []
    }
    
    # Detect service
    if 's3' in msg_lower or 'bucket' in msg_lower:
        intent["service"] = "s3"
    elif 'lambda' in msg_lower or 'function' in msg_lower:
        intent["service"] = "lambda"
    elif 'dynamodb' in msg_lower or 'table' in msg_lower:
        intent["service"] = "dynamodb"
    elif 'ec2' in msg_lower or 'instance' in msg_lower:
        intent["service"] = "ec2"
    
    # Detect action type
    if 'read' in msg_lower or 'get' in msg_lower or 'list' in msg_lower or 'view' in msg_lower:
        intent["action"] = "read"
    elif 'write' in msg_lower or 'put' in msg_lower or 'create' in msg_lower or 'upload' in msg_lower:
        intent["action"] = "write"
    elif 'delete' in msg_lower or 'remove' in msg_lower:
        intent["action"] = "delete"
    elif 'full' in msg_lower or 'admin' in msg_lower or 'manage' in msg_lower:
        intent["action"] = "full"
    
    # Detect resource mentions
    bucket_match = re.search(r'bucket\s+(?:named\s+)?["\']?([a-z0-9-]+)["\']?', msg_lower)
    if bucket_match:
        intent["resource"] = bucket_match.group(1)
    
    table_match = re.search(r'table\s+(?:named\s+)?["\']?([a-z0-9-]+)["\']?', msg_lower)
    if table_match:
        intent["resource"] = table_match.group(1)
    
    # Check for missing critical information
    if intent["service"] == "s3" and not intent["resource"]:
        intent["missing_info"].append("bucket_name")
    
    if intent["service"] == "dynamodb" and not intent["resource"]:
        intent["missing_info"].append("table_name")
    
    # Check for conditions mentions without values
    if 'ip' in msg_lower and 'restrict' in msg_lower:
        if not re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', message):
            intent["missing_info"].append("ip_range")
    
    if 'org' in msg_lower or 'organization' in msg_lower:
        if not re.search(r'o-[a-z0-9]{10,}', message):
            intent["missing_info"].append("org_id")
    
    if 'vpc' in msg_lower and 'endpoint' in msg_lower:
        if not re.search(r'vpce-[a-z0-9]+', message):
            intent["missing_info"].append("vpc_endpoint_id")
    
    if 'prefix' in msg_lower or 'folder' in msg_lower or 'path' in msg_lower:
        if not re.search(r'[a-z0-9-]+/\*', message):
            intent["missing_info"].append("prefix_path")
    
    return intent

def generate_clarifying_questions(user_intent: Dict, policy_json: dict) -> List[str]:
    """
    Generate specific clarifying questions based on user intent and current policy
    Returns: List of questions the agent should ask
    """
    questions = []
    
    missing = user_intent.get("missing_info", [])
    
    if "bucket_name" in missing:
        questions.append("🤔 **What's the exact S3 bucket name?** (e.g., `my-app-data`, `company-logs`)")
    
    if "table_name" in missing:
        questions.append("🤔 **What's the DynamoDB table name?** (e.g., `users`, `orders`)")
    
    if "ip_range" in missing:
        questions.append("🤔 **What IP range should I allow?** (e.g., `10.0.0.0/8` for corporate VPN, `203.0.113.0/24` for office)")
    
    if "org_id" in missing:
        questions.append("🤔 **What's your AWS Organization ID?** (Format: `o-xxxxxxxxxx` - find it in AWS Organizations console)")
    
    if "vpc_endpoint_id" in missing:
        questions.append("🤔 **What's your VPC Endpoint ID?** (Format: `vpce-xxxxxxxxx` - find it in VPC console → Endpoints)")
    
    if "prefix_path" in missing:
        questions.append("🤔 **What specific folder/prefix path?** (e.g., `team-name/*`, `data/reports/*`, `users/john/*`)")
    
    # Check policy for placeholders
    if policy_json:
        policy_str = json.dumps(policy_json)
        
        if 'o-example' in policy_str or 'exampleorgid' in policy_str:
            questions.append("🤔 **Replace placeholder org ID** - I used `o-exampleorgid`. What's your real organization ID?")
        
        if 'vpce-example' in policy_str:
            questions.append("🤔 **Replace placeholder VPC endpoint** - What's your actual VPC endpoint ID?")
        
        if 'team-name' in policy_str or 'specific' in policy_str.lower():
            questions.append("🤔 **Specify the exact prefix** - I used a generic path. What's the actual folder structure?")
    
    return questions

def generate_intelligent_suggestions(
    user_intent: Dict,
    policy_json: dict,
    conversation_history: List[Dict]
) -> List[Dict[str, str]]:
    """
    Generate suggestions based ONLY on:
    1. What user is trying to achieve (intent)
    2. What's missing in current policy
    3. Next logical security step
    
    No hardcoded generic suggestions!
    """
    suggestions = []
    
    if not policy_json:
        return []
    
    service = user_intent.get("service", "")
    action = user_intent.get("action", "")
    
    statements = policy_json.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    policy_str = json.dumps(policy_json).lower()
    
    # Get what user last asked for from conversation
    last_user_msg = ""
    for msg in reversed(conversation_history):
        if msg['role'] == 'user':
            last_user_msg = msg['content'].lower()
            break
    
    # INTELLIGENT SUGGESTION LOGIC - Based on what user JUST did
    
    # If user just created a basic policy, suggest first security layer
    if len(conversation_history) <= 2:  # Initial request
        if service == "s3":
            if action == "read":
                suggestions.append({
                    "suggestion": "Limit to specific prefix (e.g., team-folder/*)",
                    "reason": "Currently allows reading ALL files in bucket. Restrict to only needed folders."
                })
            suggestions.append({
                "suggestion": "Add IP address whitelist",
                "reason": "Only allow access from your corporate network/VPN to prevent unauthorized access."
            })
        
        if action in ["write", "delete", "full"]:
            suggestions.append({
                "suggestion": "Require MFA for destructive operations",
                "reason": "Delete and write operations are high-risk. Require MFA for extra protection."
            })
    
    # If user just added a prefix restriction
    if 'prefix' in last_user_msg or 's3:prefix' in policy_str:
        suggestions.append({
            "suggestion": "Enable CloudTrail data events for this prefix",
            "reason": "Track who accessed which files for compliance and security audits."
        })
        suggestions.append({
            "suggestion": "Require encryption on uploads (SSE-S3 or SSE-KMS)",
            "reason": "Ensure all files in this prefix are encrypted at rest."
        })
    
    # If user just added org ID
    if 'org' in last_user_msg or 'aws:principalorgid' in policy_str:
        suggestions.append({
            "suggestion": "Restrict to specific AWS accounts in your org",
            "reason": "Further limit which accounts can access (e.g., only production accounts)."
        })
        suggestions.append({
            "suggestion": "Add required resource tags",
            "reason": "Ensure resources are properly tagged for governance and cost allocation."
        })
    
    # If user just added IP restriction
    if 'ip' in last_user_msg or 'ipaddress' in policy_str:
        suggestions.append({
            "suggestion": "Add VPC endpoint restriction",
            "reason": "Force access through private network, block public internet even from allowed IPs."
        })
        suggestions.append({
            "suggestion": "Add time-based restriction (business hours)",
            "reason": "Only allow access during work hours for additional security."
        })
    
    # If user just added VPC endpoint
    if 'vpc' in last_user_msg or 'sourcevpce' in policy_str:
        suggestions.append({
            "suggestion": "Require TLS 1.2+ for encryption in transit",
            "reason": "Ensure all connections use modern, secure encryption protocols."
        })
    
    # If user just added encryption requirements
    if 'encrypt' in last_user_msg or 'server-side-encryption' in policy_str:
        suggestions.append({
            "suggestion": "Enforce specific KMS key usage",
            "reason": "Control which encryption keys can be used for better key management."
        })
    
    # Check for critical missing items (always suggest if missing)
    has_conditions = any('Condition' in stmt for stmt in statements)
    has_wildcard = '*' in policy_str and 'resource' in policy_str
    
    if has_wildcard:
        suggestions.insert(0, {
            "suggestion": "🚨 URGENT: Replace wildcard (*) with specific ARNs",
            "reason": "Wildcard grants overly broad access. Specify exact resources."
        })
    
    if not has_conditions and len(suggestions) == 0:
        # Only if no other contextual suggestions, offer first security layer
        suggestions.append({
            "suggestion": "Add your first security condition",
            "reason": "Choose one: IP restriction, MFA requirement, or time-based access."
        })
    
    return suggestions[:4]  # Max 4 suggestions

@app.post("/generate")
def generate(request: GenerationRequest):
    try:
        conversation_id = request.conversation_id or str(uuid.uuid4())
        
        if conversation_id not in conversations:
            conversations[conversation_id] = []
        
        user_message = {
            "role": "user",
            "content": request.description,
            "timestamp": str(uuid.uuid4())
        }
        conversations[conversation_id].append(user_message)
        
        # Build context for agent
        if request.is_followup and len(conversations[conversation_id]) > 1:
            context = "\n".join([
                f"{msg['role']}: {msg['content']}" 
                for msg in conversations[conversation_id][-5:]
            ])
            prompt = f"Previous conversation:\n{context}\n\nNow, {request.description}"
        else:
            prompt = request.description
        
        # Run agent
        agent_result = aegis_agent.run(user_request=prompt, service=request.service)
        
        # Extract response
        if isinstance(agent_result.message, dict):
            if 'content' in agent_result.message and isinstance(agent_result.message['content'], list):
                if len(agent_result.message['content']) > 0 and 'text' in agent_result.message['content'][0]:
                    final_message = agent_result.message['content'][0]['text']
                else:
                    final_message = str(agent_result.message)
            else:
                final_message = str(agent_result.message)
        else:
            final_message = str(agent_result.message)
        
        # Extract policy and calculate DETAILED security score
        policy_json = extract_policy_json(final_message)
        security_analysis = calculate_detailed_security_score(policy_json)
        
        # Add agent response to history
        assistant_message = {
            "role": "assistant",
            "content": final_message,
            "timestamp": str(uuid.uuid4())
        }
        conversations[conversation_id].append(assistant_message)
        
        # Analyze user intent
        user_intent = extract_user_intent(request.description)
        
        # Generate clarifying questions
        clarifying_questions = generate_clarifying_questions(user_intent, policy_json)
        
        # Generate intelligent suggestions
        intelligent_suggestions = generate_intelligent_suggestions(
            user_intent,
            policy_json,
            conversations[conversation_id]
        )
        
        # Format suggestions
        formatted_suggestions = [
            f"{s['suggestion']} → {s['reason']}"
            for s in intelligent_suggestions
        ]
        
        # Combine questions and suggestions
        all_suggestions = clarifying_questions + formatted_suggestions
        
        return {
            "final_answer": final_message,
            "conversation_id": conversation_id,
            "message_count": len(conversations[conversation_id]),
            "security_score": security_analysis["score"],
            "security_notes": security_analysis["issues"],
            "score_breakdown": security_analysis["breakdown"],
            "refinement_suggestions": all_suggestions[:5],
            "conversation_history": conversations[conversation_id]
        }
        
    except Exception as e:
        print(f"ERROR in generate endpoint: {e}")
        import traceback
        traceback.print_exc()
        
        return {
            "final_answer": "Error generating policy",
            "conversation_id": str(uuid.uuid4()),
            "message_count": 0,
            "security_score": 0,
            "security_notes": ["Error occurred"],
            "score_breakdown": {},
            "refinement_suggestions": [],
            "conversation_history": []
        }

@app.get("/conversation/{conversation_id}")
def get_conversation(conversation_id: str):
    if conversation_id not in conversations:
        return {"error": "Conversation not found", "conversation_id": conversation_id}
    
    return {
        "conversation_id": conversation_id,
        "messages": conversations[conversation_id],
        "message_count": len(conversations[conversation_id])
    }

@app.delete("/conversation/{conversation_id}")
def clear_conversation(conversation_id: str):
    if conversation_id in conversations:
        del conversations[conversation_id]
        return {"message": "Conversation cleared", "conversation_id": conversation_id}
    return {"error": "Conversation not found", "conversation_id": conversation_id}