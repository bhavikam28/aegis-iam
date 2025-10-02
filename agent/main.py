from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
from policy_agent import PolicyAgent
import uuid
import json
import re

app = FastAPI(title="Aegis IAM Agent - Intelligent Conversational Server")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173",
    "https://aegis-iam.vercel.app"], allow_methods=["*"], allow_headers=["*"])

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

def calculate_detailed_security_score(policy_json: dict, user_intent: str = "") -> Dict:
    """
    Calculate security score with contextual awareness and detailed breakdown
    FIXED: More strict scoring - always deduct for missing conditions
    """
    if not policy_json:
        return {
            "score": 0, 
            "issues": ["No policy provided"], 
            "breakdown": {}, 
            "explanation": "No policy was generated."
        }
    
    score = 100
    issues = []
    breakdown = {}
    explanations = []
    
    statements = policy_json.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    policy_str = json.dumps(policy_json).lower()
    intent_lower = user_intent.lower()
    
    # CRITICAL ISSUES (-25 points each)
    
    # Check for wildcard resources
    for stmt in statements:
        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        if any(r == '*' for r in resources):
            score -= 25
            issues.append("Wildcard (*) resources allow access to ALL resources")
            breakdown['wildcard_resources'] = -25
            explanations.append("Used wildcard resource (*) instead of specific ARNs")
            break
    
    # Check for wildcard actions
    for stmt in statements:
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        if '*' in actions or any(':*' in str(a) for a in actions):
            score -= 25
            issues.append("Wildcard (*) actions grant overly broad permissions")
            breakdown['wildcard_actions'] = -25
            explanations.append("Used wildcard actions (e.g., s3:*) violating least privilege")
            break
    
    # Check for full admin access
    for stmt in statements:
        actions = stmt.get('Action', [])
        resources = stmt.get('Resource', [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if '*' in actions and '*' in resources:
            score -= 30
            issues.append("Full administrative access detected")
            breakdown['full_admin'] = -30
            explanations.append("Policy grants full administrative access - extremely dangerous")
            break
    
    # ALWAYS check for missing conditions (this is the fix!)
    has_any_condition = any('Condition' in stmt for stmt in statements)
    
    if not has_any_condition:
        score -= 10
        issues.append("No security conditions (IP, MFA, or time restrictions)")
        breakdown['no_conditions'] = -10
        explanations.append("Policy lacks condition blocks to restrict when/how permissions can be used")
    
    # Check for specific condition types
    has_ip = any('ipaddress' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_mfa = any('multifactor' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_vpc = any('vpce' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    
    # Suggest what's missing
    missing_conditions = []
    if not has_ip:
        missing_conditions.append("IP restrictions")
    if not has_mfa:
        missing_conditions.append("MFA requirements")
    if not has_vpc:
        missing_conditions.append("VPC endpoint restrictions")
    
    # Check for encryption requirements (S3 write policies)
    is_s3_policy = any('s3:' in str(stmt.get('Action', [])) for stmt in statements)
    has_write = any(action in policy_str for action in ['put', 'delete', 'create', 'write'])
    has_encryption = any('encryption' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    
    if is_s3_policy and has_write and not has_encryption:
        score -= 5
        issues.append("S3 write operations without encryption requirements")
        breakdown['no_encryption'] = -5
        explanations.append("S3 upload permissions without requiring encryption")
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    # Generate human-readable explanation
    if score >= 95:
        grade = "A+ (Excellent)"
        summary = "Policy follows security best practices with only minor improvements needed."
    elif score >= 90:
        grade = "A (Very Good)"
        summary = "Policy is secure with good restrictions, but could be enhanced further."
    elif score >= 80:
        grade = "B (Good)"
        summary = "Policy is acceptable but needs additional security controls."
    elif score >= 70:
        grade = "C (Acceptable)"
        summary = "Policy works but requires security improvements for production use."
    else:
        grade = "D/F (Needs Work)"
        summary = "Policy has significant security issues that must be addressed."
    
    # Build detailed explanation
    explanation_text = f"Score Grade: {grade}\n\n{summary}\n\n"
    
    if explanations:
        explanation_text += "Why this score?\n"
        for exp in explanations:
            explanation_text += f"• {exp}\n"
    else:
        explanation_text += "Why this score?\n• Policy uses specific actions and resources\n• Applies principle of least privilege\n"
    
    if missing_conditions:
        explanation_text += f"\nMissing security controls: {', '.join(missing_conditions)}"
    
    return {
        "score": score,
        "issues": issues,
        "breakdown": breakdown,
        "explanation": explanation_text.strip()
    }

def generate_intelligent_suggestions(
    user_intent: str,
    policy_json: dict,
    conversation_history: List[Dict],
    security_score: int
) -> List[str]:
    """
    FIXED: Generate 2-3 relevant contextual suggestions
    """
    suggestions = []
    
    if not policy_json:
        return []
    
    statements = policy_json.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    policy_str = json.dumps(policy_json).lower()
    intent_lower = user_intent.lower()
    
    # Get last user message
    last_user_msg = ""
    for msg in reversed(conversation_history):
        if msg['role'] == 'user':
            last_user_msg = msg['content'].lower()
            break
    
    # Context
    is_s3_policy = any('s3:' in str(stmt.get('Action', [])) for stmt in statements)
    has_write_access = any(action in policy_str for action in ['put', 'delete', 'create', 'write'])
    has_read_only = 'get' in policy_str and not has_write_access
    is_first_generation = len(conversation_history) <= 2
    
    # ⚠️ CRITICAL: Fix wildcard issues first
    has_wildcard_resource = False
    for stmt in statements:
        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        if any(r == '*' for r in resources):
            has_wildcard_resource = True
            break
    
    has_wildcard_action = False
    for stmt in statements:
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        if any(':*' in str(a) for a in actions):
            has_wildcard_action = True
            break
    
    if has_wildcard_resource:
        suggestions.append("⚠️ Replace wildcard resources with specific ARNs")
        return suggestions
    
    if has_wildcard_action:
        suggestions.append("⚠️ Replace wildcard actions with specific permissions")
        return suggestions
    
    # Check what's already in the policy
    has_conditions = any('Condition' in stmt for stmt in statements)
    has_ip = any('ipaddress' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_mfa = any('multifactor' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_vpc = any('vpce' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_prefix = any('/' in str(res) and '*' in str(res) for stmt in statements for res in (stmt.get('Resource', []) if isinstance(stmt.get('Resource', []), list) else [stmt.get('Resource', '')]))
    
    # FIRST GENERATION - Suggest foundational security
    if is_first_generation:
        # 1. Prefix restriction (for S3 read-only)
        if is_s3_policy and has_read_only and not has_prefix:
            suggestions.append("Restrict to specific folder prefix (e.g., /reports/*) to limit file access")
        
        # 2. IP restriction (always relevant if no conditions)
        if not has_ip and not has_conditions:
            suggestions.append("Add IP address whitelist to allow access only from corporate network")
        
        # 3. MFA for write, or VPC for read
        if has_write_access and not has_mfa:
            suggestions.append("Require MFA for write/delete operations to prevent unauthorized changes")
        elif not has_vpc and is_s3_policy:
            suggestions.append("Add VPC endpoint restriction to force private network access")
    
    # FOLLOW-UP GENERATION - Progressive suggestions
    else:
        # If user just added prefix
        if ('prefix' in last_user_msg or has_prefix) and is_s3_policy:
            if not has_ip:
                suggestions.append("Add IP restriction to allow access only from specific network ranges")
            if has_write_access:
                suggestions.append("Require encryption for all uploads (aws:SecureTransport condition)")
        
        # If user just added IP
        elif ('ip' in last_user_msg or has_ip) and not has_vpc:
            suggestions.append("Add VPC endpoint restriction for additional network security")
            if not has_mfa and has_write_access:
                suggestions.append("Require MFA for sensitive write operations")
        
        # If user added VPC
        elif ('vpc' in last_user_msg or has_vpc) and not has_mfa:
            suggestions.append("Add MFA requirement for critical operations")
        
        # Default - suggest what's missing
        else:
            if not has_ip:
                suggestions.append("Add IP address restrictions for network-level security")
            if not has_vpc and is_s3_policy:
                suggestions.append("Restrict access through VPC endpoint only")
            if not has_mfa and has_write_access:
                suggestions.append("Require MFA for write/delete operations")
    
    # Return top 3 suggestions
    return suggestions[:3]

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
        
        # Extract policy JSON
        policy_json = extract_policy_json(final_message)
        
        # Calculate security score WITH CONTEXT
        security_analysis = calculate_detailed_security_score(
            policy_json, 
            user_intent=request.description
        )
        
        # Add agent response to history
        assistant_message = {
            "role": "assistant",
            "content": final_message,
            "timestamp": str(uuid.uuid4())
        }
        conversations[conversation_id].append(assistant_message)
        
        # Generate INTELLIGENT suggestions
        intelligent_suggestions = generate_intelligent_suggestions(
            user_intent=request.description,
            policy_json=policy_json,
            conversation_history=conversations[conversation_id],
            security_score=security_analysis["score"]
        )
        
        return {
            "final_answer": final_message,
            "conversation_id": conversation_id,
            "message_count": len(conversations[conversation_id]),
            "security_score": security_analysis["score"],
            "security_notes": security_analysis["issues"],
            "score_breakdown": security_analysis["breakdown"],
            "score_explanation": security_analysis["explanation"],
            "refinement_suggestions": intelligent_suggestions,
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
            "score_explanation": "",
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