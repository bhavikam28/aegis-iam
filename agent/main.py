from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
from policy_agent import PolicyAgent
import uuid
import json
import re

app = FastAPI(title="Aegis IAM Agent - Intelligent Conversational Server")
app.add_middleware(
    CORSMiddleware, 
    allow_origins=[
        "http://localhost:5173",
        "https://aegis-iam.vercel.app"
    ], 
    allow_methods=["*"], 
    allow_headers=["*"]
)

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
    """
    if not policy_json:
        return {
            "score": 0, 
            "issues": ["No policy provided"], 
            "breakdown": {}, 
            "explanation": "No policy was generated.",
            "security_features": []
        }
    
    score = 100
    issues = []
    breakdown = {}
    explanations = []
    security_features = []
    
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
    
    # ALWAYS check for missing conditions
    has_any_condition = any('Condition' in stmt for stmt in statements)
    
    if not has_any_condition:
        score -= 10
        issues.append("No security conditions (IP, MFA, or time restrictions)")
        breakdown['no_conditions'] = -10
        explanations.append("Policy lacks condition blocks to restrict when/how permissions can be used")
    else:
        security_features.append("✅ Includes security conditions for enhanced protection")
    
    # Check for specific condition types
    has_ip = any('ipaddress' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_mfa = any('multifactor' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_vpc = any('vpce' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_org = any('principalorgid' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    
    # Add positive security features
    if has_ip:
        security_features.append("✅ IP address restrictions enabled")
    if has_mfa:
        security_features.append("✅ MFA requirement enforced")
    if has_vpc:
        security_features.append("✅ VPC endpoint restrictions applied")
    if has_org:
        security_features.append("✅ Organization ID restriction enforced")
    
    # Check if using specific resources (not wildcards)
    has_specific_resources = True
    for stmt in statements:
        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        if any(r == '*' for r in resources):
            has_specific_resources = False
            break
    
    if has_specific_resources:
        security_features.append("✅ Uses specific resource ARNs (no wildcards)")
    
    # Check if using specific actions (not wildcards)
    has_specific_actions = True
    for stmt in statements:
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        if '*' in actions or any(':*' in str(a) for a in actions):
            has_specific_actions = False
            break
    
    if has_specific_actions:
        security_features.append("✅ Uses specific actions (follows least privilege)")
    
    # Suggest what's missing
    missing_conditions = []
    if not has_ip:
        missing_conditions.append("IP restrictions")
    if not has_mfa:
        missing_conditions.append("MFA requirements")
    if not has_vpc:
        missing_conditions.append("VPC endpoint restrictions")
    if not has_org:
        missing_conditions.append("Organization ID restrictions")
    
    # Check for encryption requirements (S3 write policies)
    is_s3_policy = any('s3:' in str(stmt.get('Action', [])) for stmt in statements)
    has_write = any(action in policy_str for action in ['put', 'delete', 'create', 'write'])
    has_encryption = any('encryption' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    
    if is_s3_policy and has_write and not has_encryption:
        score -= 5
        issues.append("S3 write operations without encryption requirements")
        breakdown['no_encryption'] = -5
        explanations.append("S3 upload permissions without requiring encryption")
    elif is_s3_policy and has_write and has_encryption:
        security_features.append("✅ Encryption requirements enforced for uploads")
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    # Generate human-readable explanation
    if score >= 95:
        grade = "A+ (Excellent)"
        summary = "Policy follows security best practices with comprehensive protections."
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
    
    # If no specific features mentioned, add general positive note
    if not security_features:
        security_features.append("⚠️ Consider adding security conditions for enhanced protection")
    
    return {
        "score": score,
        "issues": issues,
        "breakdown": breakdown,
        "explanation": explanation_text.strip(),
        "security_features": security_features
    }

def generate_intelligent_suggestions(
    user_intent: str,
    policy_json: dict,
    conversation_history: List[Dict],
    security_score: int
) -> List[str]:
    """
    Generate 5-7 relevant contextual suggestions that update after each conversation turn
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
        return suggestions[:7]  # Return immediately with critical fix
    
    if has_wildcard_action:
        suggestions.append("⚠️ Replace wildcard actions with specific permissions")
        return suggestions[:7]  # Return immediately with critical fix
    
    # Check what's already in the policy
    has_conditions = any('Condition' in stmt for stmt in statements)
    has_ip = any('ipaddress' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_mfa = any('multifactor' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_vpc = any('vpce' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_org = any('principalorgid' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_prefix = any('/' in str(res) and '*' in str(res) for stmt in statements for res in (stmt.get('Resource', []) if isinstance(stmt.get('Resource', []), list) else [stmt.get('Resource', '')]))
    has_encryption = any('encryption' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_time = any('datelessthan' in str(stmt.get('Condition', {})).lower() or 'dategreaterthan' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    has_tags = any('requestedtag' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    
    # ALWAYS offer these core suggestions if missing
    if not has_ip:
        suggestions.append("Add IP address whitelist to allow access only from corporate network")
    
    if not has_vpc and is_s3_policy:
        suggestions.append("Add VPC endpoint restriction to force private network access")
    
    if not has_mfa and has_write_access:
        suggestions.append("Require MFA for write/delete operations to prevent unauthorized changes")
    
    if not has_org:
        suggestions.append("Add organization ID restriction to limit cross-account access")
    
    if not has_encryption and is_s3_policy and has_write_access:
        suggestions.append("Require encryption for all uploads (aws:SecureTransport condition)")
    
    # ADVANCED suggestions (always offer if space available)
    if not has_time and len(suggestions) < 7:
        suggestions.append("Add time-based access restriction (only allow during business hours)")
    
    if not has_tags and len(suggestions) < 7:
        suggestions.append("Add tag-based condition to restrict by resource tags")
    
    if not has_prefix and is_s3_policy and len(suggestions) < 7:
        suggestions.append("Restrict to specific folder prefix (e.g., /reports/*) to limit file access")
    
    # Context-specific suggestions based on what user just did
    if 'ip' in last_user_msg and has_ip and not has_vpc and len(suggestions) < 7:
        suggestions.append("Great! Now add VPC endpoint restriction for additional network security")
    
    if 'vpc' in last_user_msg and has_vpc and not has_mfa and has_write_access and len(suggestions) < 7:
        suggestions.append("Excellent! Consider adding MFA requirement for critical operations")
    
    if 'mfa' in last_user_msg and has_mfa and not has_time and len(suggestions) < 7:
        suggestions.append("Perfect! You could also add time-based restrictions for compliance")
    
    # Service-specific suggestions
    if is_s3_policy and len(suggestions) < 7:
        if not has_encryption and has_write_access:
            suggestions.append("Add server-side encryption requirement for data at rest")
        if 'logging' not in policy_str and len(suggestions) < 7:
            suggestions.append("Consider enabling S3 access logging for audit trails")
    
    # Return top 7 suggestions (increased from 3)
    return suggestions[:7]

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
        
        # Generate INTELLIGENT suggestions (now returns 5-7 instead of 3)
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
            "security_features": security_analysis["security_features"],  # NEW: Positive features list
            "refinement_suggestions": intelligent_suggestions,
            "conversation_history": conversations[conversation_id]
        }
        
    except Exception as e:
        print(f"ERROR in generate endpoint: {e}")
        import traceback
        traceback.print_exc()
        
        return {
            "final_answer": "I apologize, but I encountered an error while generating your policy. Let me try again, or we can start with a basic template that I'll help you customize.",
            "conversation_id": str(uuid.uuid4()),
            "message_count": 0,
            "security_score": 0,
            "security_notes": ["Error occurred during policy generation"],
            "score_breakdown": {},
            "score_explanation": "Unable to generate policy due to an error.",
            "security_features": [],
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