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

def extract_explanation(message: str) -> str:
    """Extract explanation from agent's response"""
    # Try to find Explanation section
    match = re.search(r'\*\*Explanation:\*\*\s*([\s\S]*?)(?:\*\*Next Steps:\*\*|$)', message)
    if match:
        explanation = match.group(1).strip()
        # Remove code blocks from explanation
        explanation = re.sub(r'```json[\s\S]*?```', '', explanation)
        explanation = re.sub(r'```[\s\S]*?```', '', explanation)
        return explanation.strip()
    
    # Fallback: get everything after the JSON block
    parts = message.split('```')
    if len(parts) > 2:
        text = parts[2].strip()
        # Remove "Next Steps" section if present
        text = re.sub(r'\*\*Next Steps:\*\*[\s\S]*$', '', text)
        return text.strip()
    
    return "Policy generated successfully."

def extract_next_steps(message: str) -> List[str]:
    """Extract Next Steps suggestions from agent's response"""
    match = re.search(r'\*\*Next Steps:\*\*\s*([\s\S]*?)$', message)
    if match:
        next_steps_text = match.group(1).strip()
        # Split by newlines and clean up
        suggestions = []
        for line in next_steps_text.split('\n'):
            line = line.strip()
            # Remove bullet points, numbers, quotes
            line = re.sub(r'^[\d\.\-\*\•\"\']+ ?', '', line)
            line = re.sub(r'[\"\']$', '', line)
            if line and len(line) > 15:  # Ignore very short lines
                suggestions.append(line)
        return suggestions[:5]  # Return max 5 suggestions
    return []

def calculate_detailed_security_score(policy_json: dict, user_intent: str = "") -> Dict:
    """
    Calculate security score with STRICTER grading
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
    
    # CRITICAL ISSUES
    
    # Check for wildcard resources (-30 points)
    for stmt in statements:
        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        if any(r == '*' for r in resources):
            score -= 30
            issues.append("Wildcard (*) resources allow access to ALL resources")
            breakdown['wildcard_resources'] = -30
            explanations.append("Using wildcard resource (*) instead of specific ARNs")
            break
    
    # Check for wildcard actions (-30 points)
    for stmt in statements:
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        if '*' in actions or any(':*' in str(a) for a in actions):
            score -= 30
            issues.append("Wildcard (*) actions grant overly broad permissions")
            breakdown['wildcard_actions'] = -30
            explanations.append("Using wildcard actions (e.g., s3:*) violating least privilege")
            break
    
    # Check for full admin access (-40 points)
    for stmt in statements:
        actions = stmt.get('Action', [])
        resources = stmt.get('Resource', [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if '*' in actions and '*' in resources:
            score -= 40
            issues.append("Full administrative access detected")
            breakdown['full_admin'] = -40
            explanations.append("Policy grants full administrative access - critical security risk")
            break
    
    # Check for missing conditions (-25 points, STRICTER)
    has_any_condition = any('Condition' in stmt for stmt in statements)
    
    if not has_any_condition:
        score -= 25  # Changed from -10 to -25
        issues.append("No security conditions (IP, MFA, VPC, or organizational restrictions)")
        breakdown['no_conditions'] = -25
        explanations.append("Policy lacks condition blocks - missing critical security controls")
    else:
        security_features.append("✅ Includes security condition blocks")
    
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
    
    # Check if using specific resources
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
    
    # Check if using specific actions
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
    
    # Check for encryption requirements (S3 write policies)
    is_s3_policy = any('s3:' in str(stmt.get('Action', [])) for stmt in statements)
    has_write = any(action in policy_str for action in ['put', 'delete', 'create', 'write'])
    has_encryption = any('encryption' in str(stmt.get('Condition', {})).lower() or 'securetransport' in str(stmt.get('Condition', {})).lower() for stmt in statements)
    
    if is_s3_policy and has_write and not has_encryption:
        score -= 10
        issues.append("S3 write operations without encryption requirements")
        breakdown['no_encryption'] = -10
        explanations.append("Missing encryption enforcement for S3 uploads")
    elif is_s3_policy and has_write and has_encryption:
        security_features.append("✅ Encryption requirements enforced for uploads")
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    # Generate human-readable explanation with STRICTER grading
    if score >= 95:
        grade = "A+ (Excellent)"
        summary = "Exceptional security posture with comprehensive protections. Production-ready."
    elif score >= 85:
        grade = "A (Very Good)"
        summary = "Strong security with good protections. Minor enhancements recommended."
    elif score >= 75:
        grade = "B (Good)"
        summary = "Solid foundation but needs additional security controls for production use."
    elif score >= 65:
        grade = "C (Acceptable)"
        summary = "Functional but requires significant security improvements before production deployment."
    else:
        grade = "D/F (Needs Work)"
        summary = "Critical security gaps that must be addressed immediately."
    
    # Build detailed explanation
    explanation_text = f"**Grade: {grade}**\n\n{summary}\n\n"
    
    if explanations:
        explanation_text += "**Why this score?**\n"
        for exp in explanations:
            explanation_text += f"• {exp}\n"
    else:
        explanation_text += "**Why this score?**\n"
        explanation_text += "• Policy uses specific actions and resources\n"
        explanation_text += "• Follows principle of least privilege\n"
    
    # If no specific features mentioned, add note
    if not security_features:
        security_features.append("⚠️ Basic policy structure - add security conditions for production use")
    
    return {
        "score": score,
        "issues": issues,
        "breakdown": breakdown,
        "explanation": explanation_text.strip(),
        "security_features": security_features
    }

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
        
        # Extract components from agent response
        policy_json = extract_policy_json(final_message)
        explanation = extract_explanation(final_message)
        ai_suggestions = extract_next_steps(final_message)
        
        # Calculate security score
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
        
        return {
            "final_answer": final_message,
            "conversation_id": conversation_id,
            "message_count": len(conversations[conversation_id]),
            "security_score": security_analysis["score"],
            "security_notes": security_analysis["issues"],
            "score_breakdown": security_analysis["breakdown"],
            "score_explanation": security_analysis["explanation"],
            "security_features": security_analysis["security_features"],
            "refinement_suggestions": ai_suggestions,  # Now from AI!
            "conversation_history": conversations[conversation_id],
            "explanation": explanation  # Clean explanation without code blocks
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
            "conversation_history": [],
            "explanation": "Error generating policy."
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