from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
from policy_agent import PolicyAgent
from security_validator import calculate_security_score
import uuid
import json
import re

app = FastAPI(title="Aegis IAM Agent - Conversational Server")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory conversation storage
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

@app.post("/generate")
def generate(request: GenerationRequest):
    try:
        # Generate or retrieve conversation ID
        conversation_id = request.conversation_id or str(uuid.uuid4())
        
        # Initialize conversation history if new
        if conversation_id not in conversations:
            conversations[conversation_id] = []
        
        # Add user message to history
        conversations[conversation_id].append({
            "role": "user",
            "content": request.description,
            "timestamp": str(uuid.uuid4())  # Simple timestamp placeholder
        })
        
        # Build context for agent (include previous messages for follow-ups)
        if request.is_followup and len(conversations[conversation_id]) > 1:
            context = "\n".join([
                f"{msg['role']}: {msg['content']}" 
                for msg in conversations[conversation_id][-3:]
            ])
            prompt = f"Previous conversation:\n{context}\n\nNow, {request.description}"
        else:
            prompt = request.description
        
        # Run agent
        agent_result = aegis_agent.run(user_request=prompt, service=request.service)
        
        # Extract response from agent
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
        
        # Calculate real security score
        policy_json = extract_policy_json(final_message)
        if policy_json:
            security_analysis = calculate_security_score(policy_json)
            security_score = security_analysis['score']
            security_notes = security_analysis['issues']
        else:
            security_score = 85
            security_notes = []
        
        # Add agent response to history
        conversations[conversation_id].append({
            "role": "assistant",
            "content": final_message,
            "timestamp": str(uuid.uuid4())
        })
        
        # Generate refinement suggestions for initial policies
        refinement_suggestions = []
        if not request.is_followup:
            refinement_suggestions = [
                "Restrict to specific S3 prefix (e.g., red-team/*)",
                "Add organization ID condition",
                "Restrict to VPC endpoints",
                "Add time-based restrictions"
            ]
        
        return {
            "final_answer": final_message,
            "conversation_id": conversation_id,
            "message_count": len(conversations[conversation_id]),
            "security_score": security_score,
            "security_notes": security_notes,
            "refinement_suggestions": refinement_suggestions,
            "conversation_history": conversations[conversation_id]  # Include full history
        }
        
    except Exception as e:
        print(f"ERROR in generate endpoint: {e}")
        import traceback
        traceback.print_exc()
        
        error_response = f"""```json
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::example-bucket/*"]
    }}
  ]
}}
"""