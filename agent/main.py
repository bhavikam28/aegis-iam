from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
from policy_agent import PolicyAgent
from validator_agent import ValidatorAgent
import uuid
import json
import re
import logging
import asyncio

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Aegis IAM Agent - MCP Enabled")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://aegis-iam.vercel.app"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True
)

class GenerationRequest(BaseModel):
    description: str
    service: str
    conversation_id: Optional[str] = None
    is_followup: bool = False

class ValidationRequest(BaseModel):
    policy_json: Optional[str] = None
    role_arn: Optional[str] = None
    compliance_frameworks: Optional[List[str]] = ["general"]
    mode: str = "quick"  # "quick" or "audit"

class AuditRequest(BaseModel):
    """Request for full autonomous audit"""
    compliance_frameworks: Optional[List[str]] = ["pci_dss", "hipaa", "sox", "gdpr", "cis"]

conversations: Dict[str, List[Dict]] = {}
aegis_agent = PolicyAgent()
validator_agent = ValidatorAgent()

@app.get("/")
def health():
    return {
        "status": "healthy",
        "message": "Aegis IAM Agent with MCP Support",
        "mcp_enabled": True,
        "features": ["policy_generation", "validation", "autonomous_audit"]
    }

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logging.info(f"Incoming request: {request.method} {request.url}")
    try:
        response = await call_next(request)
        logging.info(f"Response status: {response.status_code}")
        return response
    except Exception as e:
        logging.error(f"Request failed: {str(e)}")
        raise

# ============================================
# POLICY GENERATION (Keep existing)
# ============================================

@app.post("/generate")
async def generate(request: GenerationRequest):
    """Generate IAM policy - keep existing implementation"""
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
        
        # Check if user specified specific resource names
        has_specific_resources = bool(re.search(r'(bucket|table|function|queue|topic)\s+(?:named|called)?\s*["\']?[\w-]+["\']?', request.description, re.IGNORECASE))

        if has_specific_resources and not request.is_followup:
            # Force a question response
            question_response = f"""Hi! I'd be happy to help create a secure IAM policy.

I see you need a policy for {request.service} with specific resource names. To create production-ready ARNs with exact resource references, I need:

- **AWS Account ID** (12 digits)
- **AWS Region** (e.g., us-east-1)

Or I can use {{{{ACCOUNT_ID}}}} and {{{{REGION}}}} placeholders that you can replace later - which would you prefer?"""
            
            assistant_message = {
                "role": "assistant",
                "content": question_response,
                "timestamp": str(uuid.uuid4())
            }
            conversations[conversation_id].append(assistant_message)
            
            return {
                "conversation_id": conversation_id,
                "final_answer": question_response,
                "message_count": len(conversations[conversation_id]),
                "policy": None,
                "explanation": "",
                "security_score": 0,
                "security_notes": [],
                "security_features": [],
                "score_explanation": "",
                "is_question": True,
                "conversation_history": [
                    {"role": "user", "content": request.description, "timestamp": user_message["timestamp"]},
                    {"role": "assistant", "content": question_response, "timestamp": assistant_message["timestamp"]}
                ],
                "refinement_suggestions": []
            }
        
        prompt = request.description
        if request.is_followup and len(conversations[conversation_id]) > 1:
            context = "\n".join([
                f"{msg['role']}: {msg['content']}" 
                for msg in conversations[conversation_id][-5:]
            ])
            prompt = f"Previous conversation:\n{context}\n\nNow, {request.description}"
        
        async with asyncio.timeout(30):
            logging.info(f"Calling agent with prompt: {prompt[:100]}...")
            agent_result = aegis_agent.run(user_request=prompt, service=request.service)
            
            final_message = str(agent_result.message)
            if isinstance(agent_result.message, dict):
                if "content" in agent_result.message and isinstance(agent_result.message["content"], list):
                    if len(agent_result.message["content"]) > 0 and "text" in agent_result.message["content"][0]:
                        final_message = agent_result.message["content"][0]["text"]
            
            assistant_message = {
                "role": "assistant",
                "content": final_message,
                "timestamp": str(uuid.uuid4())
            }
            conversations[conversation_id].append(assistant_message)
            
            policy = None
            explanation = final_message
            security_score = 0
            security_notes = []
            security_features = []
            score_explanation = ""
            is_question = True
            
            logging.info(f"📝 Parsing agent response (length: {len(final_message)} chars)")
            
            # Try to extract JSON policy from the response
            json_str = None
            
            # Pattern 1: Markdown code block with json tag
            markdown_match = re.search(r'```json\s*([\s\S]*?)```', final_message, re.IGNORECASE)
            if markdown_match:
                json_str = markdown_match.group(1).strip()
                logging.info(f"🔍 Found JSON in markdown code block")
            
            if not json_str:
                # Pattern 2: Any markdown code block containing Version and Statement
                markdown_match = re.search(r'```\s*([\s\S]*?Version[\s\S]*?Statement[\s\S]*?)```', final_message, re.IGNORECASE)
                if markdown_match:
                    json_str = markdown_match.group(1).strip()
                    logging.info(f"🔍 Found JSON in code block")
            
            if not json_str:
                # Pattern 3: Raw JSON in text
                json_match = re.search(r'\{[\s\S]*?"Version"\s*:\s*"[^"]*"[\s\S]*?"Statement"\s*:[\s\S]*?\][\s\S]*?\}', final_message)
                if json_match:
                    json_str = json_match.group(0)
                    logging.info(f"🔍 Found raw JSON structure")
            
            if json_str:
                logging.info(f"📄 Extracted JSON ({len(json_str)} chars)")
                try:
                    policy = json.loads(json_str)
                    is_question = False
                    logging.info("✅ Successfully extracted and parsed policy JSON")
                    logging.info(f"   Policy has {len(policy.get('Statement', []))} statements")
                except json.JSONDecodeError as e:
                    logging.warning(f"❌ JSON parse error: {str(e)}")
            else:
                logging.warning("❌ No JSON structure found")
            
            # Extract security score
            score_match = re.search(r'Security Score[:\s]+(\d+)', final_message, re.IGNORECASE)
            if score_match:
                security_score = int(score_match.group(1))
            
            # Extract security notes
            notes_section = re.search(
                r'###?\s*Security Notes?:(.*?)(?=###?\s*Security Features?:|###?\s*Score Explanation:|###?\s*Refinement Suggestions?:|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if notes_section:
                notes_text = notes_section.group(1)
                security_notes = [
                    line.strip('- ').strip() 
                    for line in notes_text.split('\n') 
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
            
            # Extract security features
            features_section = re.search(
                r'###?\s*Security Features?:(.*?)(?=###?\s*Security Notes?:|###?\s*Score Explanation:|###?\s*Refinement Suggestions?:|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if features_section:
                features_text = features_section.group(1)
                security_features = [
                    line.strip('- ').strip() 
                    for line in features_text.split('\n') 
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
            
            # Extract score explanation
            score_exp_section = re.search(
                r'###?\s*Score Explanation:(.*?)(?=###?\s*Security Features?:|###?\s*Security Notes?:|###?\s*Refinement Suggestions?:|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if score_exp_section:
                score_explanation = score_exp_section.group(1).strip()
            
            # Extract explanation (Policy Explanation section ONLY)
            exp_match = re.search(
                r'###?\s*Policy Explanation[:\s]*\n(.*?)(?=###?\s*Security Score:|###?\s*Security Features:|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if exp_match:
                explanation = exp_match.group(1).strip()
                explanation = re.sub(r'^.*?(?:I\'ll create|Here\'s|Let me).*?\n', '', explanation, flags=re.IGNORECASE, count=1)
                logging.info(f"✅ Extracted explanation: {len(explanation)} chars")
            else:
                explanation = ""
                logging.warning("❌ No Policy Explanation section found")
            
            # Build conversation history - clean up agent responses
            conversation_history = []
            for msg in conversations[conversation_id]:
                content = msg["content"]

                if msg["role"] == "assistant":
                    has_policy_json = bool(re.search(r'```json[\s\S]*?```', content))
                    
                    if has_policy_json:
                        json_match = re.search(r'(```json[\s\S]*?```)', content)
                        if json_match:
                            content = json_match.group(1)
                    else:
                        content = re.sub(r'```json[\s\S]*?```', '', content)
                        content = re.sub(r'```[\s\S]*?```', '', content)
                        content = re.sub(r'\{[\s\S]*?"Version"[\s\S]*?\}', '', content)
                        
                        policy_exp_start = re.search(r'###?\s*Policy Explanation', content, re.IGNORECASE)
                        if policy_exp_start:
                            content = content[:policy_exp_start.start()]
        
                    content = ' '.join(content.split())
                    content = content.strip()
                    
                    logging.info(f"📝 Conversation msg {msg['role']}: '{content[:100]}...'")
        
                conversation_history.append({  
                    "role": msg["role"],
                    "content": content,
                    "timestamp": msg["timestamp"]
                })

            # Extract refinement suggestions
            refinement_suggestions = []
            suggestions_match = re.search(
                r'###?\s*Refinement Suggestions?[:\s]*\n(.*?)(?=###|##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if suggestions_match:
                suggestions_text = suggestions_match.group(1)
                suggestions = re.findall(r'(?:^|\n)\s*[-•*]\s*(.+?)(?=\n|$)', suggestions_text, re.MULTILINE)
                if not suggestions:
                    suggestions = re.findall(r'(?:^|\n)\s*\d+\.\s*(.+?)(?=\n|$)', suggestions_text, re.MULTILINE)
                refinement_suggestions = [s.strip() for s in suggestions if s.strip() and len(s.strip()) > 10]
                logging.info(f"✅ Extracted {len(refinement_suggestions)} refinement suggestions")
            else:
                logging.warning("❌ No Refinement Suggestions section found")

            if is_question:
                explanation = ""
            
            response = {
                "conversation_id": conversation_id,
                "final_answer": final_message,
                "message_count": len(conversations[conversation_id]),
                "policy": policy,
                "explanation": explanation,
                "security_score": security_score,
                "security_notes": security_notes,
                "security_features": security_features,
                "score_explanation": score_explanation,
                "is_question": is_question,
                "conversation_history": conversation_history,
                "refinement_suggestions": refinement_suggestions
            }
            
            logging.info(f"📤 RESPONSE SUMMARY:")
            logging.info(f"   ├─ is_question: {is_question}")
            logging.info(f"   ├─ has_policy: {policy is not None}")
            logging.info(f"   ├─ security_score: {security_score}")
            logging.info(f"   ├─ security_notes: {len(security_notes)} items")
            logging.info(f"   ├─ security_features: {len(security_features)} items")
            logging.info(f"   ├─ refinement_suggestions: {len(refinement_suggestions)} items")
            logging.info(f"   └─ conversation_history: {len(conversation_history)} messages")
            
            return response
            
    except asyncio.TimeoutError:
        logging.error("Request timed out after 30 seconds")
        return {
            "error": "Request timed out after 30 seconds. Please try again.",
            "conversation_id": str(uuid.uuid4()),
            "message_count": 0
        }
    except Exception as e:
        logging.exception("Error in generate endpoint")
        return {
            "error": str(e),
            "conversation_id": str(uuid.uuid4()),
            "message_count": 0
        }


# ============================================
# VALIDATION (MCP-ENABLED)
# ============================================

@app.post("/validate")
async def validate_policy(request: ValidationRequest):
    """
    Validate an IAM policy for security issues and compliance
    Now with MCP server integration!
    """
    try:
        if not request.policy_json and not request.role_arn:
            return {
                "error": "Either policy_json or role_arn must be provided",
                "success": False
            }
        
        logging.info(f"🔍 Starting validation in {request.mode} mode")
        logging.info(f"   MCP-enabled: True")
        logging.info(f"   Compliance frameworks: {request.compliance_frameworks}")
        
        async with asyncio.timeout(120):  # Longer timeout for audit mode
            result = validator_agent.validate_policy(
                policy_json=request.policy_json,
                role_arn=request.role_arn,
                compliance_frameworks=request.compliance_frameworks,
                mode=request.mode
            )
            
            if not result.get("success"):
                return {
                    "error": result.get("error", "Validation failed"),
                    "success": False
                }
            
            validation_data = result.get("validation", {})
            
            # Extract structured data
            risk_score = validation_data.get("risk_score", 50)
            findings = validation_data.get("findings", [])
            compliance_status = validation_data.get("compliance_status", {})
            recommendations = validation_data.get("security_improvements", [])
            quick_wins = validation_data.get("quick_wins", [])
            
            # Include audit summary if in audit mode
            audit_summary = validation_data.get("audit_summary")
            top_risks = validation_data.get("top_risks")
            
            logging.info(f"✅ Validation completed:")
            logging.info(f"   ├─ Risk Score: {risk_score}/100")
            logging.info(f"   ├─ Findings: {len(findings)}")
            logging.info(f"   ├─ Compliance Checks: {len(compliance_status)}")
            if audit_summary:
                logging.info(f"   └─ Audit Summary: {audit_summary.get('total_roles', 0)} roles analyzed")
            
            return {
                "success": True,
                "risk_score": risk_score,
                "findings": findings,
                "compliance_status": compliance_status,
                "recommendations": recommendations,
                "quick_wins": quick_wins,
                "audit_summary": audit_summary,
                "top_risks": top_risks,
                "raw_response": result.get("raw_response", ""),
                "mcp_enabled": result.get("mcp_enabled", False)
            }
            
    except asyncio.TimeoutError:
        logging.error("⏱️ Validation timed out after 120 seconds")
        return {
            "error": "Validation request timed out. Please try again.",
            "success": False
        }
    except Exception as e:
        logging.exception("❌ Error in validate endpoint")
        return {
            "error": str(e),
            "success": False
        }


# ============================================
# AUTONOMOUS AUDIT (NEW ENDPOINT)
# ============================================

@app.post("/audit")
async def autonomous_audit(request: AuditRequest):
    """
    Perform full autonomous IAM audit of entire AWS account
    Uses MCP servers to scan all roles and policies
    """
    try:
        logging.info("🤖 AUTONOMOUS AUDIT MODE INITIATED")
        logging.info("   This will scan ALL IAM roles in the account")
        
        async with asyncio.timeout(300):  # 5 minute timeout for full audit
            result = validator_agent.validate_policy(
                compliance_frameworks=request.compliance_frameworks,
                mode="audit"
            )
            
            if not result.get("success"):
                return {
                    "error": result.get("error", "Audit failed"),
                    "success": False
                }
            
            validation_data = result.get("validation", {})
            
            return {
                "success": True,
                "audit_summary": validation_data.get("audit_summary", {}),
                "risk_score": validation_data.get("risk_score", 50),
                "top_risks": validation_data.get("top_risks", []),
                "findings": validation_data.get("findings", []),
                "compliance_status": validation_data.get("compliance_status", {}),
                "recommendations": validation_data.get("security_improvements", []),
                "quick_wins": validation_data.get("quick_wins", []),
                "raw_response": result.get("raw_response", ""),
                "mcp_enabled": True
            }
            
    except asyncio.TimeoutError:
        logging.error("⏱️ Audit timed out after 5 minutes")
        return {
            "error": "Audit timed out. Try reducing the scope or contact support.",
            "success": False
        }
    except Exception as e:
        logging.exception("❌ Error in audit endpoint")
        return {
            "error": str(e),
            "success": False
        }


# ============================================
# CONVERSATION MANAGEMENT
# ============================================

@app.get("/conversation/{conversation_id}")
def get_conversation(conversation_id: str):
    if conversation_id not in conversations:
        return {"error": "Conversation not found"}
    return {
        "conversation_id": conversation_id,
        "messages": conversations[conversation_id]
    }

@app.delete("/conversation/{conversation_id}")
def clear_conversation(conversation_id: str):
    if conversation_id in conversations:
        del conversations[conversation_id]
        return {"message": "Conversation cleared"}
    return {"error": "Conversation not found"}