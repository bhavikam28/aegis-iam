from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
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

def extract_score_breakdown(text: str) -> dict:
    """Extract separate score breakdowns for permissions and trust policies"""
    breakdown = {
        "permissions": {"positive": [], "improvements": []},
        "trust": {"positive": [], "improvements": []}
    }
    
    try:
        # Extract Permissions Policy breakdown
        perm_section = re.search(
            r'##\s*Permissions Policy Security Analysis[\s\S]*?✅\s*\*\*Positive:\*\*\s*([\s\S]*?)(?=⚠️|##|$)',
            text, re.DOTALL
        )
        if perm_section:
            pos_text = perm_section.group(1)
            breakdown["permissions"]["positive"] = [
                line.strip('- ').strip()
                for line in pos_text.split('\n')
                if line.strip() and line.strip().startswith('-')
            ]
        
        perm_improve = re.search(
            r'Permissions Policy Security Analysis[\s\S]*?⚠️\s*\*\*Could Improve:\*\*\s*([\s\S]*?)(?=##|$)',
            text, re.DOTALL
        )
        if perm_improve:
            imp_text = perm_improve.group(1)
            breakdown["permissions"]["improvements"] = [
                line.strip('- ').strip()
                for line in imp_text.split('\n')
                if line.strip() and line.strip().startswith('-')
            ]
        
        # Extract Trust Policy breakdown
        trust_section = re.search(
            r'##\s*Trust Policy Security Analysis[\s\S]*?✅\s*\*\*Positive:\*\*\s*([\s\S]*?)(?=⚠️|##|$)',
            text, re.DOTALL
        )
        if trust_section:
            pos_text = trust_section.group(1)
            breakdown["trust"]["positive"] = [
                line.strip('- ').strip()
                for line in pos_text.split('\n')
                if line.strip() and line.strip().startswith('-')
            ]
        
        trust_improve = re.search(
            r'Trust Policy Security Analysis[\s\S]*?⚠️\s*\*\*Could Improve:\*\*\s*([\s\S]*?)(?=##|$)',
            text, re.DOTALL
        )
        if trust_improve:
            imp_text = trust_improve.group(1)
            breakdown["trust"]["improvements"] = [
                line.strip('- ').strip()
                for line in imp_text.split('\n')
                if line.strip() and line.strip().startswith('-')
            ]
            
    except Exception as e:
        logging.error(f"Error extracting score breakdown: {e}")
    
    return breakdown

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
    mode: str = "quick"

class AuditRequest(BaseModel):
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
# POLICY GENERATION
# ============================================

@app.post("/generate")
async def generate(request: GenerationRequest):
    """Generate IAM policy with separate scoring for permissions and trust policies"""
    try:
        logging.info(f"🚀 GENERATE ENDPOINT CALLED")
        logging.info(f"   ├─ Description: {request.description[:100]}...")
        logging.info(f"   ├─ Service: {request.service}")
        logging.info(f"   ├─ Is followup: {request.is_followup}")
        
        conversation_id = request.conversation_id or str(uuid.uuid4())
        logging.info(f"   └─ Conversation ID: {conversation_id}")
        
        if conversation_id not in conversations:
            conversations[conversation_id] = []
        
        # Store user message
        user_message = {
            "role": "user",
            "content": request.description,
            "timestamp": str(uuid.uuid4())
        }
        conversations[conversation_id].append(user_message)
        
        # Check if user specified specific resource names
        has_specific_resources = bool(re.search(r'(bucket|table|function|queue|topic)\s+(?:named|called)?\s*["\']?[\w-]+["\']?', request.description, re.IGNORECASE))
        logging.info(f"🔍 Resource check: has_specific_resources={has_specific_resources}, is_followup={request.is_followup}")

        if has_specific_resources and not request.is_followup:
            logging.info(f"❓ Triggering question response for resource details")
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
            
            logging.info(f"✅ Returning question response to frontend")
            return {
                "conversation_id": conversation_id,
                "final_answer": question_response,
                "message_count": len(conversations[conversation_id]),
                "policy": None,
                "trust_policy": None,
                "explanation": "",
                "trust_explanation": "",
                "permissions_score": 0,
                "trust_score": 0,
                "overall_score": 0,
                "security_notes": {"permissions": [], "trust": []},
                "security_features": {"permissions": [], "trust": []},
                "score_breakdown": {"permissions": {"positive": [], "improvements": []}, "trust": {"positive": [], "improvements": []}},
                "is_question": True,
                "conversation_history": [
                    {"role": "user", "content": request.description, "timestamp": user_message["timestamp"]},
                    {"role": "assistant", "content": question_response, "timestamp": assistant_message["timestamp"]}
                ],
                "refinement_suggestions": {"permissions": [], "trust": []}
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
            trust_policy = None
            explanation = final_message
            trust_explanation = ""
            permissions_score = 0
            trust_score = 0
            overall_score = 0
            security_notes = {"permissions": [], "trust": []}
            security_features = {"permissions": [], "trust": []}
            is_question = True
            
            logging.info(f"📝 Parsing agent response (length: {len(final_message)} chars)")
            
            # Extract Permissions Policy
            permissions_match = re.search(
                r'##\s*(?:🔐\s*)?Permissions\s+Policy[\s\S]*?```json\s*([\s\S]*?)```', 
                final_message, 
                re.IGNORECASE
            )
            if permissions_match:
                try:
                    policy = json.loads(permissions_match.group(1).strip())
                    is_question = False
                    logging.info("✅ Found and parsed Permissions Policy")
                    logging.info(f"   Policy has {len(policy.get('Statement', []))} statements")
                except json.JSONDecodeError as e:
                    logging.warning(f"❌ Permissions Policy JSON parse error: {str(e)}")
            
            # Extract Trust Policy
            trust_match = re.search(
                r'##\s*(?:🤝\s*)?Trust\s+Policy[\s\S]*?```json\s*([\s\S]*?)```', 
                final_message, 
                re.IGNORECASE
            )
            if trust_match:
                try:
                    trust_policy = json.loads(trust_match.group(1).strip())
                    logging.info("✅ Found and parsed Trust Policy")
                    logging.info(f"   Trust policy has {len(trust_policy.get('Statement', []))} statements")
                except json.JSONDecodeError as e:
                    logging.warning(f"❌ Trust Policy JSON parse error: {str(e)}")
            
            # Fallback extraction
            if not policy:
                all_json_blocks = re.findall(r'```json\s*([\s\S]*?)```', final_message, re.IGNORECASE)
                if len(all_json_blocks) >= 1:
                    try:
                        policy = json.loads(all_json_blocks[0].strip())
                        is_question = False
                        logging.info("✅ Extracted Permissions Policy from first JSON block")
                    except json.JSONDecodeError:
                        logging.warning("❌ Failed to parse first JSON block")
                
                if len(all_json_blocks) >= 2 and not trust_policy:
                    try:
                        trust_policy = json.loads(all_json_blocks[1].strip())
                        logging.info("✅ Extracted Trust Policy from second JSON block")
                    except json.JSONDecodeError:
                        logging.warning("❌ Failed to parse second JSON block")
            
            # Extract SEPARATE security scores
            perm_score_match = re.search(r'Permissions Policy Security Score[:\s]+(\d+)', final_message, re.IGNORECASE)
            if perm_score_match:
                permissions_score = int(perm_score_match.group(1))
                logging.info(f"✅ Permissions Score: {permissions_score}")
            
            trust_score_match = re.search(r'Trust Policy Security Score[:\s]+(\d+)', final_message, re.IGNORECASE)
            if trust_score_match:
                trust_score = int(trust_score_match.group(1))
                logging.info(f"✅ Trust Score: {trust_score}")
            
            overall_score_match = re.search(r'Overall Security Score[:\s]+(\d+)', final_message, re.IGNORECASE)
            if overall_score_match:
                overall_score = int(overall_score_match.group(1))
                logging.info(f"✅ Overall Score: {overall_score}")
            
            # Extract SEPARATE security features for permissions policy
            perm_features_section = re.search(
                r'##\s*Permissions Policy Security Features[:\s]*(.*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if perm_features_section:
                features_text = perm_features_section.group(1)
                security_features["permissions"] = [
                    line.replace('- ✅', '').replace('✅', '').replace('-', '').strip()
                    for line in features_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or '✅' in line)
                ]
                logging.info(f"✅ Extracted {len(security_features['permissions'])} permissions features")
            
            # Extract SEPARATE security features for trust policy
            trust_features_section = re.search(
                r'##\s*Trust Policy Security Features[:\s]*(.*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if trust_features_section:
                features_text = trust_features_section.group(1)
                security_features["trust"] = [
                    line.replace('- ✅', '').replace('✅', '').replace('-', '').strip()
                    for line in features_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or '✅' in line)
                ]
                logging.info(f"✅ Extracted {len(security_features['trust'])} trust features")
            
            # Extract SEPARATE security considerations for permissions policy
            perm_notes_section = re.search(
                r'##\s*Permissions Policy Considerations[:\s]*(.*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if perm_notes_section:
                notes_text = perm_notes_section.group(1)
                security_notes["permissions"] = [
                    line.replace('- ⚠️', '').replace('⚠️', '').replace('- ✅', '').replace('✅', '').replace('-', '').strip()
                    for line in notes_text.split('\n')
                    if line.strip() and line.strip().startswith('-')
                ]
                logging.info(f"✅ Extracted {len(security_notes['permissions'])} permissions considerations")
            
            # Extract SEPARATE security considerations for trust policy
            trust_notes_section = re.search(
                r'##\s*Trust Policy Considerations[:\s]*(.*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if trust_notes_section:
                notes_text = trust_notes_section.group(1)
                security_notes["trust"] = [
                    line.replace('- ⚠️', '').replace('⚠️', '').replace('- ✅', '').replace('✅', '').replace('-', '').strip()
                    for line in notes_text.split('\n')
                    if line.strip() and line.strip().startswith('-')
                ]
                logging.info(f"✅ Extracted {len(security_notes['trust'])} trust considerations")
            
            # Extract policy explanations
            perm_exp_match = re.search(
                r'##\s*Permissions Policy Explanation[:\s]*\n(.*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if perm_exp_match:
                explanation = perm_exp_match.group(1).strip()
                logging.info(f"✅ Extracted permissions explanation: {len(explanation)} chars")
            
            trust_exp_match = re.search(
                r'##\s*Trust Policy Explanation[:\s]*\n(.*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if trust_exp_match:
                trust_explanation = trust_exp_match.group(1).strip()
                logging.info(f"✅ Extracted trust explanation: {len(trust_explanation)} chars")
            
            # Extract score breakdown (separate for permissions and trust)
            score_breakdown = extract_score_breakdown(final_message)
            logging.info(f"✅ Extracted score breakdown")
            
            # Extract SEPARATE refinement suggestions
            refinement_suggestions = {"permissions": [], "trust": []}
            
            perm_suggestions_match = re.search(
                r'##\s*Permissions Policy Refinement Suggestions[:\s]*\n(.*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if perm_suggestions_match:
                suggestions_text = perm_suggestions_match.group(1)
                suggestions = re.findall(r'(?:^|\n)\s*[-•*]\s*(.+?)(?=\n|$)', suggestions_text, re.MULTILINE)
                refinement_suggestions["permissions"] = [s.strip() for s in suggestions if s.strip() and len(s.strip()) > 10]
                logging.info(f"✅ Extracted {len(refinement_suggestions['permissions'])} permissions refinement suggestions")
            
            trust_suggestions_match = re.search(
                r'##\s*Trust Policy Refinement Suggestions[:\s]*\n(.*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if trust_suggestions_match:
                suggestions_text = trust_suggestions_match.group(1)
                suggestions = re.findall(r'(?:^|\n)\s*[-•*]\s*(.+?)(?=\n|$)', suggestions_text, re.MULTILINE)
                refinement_suggestions["trust"] = [s.strip() for s in suggestions if s.strip() and len(s.strip()) > 10]
                logging.info(f"✅ Extracted {len(refinement_suggestions['trust'])} trust refinement suggestions")
            
            # Build conversation history
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
                        policy_exp_start = re.search(r'##\s*(?:Permissions |Trust )?Policy', content, re.IGNORECASE)
                        if policy_exp_start:
                            content = content[:policy_exp_start.start()]
                    content = ' '.join(content.split()).strip()
                
                conversation_history.append({  
                    "role": msg["role"],
                    "content": content,
                    "timestamp": msg["timestamp"]
                })
            
            if is_question:
                explanation = ""
                trust_explanation = ""
            
            response = {
                "conversation_id": conversation_id,
                "final_answer": final_message,
                "message_count": len(conversations[conversation_id]),
                "policy": policy,
                "trust_policy": trust_policy,
                "explanation": explanation,
                "trust_explanation": trust_explanation,
                "permissions_score": permissions_score,
                "trust_score": trust_score,
                "overall_score": overall_score,
                "security_notes": security_notes,
                "security_features": security_features,
                "score_breakdown": score_breakdown,
                "is_question": is_question,
                "conversation_history": conversation_history,
                "refinement_suggestions": refinement_suggestions
            }
            
            logging.info(f"📤 RESPONSE SUMMARY:")
            logging.info(f"   ├─ is_question: {is_question}")
            logging.info(f"   ├─ has_policy: {policy is not None}")
            logging.info(f"   ├─ has_trust_policy: {trust_policy is not None}")
            logging.info(f"   ├─ permissions_score: {permissions_score}")
            logging.info(f"   ├─ trust_score: {trust_score}")
            logging.info(f"   ├─ overall_score: {overall_score}")
            logging.info(f"   ├─ permissions_notes: {len(security_notes['permissions'])} items")
            logging.info(f"   ├─ trust_notes: {len(security_notes['trust'])} items")
            logging.info(f"   ├─ permissions_features: {len(security_features['permissions'])} items")
            logging.info(f"   ├─ trust_features: {len(security_features['trust'])} items")
            logging.info(f"   ├─ permissions_suggestions: {len(refinement_suggestions['permissions'])} items")
            logging.info(f"   ├─ trust_suggestions: {len(refinement_suggestions['trust'])} items")
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
    """Validate an IAM policy for security issues and compliance"""
    try:
        if not request.policy_json and not request.role_arn:
            return {
                "error": "Either policy_json or role_arn must be provided",
                "success": False
            }
        
        logging.info(f"🔍 Starting validation in {request.mode} mode")
        
        async with asyncio.timeout(120):
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
            risk_score = validation_data.get("risk_score", 50)
            findings = validation_data.get("findings", [])
            compliance_status = validation_data.get("compliance_status", {})
            recommendations = validation_data.get("security_improvements", [])
            quick_wins = validation_data.get("quick_wins", [])
            audit_summary = validation_data.get("audit_summary")
            top_risks = validation_data.get("top_risks")
            
            logging.info(f"✅ Validation completed:")
            logging.info(f"   ├─ Risk Score: {risk_score}/100")
            logging.info(f"   ├─ Findings: {len(findings)}")
            
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
# AUTONOMOUS AUDIT
# ============================================

@app.post("/audit")
async def autonomous_audit(request: AuditRequest):
    """Perform full autonomous IAM audit of entire AWS account"""
    try:
        logging.info("🤖 AUTONOMOUS AUDIT MODE INITIATED")
        
        async with asyncio.timeout(300):
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


@app.get("/audit/stream")
async def stream_audit(compliance_frameworks: str = "pci_dss,hipaa,sox,gdpr,cis"):
    """Stream autonomous audit progress using Server-Sent Events"""
    frameworks = compliance_frameworks.split(',')
    
    async def event_generator():
        try:
            yield f"data: {json.dumps({'type': 'start', 'message': '🚀 Audit started', 'progress': 5})}\n\n"
            await asyncio.sleep(0.5)
            
            validator = ValidatorAgent()
            result = validator.validate_policy(
                compliance_frameworks=frameworks,
                mode="audit"
            )
            
            if not result.get("success"):
                error_msg = f'❌ Error: {result.get("error")}'
                yield f"data: {json.dumps({'type': 'error', 'message': error_msg, 'progress': 100})}\n\n"
                return
            
            validation_data = result.get("validation", {})
            yield f"data: {json.dumps({'type': 'complete', 'message': '✅ Audit complete!', 'progress': 100, 'result': {'success': True, 'audit_summary': validation_data.get('audit_summary', {}), 'risk_score': validation_data.get('risk_score', 50)}})}\n\n"
            
        except Exception as e:
            logging.exception("❌ Error in streaming audit")
            yield f"data: {json.dumps({'type': 'error', 'message': f'❌ Error: {str(e)}', 'progress': 100})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


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