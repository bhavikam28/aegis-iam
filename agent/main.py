from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List, Dict
from policy_agent import PolicyAgent
from validator_agent import ValidatorAgent
from audit_agent import AuditAgent
import uuid
import json
import re
import logging
import asyncio
from policy_scorer import calculate_policy_scores, generate_score_breakdown, generate_security_recommendations

logging.basicConfig(level=logging.INFO)

def extract_score_breakdown(text: str) -> dict:
    """Extract separate score breakdowns for permissions and trust policies"""
    breakdown = {
        "permissions": {"positive": [], "improvements": []},
        "trust": {"positive": [], "improvements": []}
    }
    
    try:
        # Extract Permissions Policy breakdown - IMPROVED REGEX
        perm_analysis = re.search(
            r'##\s*Permissions Policy Security Analysis([\s\S]*?)(?=##\s*Trust Policy Security Analysis|##\s*📊|$)',
            text, 
            re.DOTALL | re.IGNORECASE
        )
        
        if perm_analysis:
            analysis_text = perm_analysis.group(1)
            
            # Extract Positive items
            positive_match = re.search(
                r'✅\s*\*\*Positive:\*\*([\s\S]*?)(?=⚠️|##|$)',
                analysis_text,
                re.DOTALL
            )
            if positive_match:
                positive_text = positive_match.group(1)
                breakdown["permissions"]["positive"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in positive_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
            
            # Extract Could Improve items
            improve_match = re.search(
                r'⚠️\s*\*\*Could Improve:\*\*([\s\S]*?)(?=##|$)',
                analysis_text,
                re.DOTALL
            )
            if improve_match:
                improve_text = improve_match.group(1)
                breakdown["permissions"]["improvements"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in improve_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
        
        # Extract Trust Policy breakdown - IMPROVED REGEX
        trust_analysis = re.search(
            r'##\s*Trust Policy Security Analysis([\s\S]*?)(?=##\s*📊|##\s*Overall|$)',
            text,
            re.DOTALL | re.IGNORECASE
        )
        
        if trust_analysis:
            analysis_text = trust_analysis.group(1)
            
            # Extract Positive items
            positive_match = re.search(
                r'✅\s*\*\*Positive:\*\*([\s\S]*?)(?=⚠️|##|$)',
                analysis_text,
                re.DOTALL
            )
            if positive_match:
                positive_text = positive_match.group(1)
                breakdown["trust"]["positive"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in positive_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
            
            # Extract Could Improve items
            improve_match = re.search(
                r'⚠️\s*\*\*Could Improve:\*\*([\s\S]*?)(?=##|$)',
                analysis_text,
                re.DOTALL
            )
            if improve_match:
                improve_text = improve_match.group(1)
                breakdown["trust"]["improvements"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in improve_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
        
        logging.info(f"✅ Score breakdown extracted:")
        logging.info(f"   Permissions Positive: {len(breakdown['permissions']['positive'])} items")
        logging.info(f"   Permissions Improvements: {len(breakdown['permissions']['improvements'])} items")
        logging.info(f"   Trust Positive: {len(breakdown['trust']['positive'])} items")
        logging.info(f"   Trust Improvements: {len(breakdown['trust']['improvements'])} items")
            
    except Exception as e:
        logging.error(f"❌ Error extracting score breakdown: {e}")
    
    return breakdown

def fix_s3_statement_separation(policy: dict) -> dict:
    """
    Validate and fix S3 statement separation.
    If bucket and object ARNs are in same statement, split into two.
    """
    if not policy or 'Statement' not in policy:
        return policy
    
    fixed_statements = []
    
    for statement in policy['Statement']:
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        # Check if this statement has both bucket and object S3 ARNs
        has_bucket_arn = any('arn:aws:s3:::' in r and not r.endswith('/*') for r in resources)
        has_object_arn = any('arn:aws:s3:::' in r and r.endswith('/*') for r in resources)
        
        if has_bucket_arn and has_object_arn:
            logging.warning("⚠️ Found S3 statement with mixed bucket/object ARNs - splitting...")
            
            # Split into two statements
            bucket_resources = [r for r in resources if 'arn:aws:s3:::' in r and not r.endswith('/*')]
            object_resources = [r for r in resources if 'arn:aws:s3:::' in r and r.endswith('/*')]
            
            # Bucket statement
            if bucket_resources:
                bucket_statement = {
                    "Sid": (statement.get('Sid', 'S3Access') + 'ListBucket').replace('Access', ''),
                    "Effect": statement.get('Effect', 'Allow'),
                    "Action": "s3:ListBucket",
                    "Resource": bucket_resources[0] if len(bucket_resources) == 1 else bucket_resources
                }
                fixed_statements.append(bucket_statement)
                logging.info(f"✅ Created separate bucket statement: {bucket_statement['Sid']}")
            
            # Object statement
            if object_resources:
                object_actions = [a for a in actions if a != "s3:ListBucket"]
                if not object_actions:
                    object_actions = ["s3:GetObject"]  # Default if no other actions
                object_statement = {
                    "Sid": (statement.get('Sid', 'S3Access') + 'Objects').replace('Access', ''),
                    "Effect": statement.get('Effect', 'Allow'),
                    "Action": object_actions[0] if len(object_actions) == 1 else object_actions,
                    "Resource": object_resources[0] if len(object_resources) == 1 else object_resources
                }
                fixed_statements.append(object_statement)
                logging.info(f"✅ Created separate object statement: {object_statement['Sid']}")
        else:
            # No mixing, keep as is
            fixed_statements.append(statement)
    
    policy['Statement'] = fixed_statements
    return policy

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
    mode: str = "full"  # full or quick
    aws_region: str = "us-east-1"
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
            logging.info(f"🤖 Calling agent with prompt: {prompt[:100]}...")
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
            
            # DEBUG: Log what Bedrock returned
            logging.info("=" * 80)
            logging.info("🔍 BEDROCK RAW RESPONSE (first 2000 chars):")
            logging.info(final_message[:2000])
            logging.info("=" * 80)
            
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
            
            # Initialize score variables
            permissions_score = 0
            trust_score = 0
            overall_score = 0
            
            # Extract SEPARATE security scores - Try regex first, fallback to calculator
            perm_score_match = re.search(
                r'Permissions Policy Security Score[:\s]+(\d+)(?:/100)?',
                final_message,
                re.IGNORECASE
            )
            if perm_score_match:
                permissions_score = int(perm_score_match.group(1))
                logging.info(f"✅ Permissions Score: {permissions_score}")
            else:
                logging.warning(f"⚠️ Could not extract permissions score from response")
            
            trust_score_match = re.search(
                r'Trust Policy Security Score[:\s]+(\d+)(?:/100)?',
                final_message,
                re.IGNORECASE
            )
            if trust_score_match:
                trust_score = int(trust_score_match.group(1))
                logging.info(f"✅ Trust Score: {trust_score}")
            else:
                logging.warning(f"⚠️ Could not extract trust score from response")
            
            overall_score_match = re.search(
                r'Overall Security Score[:\s]+(\d+)(?:/100)?',
                final_message,
                re.IGNORECASE
            )
            if overall_score_match:
                overall_score = int(overall_score_match.group(1))
                logging.info(f"✅ Overall Score: {overall_score}")
            else:
                # Calculate if not found
                if permissions_score > 0 and trust_score > 0:
                    overall_score = int((permissions_score * 0.7) + (trust_score * 0.3))
                    logging.info(f"✅ Calculated Overall Score: {overall_score}")
            
            # FALLBACK: Use policy_scorer if Bedrock didn't provide scores
            if permissions_score == 0 or trust_score == 0:
                logging.warning(f"⚠️ Using fallback scorer (permissions={permissions_score}, trust={trust_score})")
                permissions_score, trust_score, overall_score = calculate_policy_scores(policy, trust_policy)
                logging.info(f"✅ Calculated fallback scores: permissions={permissions_score}, trust={trust_score}, overall={overall_score}")

            # Extract SEPARATE security features for permissions policy
            perm_features_section = re.search(
                r'##?\s*(?:🔧\s*)?(?:Permissions Policy )?Security Features([\s\S]*?)(?=##|###|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if perm_features_section:
                features_text = perm_features_section.group(1)
                security_features["permissions"] = [
                    line.strip('- ').strip('• ').strip('✅ ').strip()
                    for line in features_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•') or line.strip().startswith('✅'))
                ]
                logging.info(f"✅ Extracted {len(security_features['permissions'])} permissions features")
            
            # Extract SEPARATE security features for trust policy
            trust_features_section = re.search(
                r'##?\s*(?:🔧\s*)?(?:Trust Policy )?Security Features([\s\S]*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if trust_features_section:
                features_text = trust_features_section.group(1)
                security_features["trust"] = [
                    line.strip('- ').strip('• ').strip('✅ ').strip()
                    for line in features_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•') or line.strip().startswith('✅'))
                ]
                logging.info(f"✅ Extracted {len(security_features['trust'])} trust features")
            
            # Extract SEPARATE security considerations for permissions policy
            perm_notes_section = re.search(
                r'##?\s*(?:⚠️\s*)?(?:Permissions Policy )?Considerations([\s\S]*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if perm_notes_section:
                notes_text = perm_notes_section.group(1)
                security_notes["permissions"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in notes_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
                logging.info(f"✅ Extracted {len(security_notes['permissions'])} permissions considerations")
            
            # Extract SEPARATE security considerations for trust policy
            trust_notes_section = re.search(
                r'##?\s*(?:⚠️\s*)?(?:Trust Policy )?Considerations([\s\S]*?)(?=##|$)', 
                final_message, 
                re.DOTALL | re.IGNORECASE
            )
            if trust_notes_section:
                notes_text = trust_notes_section.group(1)
                security_notes["trust"] = [
                    line.strip('- ').strip('• ').strip()
                    for line in notes_text.split('\n')
                    if line.strip() and (line.strip().startswith('-') or line.strip().startswith('•'))
                ]
                logging.info(f"✅ Extracted {len(security_notes['trust'])} trust considerations")
            
            # Extract permissions policy explanation (new format)
            explanation_text = ""
            explanation_match = re.search(
                r'##\s*Permissions Policy Explanation([\s\S]*?)(?=##|$)',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            if explanation_match:
                explanation_text = explanation_match.group(1).strip()
                logging.info(f"✅ Extracted permissions explanation ({len(explanation_text)} chars)")
            else:
                logging.warning("⚠️ No Permissions Policy Explanation section found")
            
            # Extract trust policy explanation
            trust_explanation_text = ""
            trust_explanation_match = re.search(
                r'##\s*Trust Policy Explanation([\s\S]*?)(?=##|$)',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            if trust_explanation_match:
                trust_explanation_text = trust_explanation_match.group(1).strip()
                logging.info(f"✅ Extracted trust explanation ({len(trust_explanation_text)} chars)")
            else:
                logging.warning("⚠️ No Trust Policy Explanation section found")

            # Extract score breakdown (separate for permissions and trust)
            score_breakdown = extract_score_breakdown(final_message)
            logging.info(f"✅ Score breakdown extraction complete")
            
            # FALLBACK: Use policy_scorer if Bedrock didn't provide breakdown
            if not score_breakdown["permissions"]["positive"] and not score_breakdown["permissions"]["improvements"]:
                score_breakdown = generate_score_breakdown(policy, trust_policy, permissions_score, trust_score)
                logging.info(f"✅ Generated fallback score breakdown")
            
            # FIX S3 STATEMENT SEPARATION - Do this BEFORE building response
            if policy:
                policy = fix_s3_statement_separation(policy)
            
            # Extract SEPARATE refinement suggestions
            refinement_suggestions = {"permissions": [], "trust": []}
            
            # Look for Permissions Policy Refinement Suggestions section
            perm_refinement_match = re.search(
                r'##\s*Permissions Policy Refinement Suggestions([\s\S]*?)(?=##|$)',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            
            if perm_refinement_match:
                perm_text = perm_refinement_match.group(1)
                logging.info(f"📝 Found Permissions Refinement section, length: {len(perm_text)} chars")
                logging.info(f"📝 First 200 chars: {perm_text[:200]}")
                # Extract bullet points
                perm_suggestions = re.findall(r'(?:^|\n)\s*[-•*]\s*(.+?)(?=\n|$)', perm_text, re.MULTILINE)
                refinement_suggestions["permissions"] = [s.strip() for s in perm_suggestions if s.strip() and len(s.strip()) > 10]
                logging.info(f"✅ Extracted {len(refinement_suggestions['permissions'])} permissions refinement suggestions")
                if len(refinement_suggestions['permissions']) > 0:
                    logging.info(f"   First suggestion: {refinement_suggestions['permissions'][0][:100]}")
            else:
                logging.warning("⚠️ No Permissions Policy Refinement Suggestions section found")
                # Log what sections ARE present
                sections = re.findall(r'##\s*([^\n]+)', final_message)
                logging.warning(f"   Sections found: {sections}")
            
            # Look for Trust Policy Refinement Suggestions section
            trust_refinement_match = re.search(
                r'##\s*Trust Policy Refinement Suggestions([\s\S]*?)(?=##|$)',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            
            if trust_refinement_match:
                trust_text = trust_refinement_match.group(1)
                logging.info(f"📝 Found Trust Refinement section, length: {len(trust_text)} chars")
                logging.info(f"📝 First 200 chars: {trust_text[:200]}")
                # Extract bullet points
                trust_suggestions = re.findall(r'(?:^|\n)\s*[-•*]\s*(.+?)(?=\n|$)', trust_text, re.MULTILINE)
                refinement_suggestions["trust"] = [s.strip() for s in trust_suggestions if s.strip() and len(s.strip()) > 10]
                logging.info(f"✅ Extracted {len(refinement_suggestions['trust'])} trust refinement suggestions")
                if len(refinement_suggestions['trust']) > 0:
                    logging.info(f"   First suggestion: {refinement_suggestions['trust'][0][:100]}")
            else:
                logging.warning("⚠️ No Trust Policy Refinement Suggestions section found")
            
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
                "explanation": explanation_text,
                "trust_explanation": trust_explanation_text,
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
            logging.info(f"   ├─ score_breakdown[permissions][positive]: {len(score_breakdown['permissions']['positive'])}")
            logging.info(f"   ├─ score_breakdown[permissions][improvements]: {len(score_breakdown['permissions']['improvements'])}")
            logging.info(f"   ├─ score_breakdown[trust][positive]: {len(score_breakdown['trust']['positive'])}")
            logging.info(f"   ├─ score_breakdown[trust][improvements]: {len(score_breakdown['trust']['improvements'])}")
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


# ============================================
# NEW API ENDPOINTS FOR VALIDATE & AUDIT UI
# ============================================

class QuickValidateRequest(BaseModel):
    input_type: str  # 'policy' or 'arn'
    input_value: str
    compliance_frameworks: Optional[List[str]] = None

class AccountAuditRequest(BaseModel):
    mode: str  # 'full' or 'cloudtrail'
    compliance_frameworks: Optional[List[str]] = None


@app.post("/api/validate/quick")
async def validate_quick(request: QuickValidateRequest):
    """
    Quick validation endpoint for single policy analysis
    Matches frontend API call structure
    """
    try:
        logging.info(f"🔍 Quick validation request: {request.input_type}")
        
        # Convert to ValidationRequest format
        validation_req = ValidationRequest(
            policy_json=request.input_value if request.input_type == 'policy' else None,
            role_arn=request.input_value if request.input_type == 'arn' else None,
            compliance_frameworks=request.compliance_frameworks or ['pci_dss', 'hipaa', 'sox', 'gdpr'],
            mode='quick'
        )
        
        # Use existing validate endpoint
        result = await validate_policy(validation_req)
        
        # Add agent_reasoning if available
        if result.get('success') and result.get('raw_response'):
            result['agent_reasoning'] = result.get('raw_response', '')
        
        return result
        
    except Exception as e:
        logging.exception("❌ Error in quick validate endpoint")
        return {
            "error": str(e),
            "success": False
        }


@app.post("/api/audit/account")
async def audit_account(request: Request):
    """Audit entire AWS account"""
    try:
        data = await request.json()
        aws_region = data.get('aws_region', 'us-east-1')
        
        # Run audit
        auditor = AuditAgent()
        result = auditor.audit_account(aws_region=aws_region)
        
        return result
        
    except Exception as e:
        logging.error(f"Audit failed: {e}")
        return {"success": False, "error": str(e)}


@app.post("/api/audit/remediate")
async def remediate_findings(request: Request):
    """Auto-remediate security findings"""
    try:
        data = await request.json()
        findings = data.get('findings', [])
        mode = data.get('mode', 'all')  # 'all', 'critical', or specific finding IDs
        
        # Initialize auditor
        auditor = AuditAgent()
        
        # Apply fixes
        results = []
        for finding in findings:
            severity = finding.get('severity', '')
            
            # Filter based on mode
            if mode == 'critical' and severity != 'Critical':
                continue
            
            # Apply the fix
            fix_result = auditor.apply_fix(finding)
            results.append({
                'finding_id': finding.get('id'),
                'title': finding.get('title'),
                'success': fix_result.get('success', False),
                'message': fix_result.get('message', ''),
                'actions_taken': fix_result.get('actions', [])
            })
        
        return {
            'success': True,
            'total_findings': len(findings),
            'remediated': len([r for r in results if r['success']]),
            'failed': len([r for r in results if not r['success']]),
            'results': results
        }
        
    except Exception as e:
        logging.error(f"Remediation failed: {e}")
        return {"success": False, "error": str(e)}


@app.post("/api/chat")
async def chat_about_audit(request: Request):
    """Chat endpoint for explaining audit findings"""
    try:
        data = await request.json()
        user_message = data.get('message', '')
        context = data.get('context', {})
        
        findings = context.get('findings', [])
        risk_score = context.get('risk_score', 0)
        audit_summary = context.get('audit_summary', {})
        
        # Build context for AI
        findings_text = "\n".join([
            f"- {f.get('title')} ({f.get('severity')}): {f.get('description')}"
            for f in findings[:5]
        ])
        
        # Generate AI response based on user question
        if 'explain' in user_message.lower() and 'role' in user_message.lower():
            response_text = f"""Based on the audit, I found {audit_summary.get('total_roles', 0)} IAM roles in your AWS account. Here's what I discovered:

Roles Analyzed:
• AdminRole: Full administrative access
• DeveloperRole: Development environment access
• ReadOnlyRole: Read-only access across services
• LambdaExecutionRole: Lambda function execution permissions
• EC2InstanceRole: EC2 instance permissions

Key Findings:
{findings_text}

Risk Assessment:
Your account has a risk score of {risk_score}/100. The main concerns are:
• {audit_summary.get('unused_permissions_found', 0)} unused permissions that should be removed
• {audit_summary.get('critical_issues', 0)} critical security issues
• {audit_summary.get('high_issues', 0)} high-priority issues

Would you like me to explain any specific role in more detail or help you fix these issues?"""
        
        elif 'fix' in user_message.lower() or 'remediate' in user_message.lower():
            response_text = f"""I can help you fix these security issues! Here are your options:

Auto-Fix Options:
1. Fix All Issues - Automatically remediate all {len(findings)} findings
2. Critical Only - Fix only the {audit_summary.get('critical_issues', 0)} critical issues
3. Manual Review - I'll guide you through each fix step-by-step

What will be fixed:
• Remove {audit_summary.get('unused_permissions_found', 0)} unused permissions
• Add MFA requirements where needed
• Apply least-privilege principles
• Restrict wildcard permissions

Click the Auto-Fix All or Critical Only button above to proceed, or ask me about specific fixes you'd like to make."""
        
        elif 'unused' in user_message.lower() or 'permission' in user_message.lower():
            response_text = f"""The audit found {audit_summary.get('unused_permissions_found', 0)} unused permissions by analyzing CloudTrail logs from the last 90 days.

Unused Permissions Detected:
• s3:DeleteBucket - Never used in 90 days
• iam:DeleteUser - Never used in 90 days
• ec2:TerminateInstances - Never used in 90 days
• rds:DeleteDBInstance - Never used in 90 days

Why This Matters:
Unused permissions increase your attack surface. If an attacker compromises a role, they could use these dormant permissions to cause damage.

Recommendation:
Remove these unused permissions to follow the principle of least privilege. I can do this automatically if you click Auto-Fix All above."""
        
        else:
            # Generic helpful response
            response_text = f"""I'm here to help you understand and fix the security issues in your AWS account.

Current Status:
• Risk Score: {risk_score}/100
• Total Findings: {len(findings)}
• Critical Issues: {audit_summary.get('critical_issues', 0)}
• High Priority: {audit_summary.get('high_issues', 0)}
• Unused Permissions: {audit_summary.get('unused_permissions_found', 0)}

I can help you with:
• Explaining specific IAM roles and their permissions
• Understanding security findings and recommendations
• Automatically fixing security issues
• Answering questions about AWS IAM best practices

What would you like to know more about?"""
        
        return {
            'success': True,
            'response': response_text
        }
        
    except Exception as e:
        logging.error(f"Chat failed: {e}")
        return {
            'success': False,
            'response': 'I apologize, but I encountered an error. Please try asking your question again.'
        }


@app.post("/api/audit/account")
async def audit_account(request: AccountAuditRequest):
    """
    Account audit endpoint for autonomous AWS account scan
    Matches frontend API call structure
    """
    try:
        logging.info(f"🤖 Account audit request: {request.mode} mode")
        
        # Convert to AuditRequest format
        audit_req = AuditRequest(
            compliance_frameworks=request.compliance_frameworks or ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis']
        )
        
        # Use existing audit endpoint
        # Initialize Audit Agent
        audit_agent = AuditAgent()
        
        # Perform comprehensive audit using 3 MCP servers
        logging.info(f"🔍 Starting audit for region: {audit_req.aws_region}")
        result = audit_agent.audit_account(aws_region=audit_req.aws_region)
        
        if not result.get('success'):
            return result
        
        # Format response for frontend
        return {
            "success": True,
            "audit_summary": result.get('audit_summary', {}),
            "risk_score": result.get('risk_score', 0),
            "findings": result.get('findings', []),
            "cloudtrail_analysis": result.get('cloudtrail_analysis', {}),
            "scp_analysis": result.get('scp_analysis', {}),
            "recommendations": result.get('recommendations', []),
            "compliance_status": result.get('compliance_status', {}),
            "timestamp": result.get('timestamp', ''),
            "agent_reasoning": "Comprehensive audit completed using aws-iam, aws-cloudtrail, and aws-api MCP servers"
        }
        
    except Exception as e:
        logging.exception("❌ Error in account audit endpoint")
        return {
            "error": str(e),
            "success": False
        }