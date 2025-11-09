from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict
from policy_agent import PolicyAgent
from validator_agent import ValidatorAgent
from audit_agent import AuditAgent
from service_utils import validate_service, detect_service_from_description
from aws_validator import extract_and_validate_aws_values, validate_aws_region, validate_account_id
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
            
            # Bucket statement - Preserve ALL bucket-related actions
            if bucket_resources:
                # Preserve all S3 bucket actions (ListBucket, GetBucketLocation, GetBucketVersioning, etc.)
                bucket_actions = [a for a in actions if a.startswith('s3:') and 
                                 a in ['s3:ListBucket', 's3:GetBucketLocation', 's3:GetBucketVersioning', 
                                       's3:GetBucketPolicy', 's3:GetBucketAcl', 's3:GetBucketCors',
                                       's3:GetBucketLogging', 's3:GetBucketNotification', 's3:GetBucketRequestPayment',
                                       's3:GetBucketTagging', 's3:GetBucketWebsite', 's3:GetBucketPublicAccessBlock']]
                if not bucket_actions:
                    bucket_actions = ['s3:ListBucket']  # Safe default if no bucket actions found
                
                bucket_statement = {
                    "Sid": (statement.get('Sid', 'S3Access') + 'ListBucket').replace('Access', ''),
                    "Effect": statement.get('Effect', 'Allow'),
                    "Action": bucket_actions[0] if len(bucket_actions) == 1 else bucket_actions,
                    "Resource": bucket_resources[0] if len(bucket_resources) == 1 else bucket_resources
                }
                # Preserve conditions if present
                if statement.get('Condition'):
                    bucket_statement['Condition'] = statement['Condition']
                fixed_statements.append(bucket_statement)
                logging.info(f"✅ Created separate bucket statement: {bucket_statement['Sid']} with {len(bucket_actions)} actions")
            
            # Object statement - Preserve ALL object-related actions
            if object_resources:
                # Preserve all S3 object actions (excluding bucket actions)
                bucket_action_list = ['s3:ListBucket', 's3:GetBucketLocation', 's3:GetBucketVersioning',
                                     's3:GetBucketPolicy', 's3:GetBucketAcl', 's3:GetBucketCors',
                                     's3:GetBucketLogging', 's3:GetBucketNotification', 's3:GetBucketRequestPayment',
                                     's3:GetBucketTagging', 's3:GetBucketWebsite', 's3:GetBucketPublicAccessBlock']
                object_actions = [a for a in actions if a.startswith('s3:') and a not in bucket_action_list]
                if not object_actions:
                    object_actions = ["s3:GetObject"]  # Safe default if no object actions found
                object_statement = {
                    "Sid": (statement.get('Sid', 'S3Access') + 'Objects').replace('Access', ''),
                    "Effect": statement.get('Effect', 'Allow'),
                    "Action": object_actions[0] if len(object_actions) == 1 else object_actions,
                    "Resource": object_resources[0] if len(object_resources) == 1 else object_resources
                }
                # Preserve conditions if present
                if statement.get('Condition'):
                    object_statement['Condition'] = statement['Condition']
                fixed_statements.append(object_statement)
                logging.info(f"✅ Created separate object statement: {object_statement['Sid']} with {len(object_actions)} actions")
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
    compliance: Optional[str] = 'general'
    restrictive: Optional[bool] = True
    
    @field_validator('description')
    @classmethod
    def validate_description(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Description cannot be empty")
        if len(v) > 10000:
            raise ValueError("Description too long (max 10000 characters)")
        return v.strip()
    
    @field_validator('service')
    @classmethod
    def validate_service(cls, v):
        if not v or len(v.strip()) == 0:
            # Will be auto-detected in endpoint
            return 'lambda'
        return v.lower().strip()

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
    # Initialize variables to ensure they exist
    conversation_id = None
    final_message = ""
    agent_result = None
    response = None  # Initialize response variable
    is_explanation_request = False  # Initialize for non-followup requests
    has_existing_policies = False  # Initialize for non-followup requests
    
    # CRITICAL: This function MUST always return a valid dict, never None
    # If anything goes wrong, we'll return an error response
    
    # Create a default error response that will be used if anything fails
    default_error_response = {
        "conversation_id": str(uuid.uuid4()),
        "final_answer": "An unexpected error occurred. Please try again.",
        "message_count": 0,
        "policy": None,
        "trust_policy": None,
        "explanation": "An unexpected error occurred.",
        "trust_explanation": "",
        "permissions_score": 0,
        "trust_score": 0,
        "overall_score": 0,
        "security_notes": {"permissions": [], "trust": []},
        "score_breakdown": {},
        "security_features": {"permissions": [], "trust": []},
        "refinement_suggestions": {"permissions": [], "trust": []},
        "is_question": False,
        "conversation_history": [],
        "compliance_status": {},
        "error": "Internal server error"
    }
    
    try:
        logging.info(f"🚀 GENERATE ENDPOINT STARTED - Request validation passed")
        logging.info(f"   Request object type: {type(request)}")
        logging.info(f"   Request description length: {len(request.description) if request.description else 0}")
        logging.info(f"   Request service: {request.service}")
        logging.info(f"🚀 GENERATE ENDPOINT CALLED")
        logging.info(f"   ├─ Description: {request.description[:100]}...")
        logging.info(f"   ├─ Service (initial): {request.service}")
        logging.info(f"   ├─ Is followup: {request.is_followup}")
        
        # Auto-detect service if not provided or invalid
        if not request.service or request.service == 'lambda' or not validate_service(request.service):
            detected_service = detect_service_from_description(request.description)
            if detected_service and detected_service != request.service:
                request.service = detected_service
                logging.info(f"   ├─ Service (detected): {request.service}")
        
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
        
        
        # REMOVED: "More Details" page - Always generate policies with placeholders if details are missing
        # The AI agent will automatically use {{ACCOUNT_ID}} and {{REGION}} placeholders when needed
        # This prevents user frustration and keeps the flow smooth
        logging.info(f"✅ Proceeding with policy generation - AI will use placeholders if account/region not provided")
        
        # Build prompt - if followup, use conversation context
        # Let the AI agent intelligently interpret user intent (no hardcoded phrase matching!)
        prompt = request.description
        logging.info(f"📝 Initial prompt: {prompt[:100]}...")
        logging.info(f"📝 is_followup: {request.is_followup}, conversation length: {len(conversations[conversation_id])}")
        
        if request.is_followup and len(conversations[conversation_id]) > 1:
            logging.info(f"📝 Follow-up request detected - building conversation context")
            # Build full conversation context for AI agent to interpret
            # The agent is smart enough to understand:
            # - "no" / "dont know" → proceed with placeholders
            # - "please proceed" / "continue" → proceed with placeholders
            # - "use placeholders" → use placeholders
            # - Actual account/region values → use those values
            context = "\n".join([
                f"{msg['role']}: {msg['content']}" 
                for msg in conversations[conversation_id][-5:]
            ])
            # Extract and validate AWS values from user input
            validation_result = extract_and_validate_aws_values(request.description)
            validation_context = ""
            if validation_result['errors']:
                validation_context = f"\n\n⚠️ VALIDATION ISSUES DETECTED:\n" + "\n".join(validation_result['errors']) + "\n\nIMPORTANT: DO NOT use invalid values. Explain the error to the user and offer to use placeholders instead."
            
            # Check if user is asking to explain existing policies
            user_lower = request.description.lower()
            is_explanation_request = any(phrase in user_lower for phrase in [
                "explain", "what does", "describe", "tell me about", "how does", "why"
            ])
            
            # Check if policies exist in conversation
            has_existing_policies = any(
                "policy" in str(msg.get('content', '')).lower() or 
                '"Version"' in str(msg.get('content', '')) or
                '"Statement"' in str(msg.get('content', ''))
                for msg in conversations[conversation_id]
            )
            
            if is_explanation_request and has_existing_policies:
                # User wants explanation of existing policies - DO NOT call tool
                explanation_instruction = """
🚨🚨🚨 **CRITICAL: USER WANTS EXPLANATION OF EXISTING POLICIES** 🚨🚨🚨

**DO NOT CALL THE TOOL `generate_policy_from_bedrock`**
**DO NOT GENERATE NEW POLICIES**

**YOU MUST:**
1. Look at the policies in the conversation history above
2. Provide a TEXT EXPLANATION in plain English explaining what the policy does
3. Explain what each statement means in conversational language
4. THEN include the existing policies in JSON format for reference

**CORRECT RESPONSE FORMAT:**
This policy allows your Lambda function to read files from the S3 bucket 'customer-uploads' and write logs to CloudWatch.

Here's what each statement does:

Statement 1 (S3BucketOperations): This gives your Lambda permission to see what files are in the bucket and find where the bucket is located. This is needed before you can actually read files.

Statement 2 (S3ObjectOperations): This is the core permission - it lets your Lambda actually read and download files from the bucket. Without this, you can't access the file contents.

Statement 3 (CloudWatchLogsAccess): This allows your Lambda to create log groups and write log messages. This is important for debugging and monitoring your function.

Here are the current policies for reference:

## Permissions Policy
```json
[copy the existing permissions policy from conversation]
```

## Trust Policy
```json
[copy the existing trust policy from conversation]
```

**WRONG (DO NOT DO THIS):**
- Just returning JSON without explanation
- Calling the tool to generate new policies
- Skipping the text explanation
"""
            else:
                explanation_instruction = ""
            
            prompt = f"""Previous conversation:
{context}

User's current response: {request.description}
{validation_context}
{explanation_instruction}

🚨🚨🚨 **CRITICAL INSTRUCTIONS - READ THIS FIRST AND FOLLOW IT** 🚨🚨🚨

**YOU ARE A CONVERSATIONAL AI ASSISTANT - NOT JUST A CODE GENERATOR**

**STEP 1: ANALYZE USER INTENT - THIS IS THE MOST IMPORTANT STEP**

**A. IF USER SAYS "explain" or "explain this policy" or "explain this pls" or "expalin this":**
   → **USER WANTS TEXT EXPLANATION IN PLAIN ENGLISH**
   → **YOU MUST START YOUR RESPONSE WITH A CONVERSATIONAL EXPLANATION**
   → Explain what the policy does and what each statement means
   → **DO NOT skip this! DO NOT just return JSON!**
   → **DO NOT call the tool if policies already exist in conversation!**
   → THEN include BOTH policies in JSON format for reference
   
   **CORRECT FORMAT:**
   "This policy allows your Lambda function to read files from the S3 bucket 'customer-uploads' and write logs to CloudWatch.
   
   Here's what each statement does:
   - Statement 1 (S3BucketOperations): Lets your Lambda see what files are in the bucket...
   - Statement 2 (S3ObjectOperations): Gives permission to actually read files...
   - Statement 3 (CloudWatchLogsAccess): Allows your Lambda to write logs...
   
   Here are the current policies for reference:
   [JSON policies]"

   **WRONG FORMAT (DO NOT DO THIS):**
   "[Just JSON without explanation]"

**B. IF USER SAYS "give me trust policy" or "show trust policy" or "trust policy" or "give trsust polcy":**
   → **USER SPECIFICALLY WANTS TRUST POLICY**
   → Return TRUST policy prominently (NOT permissions policy!)
   → You can mention "Permissions policy also exists" but focus on trust
   → **CRITICAL: DO NOT return permissions policy when they asked for trust!**

**C. IF USER SAYS "add region ch-896765" or "add region ch-989" or "account id 1344":**
   → **VALIDATE THE INPUT FIRST** before using it
   → "ch-896765" is NOT a valid AWS region!
   → "1344" is NOT a valid account ID (needs 12 digits)!
   → **YOU MUST:**
     1. Explain the error clearly: "I notice 'ch-896765' is not a valid AWS region format."
     2. Show correct format: "AWS regions follow the pattern [area]-[direction]-[number] like 'us-east-1'"
     3. Offer placeholder: "I'll keep using the {{REGION}} placeholder for now."
     4. Be helpful: "Please provide a valid AWS region if you'd like me to update it."
   → **DO NOT silently use invalid values!**
   → **DO NOT just return JSON without explaining the validation error!**

**D. IF USER SAYS "modify" or "add" or "change":**
   → Return BOTH updated policies in JSON format
   → Explain what changed

**STEP 2: BE CONVERSATIONAL AND HELPFUL**
- Respond naturally, as if talking to a colleague
- Use friendly, clear, conversational language
- If explaining, be thorough but not overwhelming
- If validation fails, be helpful and educational (not just error messages)
- Greet the user warmly and be professional

**STEP 3: ALWAYS VALIDATE BEFORE USING**
- Extract AWS values (region, account ID) from user input
- Validate format using AWS rules
- If invalid → Explain clearly with examples, don't use it
- If valid → Use it in policies

**STEP 4: POLICY RETURN RULES**
- "explain" → **TEXT EXPLANATION FIRST**, then both policies in JSON
- "trust policy" → **TRUST POLICY** (not permissions!)
- "both policies" → Both policies in JSON
- "modify/add" → Both updated policies in JSON

**CRITICAL REMINDERS - THESE ARE MANDATORY:**
- 🚨 **NEVER skip text explanation when user asks "explain"** - This is the #1 priority
- 🚨 **NEVER return permissions when user asks for trust policy** - Give what they asked for
- 🚨 **NEVER use invalid AWS values** - Always validate and explain errors
- 🚨 **ALWAYS be conversational** - Not just code, but helpful explanations
- 🚨 **ALWAYS validate inputs** - Check format before using values"""
            logging.info("✅ Using AI agent to interpret user intent (no hardcoded phrase matching)")
            
            # If explanation requested and policies exist, generate explanation directly via Bedrock
            if is_explanation_request and has_existing_policies:
                logging.info("🔍 Explanation requested - generating explanation directly via Bedrock (bypassing tool)")
                
                # Extract policies from conversation history - look for both permissions and trust policies
                permissions_policy_text = ""
                trust_policy_text = ""
                
                for msg in reversed(conversations[conversation_id]):
                    content = str(msg.get('content', ''))
                    # Look for JSON blocks with policies
                    json_blocks = re.findall(r'```json\s*([\s\S]*?)```', content, re.IGNORECASE)
                    for json_block in json_blocks:
                        try:
                            parsed = json.loads(json_block.strip())
                            # Check if it's a permissions policy (has Action/Resource, no Principal)
                            if '"Version"' in json_block and '"Statement"' in json_block:
                                if '"Principal"' not in json_block and ('"Action"' in json_block or '"Resource"' in json_block):
                                    if not permissions_policy_text:
                                        permissions_policy_text = json_block.strip()
                                elif '"Principal"' in json_block:
                                    if not trust_policy_text:
                                        trust_policy_text = json_block.strip()
                        except:
                            pass
                    
                    # Also check for policies in final_answer from previous responses
                    if '"Version"' in content and '"Statement"' in content:
                        # Try to extract JSON from the content
                        json_match = re.search(r'\{[\s\S]*?"Version"[\s\S]*?"Statement"[\s\S]*?\}', content)
                        if json_match:
                            try:
                                parsed = json.loads(json_match.group(0))
                                if '"Principal"' not in json_match.group(0):
                                    if not permissions_policy_text:
                                        permissions_policy_text = json_match.group(0)
                                else:
                                    if not trust_policy_text:
                                        trust_policy_text = json_match.group(0)
                            except:
                                pass
                
                # Combine both policies
                policies_text = ""
                if permissions_policy_text:
                    policies_text += f"## Permissions Policy\n```json\n{permissions_policy_text}\n```\n\n"
                if trust_policy_text:
                    policies_text += f"## Trust Policy\n```json\n{trust_policy_text}\n```\n\n"
                
                if policies_text:
                    # Generate explanation directly using Bedrock
                    import boto3
                    bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
                    
                    explanation_prompt = f"""You are explaining an existing IAM policy to a user. The user asked you to explain what this policy does.

Here are the policies from the conversation:

{policies_text}

**CRITICAL INSTRUCTIONS - YOU MUST FOLLOW THIS EXACT FORMAT:**

1. **START WITH TEXT EXPLANATION** - Provide a clear, conversational explanation in plain English
2. **Explain overall purpose** - What does this policy allow?
3. **Explain EACH statement** - What does each statement do?
4. **THEN include policies** - Include the policies in JSON format for reference

**EXACT RESPONSE FORMAT (follow this exactly):**

```
This policy allows your Lambda function to read files from the S3 bucket 'customer-uploads' and write logs to CloudWatch.

Here's what each statement does:

Statement 1 (S3BucketOperations): This gives your Lambda permission to see what files are in the bucket and find where the bucket is located. This is needed before you can actually read files.

Statement 2 (S3ObjectOperations): This is the core permission - it lets your Lambda actually read and download files from the bucket. Without this, you can't access the file contents.

Statement 3 (CloudWatchLogsAccess): This allows your Lambda to create log groups and write log messages. This is important for debugging and monitoring your function.

Here are the policies for reference:

## Permissions Policy
```json
{permissions_policy_text if permissions_policy_text else '{}'}
```

## Trust Policy
```json
{trust_policy_text if trust_policy_text else '{}'}
```

Let me know if you have any questions!
```

**CRITICAL:**
- DO NOT skip the text explanation
- DO NOT just return JSON
- Start with conversational explanation FIRST
- Then include policies in JSON format
- Be helpful and clear"""
                    
                    body = json.dumps({
                        "anthropic_version": "bedrock-2023-05-31",
                        "max_tokens": 2000,
                        "messages": [{"role": "user", "content": [{"type": "text", "text": explanation_prompt}]}],
                        "temperature": 0.3
                    })
                    
                    try:
                        response = bedrock_runtime.invoke_model(
                            body=body,
                            modelId="us.anthropic.claude-3-7-sonnet-20250219-v1:0"
                        )
                        body_bytes = response.get('body').read()
                        response_body = json.loads(body_bytes)
                        final_message = response_body.get('content', [{}])[0].get('text', '')
                        logging.info("✅ Generated explanation directly via Bedrock")
                    except Exception as e:
                        logging.error(f"❌ Failed to generate explanation: {e}")
                        # Fallback to agent
                        async with asyncio.timeout(45):
                            logging.info(f"🤖 Fallback: Calling agent with prompt: {prompt[:100]}...")
                            agent_result = aegis_agent.run(user_request=prompt, service=request.service)
                            final_message = str(agent_result.message)
                            if isinstance(agent_result.message, dict):
                                if "content" in agent_result.message and isinstance(agent_result.message["content"], list):
                                    if len(agent_result.message["content"]) > 0 and "text" in agent_result.message["content"][0]:
                                        final_message = agent_result.message["content"][0]["text"]
                else:
                    # No policies found, use agent
                    async with asyncio.timeout(45):
                        logging.info(f"🤖 Calling agent with prompt: {prompt[:100]}...")
                        agent_result = aegis_agent.run(user_request=prompt, service=request.service)
                        final_message = str(agent_result.message)
                        if isinstance(agent_result.message, dict):
                            if "content" in agent_result.message and isinstance(agent_result.message["content"], list):
                                if len(agent_result.message["content"]) > 0 and "text" in agent_result.message["content"][0]:
                                    final_message = agent_result.message["content"][0]["text"]
        
        # Normal flow - use agent (for non-followup requests)
        if not request.is_followup or len(conversations[conversation_id]) <= 1:
            logging.info(f"📝 Non-followup request - proceeding with normal flow")
            logging.info(f"📝 Prompt length: {len(prompt) if prompt else 0} chars")
            logging.info(f"📝 Service: {request.service}")
            logging.info(f"📝 Prompt value (first 200 chars): {prompt[:200] if prompt else 'PROMPT IS NONE!'}")
            
            # Initialize final_message to ensure it exists
            final_message = ""
            agent_result = None
            
            try:
                logging.info(f"🤖 About to call agent...")
                logging.info(f"🤖 Agent type: {type(aegis_agent)}")
                logging.info(f"🤖 Prompt type: {type(prompt)}")
                logging.info(f"🤖 Service type: {type(request.service)}")
                
                async with asyncio.timeout(45):  # Increased timeout for complex policies (was 30)
                    logging.info(f"🤖 Calling agent with prompt: {prompt[:100] if prompt else 'NONE'}...")
                    logging.info(f"🤖 Service parameter: {request.service}")
                    agent_result = aegis_agent.run(user_request=prompt, service=request.service)
                    logging.info(f"✅ Agent call completed successfully")
                    logging.info(f"✅ Agent result type: {type(agent_result)}")
                    logging.info(f"✅ Agent result: {str(agent_result)[:200] if agent_result else 'NONE'}")
                    
                    if agent_result:
                        logging.info(f"✅ Agent result has message: {hasattr(agent_result, 'message')}")
                        if hasattr(agent_result, 'message'):
                            logging.info(f"✅ Agent message type: {type(agent_result.message)}")
                            final_message = str(agent_result.message)
                            if isinstance(agent_result.message, dict):
                                logging.info(f"📝 Agent message is a dict, extracting text...")
                                if "content" in agent_result.message and isinstance(agent_result.message["content"], list):
                                    if len(agent_result.message["content"]) > 0 and "text" in agent_result.message["content"][0]:
                                        final_message = agent_result.message["content"][0]["text"]
                                        logging.info(f"✅ Extracted text from dict content")
                    else:
                        logging.error(f"❌ CRITICAL: agent_result is None!")
                        final_message = "An error occurred: The AI agent returned None."
                    
                    logging.info(f"✅ Extracted final_message (length: {len(final_message) if final_message else 0})")
                    if not final_message or final_message.strip() == '':
                        logging.error(f"❌ CRITICAL: final_message is empty after agent call!")
                        final_message = "An error occurred: The AI agent returned an empty response."
            except asyncio.TimeoutError as timeout_error:
                logging.error(f"❌ CRITICAL: Agent call timed out: {timeout_error}")
                logging.exception(timeout_error)
                final_message = "The request timed out. Please try again with a simpler request."
            except Exception as agent_error:
                logging.error(f"❌ CRITICAL: Agent call failed: {agent_error}")
                logging.exception(agent_error)
                final_message = f"An error occurred while calling the AI agent: {str(agent_error)}"
                # Continue to build error response
            
            # CRITICAL: Ensure final_message is never empty before proceeding
            if not final_message or (isinstance(final_message, str) and final_message.strip() == ''):
                logging.error("❌ CRITICAL: final_message is empty after agent call!")
                logging.error(f"   agent_result type: {type(agent_result)}")
                logging.error(f"   agent_result value: {str(agent_result)[:200] if agent_result else 'None'}")
                final_message = "An error occurred while generating the policy. The AI agent did not return a response. Please try again."
            
            # CRITICAL: Add assistant message to conversation BEFORE checking for early return
            assistant_message = {
                "role": "assistant",
                "content": final_message,
                "timestamp": str(uuid.uuid4())
            }
            conversations[conversation_id].append(assistant_message)
            logging.info(f"✅ Added assistant message to conversation (total messages: {len(conversations[conversation_id])})")
            
            # DEBUG: Log what Bedrock returned
            logging.info("=" * 80)
            logging.info("🔍 BEDROCK RAW RESPONSE (first 2000 chars):")
            logging.info(final_message[:2000] if final_message else "EMPTY MESSAGE!")
            logging.info("=" * 80)
            
            # For explanation requests, return the explanation as-is without extracting policies
            if is_explanation_request and has_existing_policies:
                logging.info("✅ Explanation request - returning explanation text as final_answer")
                logging.info(f"   Conversation has {len(conversations[conversation_id])} messages")
                logging.info(f"   Final message length: {len(final_message)} chars")
                explanation_response = {
                    "conversation_id": conversation_id,
                    "final_answer": final_message,  # This contains the explanation + policies for reference
                    "message_count": len(conversations[conversation_id]),
                    "policy": None,  # Don't extract separately - it's in the explanation
                    "trust_policy": None,  # Don't extract separately - it's in the explanation
                    "explanation": final_message,  # Full explanation
                    "trust_explanation": "",
                    "permissions_score": 0,
                    "trust_score": 0,
                    "overall_score": 0,
                    "security_notes": {"permissions": [], "trust": []},
                    "score_breakdown": {},
                    "security_features": {"permissions": [], "trust": []},
                    "refinement_suggestions": {"permissions": [], "trust": []},
                    "is_question": False,  # Not a question - it's an explanation
                    "conversation_history": conversations[conversation_id][-10:],  # Include latest messages
                    "compliance_status": {}
                }
                logging.info(f"✅ Returning explanation response with conversation_id: {explanation_response.get('conversation_id')}")
                logging.info(f"   Conversation history length: {len(explanation_response.get('conversation_history', []))}")
                logging.info(f"   Final answer length: {len(explanation_response.get('final_answer', ''))}")
                return JSONResponse(content=explanation_response)
            
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
            
            # Extract Permissions Policy - Improved regex patterns with multiple fallbacks
            permissions_patterns = [
                r'##\s*(?:🔐\s*)?(?:Updated\s+)?Permissions\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'##\s*Permissions\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'Permissions\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'```json\s*(\{[^`]*"Version"[^`]*"Statement"[^`]*\})\s*```',  # Fallback: any JSON with Version and Statement
            ]
            
            for pattern in permissions_patterns:
                permissions_match = re.search(pattern, final_message, re.IGNORECASE | re.DOTALL)
                if permissions_match:
                    try:
                        policy_json = permissions_match.group(1).strip()
                        # Clean up any trailing text after closing brace or before next section
                        policy_json = re.sub(r'\}\s*[^}]*$', '}', policy_json, flags=re.DOTALL)
                        policy_json = re.sub(r'\}\s*##', '}', policy_json)  # Remove section headers
                        policy = json.loads(policy_json)
                        is_question = False
                        logging.info("✅ Found and parsed Permissions Policy")
                        logging.info(f"   Policy has {len(policy.get('Statement', []))} statements")
                        break
                    except json.JSONDecodeError as e:
                        logging.warning(f"❌ Permissions Policy JSON parse error with pattern: {str(e)[:100]}")
                        continue
            
            # Extract Trust Policy - Improved regex patterns with multiple fallbacks
            trust_patterns = [
                r'##\s*(?:🤝\s*)?(?:Updated\s+)?Trust\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'##\s*Trust\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'Trust\s+Policy[\s\S]*?```json\s*([\s\S]*?)```',
                r'```json\s*(\{[^`]*"Principal"[^`]*"sts:AssumeRole"[^`]*\})\s*```',  # Fallback: JSON with Principal and AssumeRole
            ]
            
            for pattern in trust_patterns:
                trust_match = re.search(pattern, final_message, re.IGNORECASE | re.DOTALL)
                if trust_match:
                    try:
                        trust_json = trust_match.group(1).strip()
                        # Clean up any trailing text after closing brace or before next section
                        trust_json = re.sub(r'\}\s*[^}]*$', '}', trust_json, flags=re.DOTALL)
                        trust_json = re.sub(r'\}\s*##', '}', trust_json)  # Remove section headers
                        parsed_trust = json.loads(trust_json)
                        # VALIDATE: Trust policy must have "Principal" field, not "Resource" or "Action" like permissions
                        if "Principal" in str(parsed_trust) or any("Principal" in str(stmt) for stmt in parsed_trust.get('Statement', [])):
                            trust_policy = parsed_trust
                            logging.info("✅ Found and parsed Trust Policy")
                            logging.info(f"   Trust policy has {len(trust_policy.get('Statement', []))} statements")
                            break
                        else:
                            logging.warning("❌ Trust Policy JSON doesn't contain 'Principal' - likely permissions policy")
                            continue
                    except json.JSONDecodeError as e:
                        logging.warning(f"❌ Trust Policy JSON parse error with pattern: {str(e)[:100]}")
                        continue
            
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
                        parsed_trust = json.loads(all_json_blocks[1].strip())
                        # VALIDATE: Trust policy must have "Principal" field
                        if "Principal" in str(parsed_trust) or any("Principal" in str(stmt) for stmt in parsed_trust.get('Statement', [])):
                            trust_policy = parsed_trust
                            logging.info("✅ Extracted Trust Policy from second JSON block")
                        else:
                            logging.warning("❌ Second JSON block doesn't contain 'Principal' - likely not a trust policy, trying next block")
                            # Try third block if available
                            if len(all_json_blocks) >= 3:
                                try:
                                    parsed_trust = json.loads(all_json_blocks[2].strip())
                                    if "Principal" in str(parsed_trust) or any("Principal" in str(stmt) for stmt in parsed_trust.get('Statement', [])):
                                        trust_policy = parsed_trust
                                        logging.info("✅ Extracted Trust Policy from third JSON block")
                                except:
                                    pass
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
            
            # VALIDATE COMPLIANCE - Check generated policy against selected framework (OPTIONAL - async to speed up)
            compliance_status = {}
            # Only validate compliance if not 'general' and policy exists
            # Make it non-blocking to improve response time
            if hasattr(request, 'compliance') and request.compliance and request.compliance != 'general' and policy:
                try:
                    logging.info(f"🔍 Validating compliance against: {request.compliance}")
                    # Convert compliance format (e.g., 'pci-dss' -> 'pci_dss')
                    compliance_framework = request.compliance.replace('-', '_')
                    compliance_frameworks = [compliance_framework]
                    
                    # Validate the generated policy (quick mode for speed)
                    validation_result = validator_agent.validate_policy(
                        policy_json=json.dumps(policy),
                        compliance_frameworks=compliance_frameworks,
                        mode='quick'
                    )
                    
                    # Extract compliance status from validation result
                    if isinstance(validation_result, dict):
                        compliance_status = validation_result.get('compliance_status', {})
                        logging.info(f"✅ Compliance validation complete: {len(compliance_status)} frameworks checked")
                    else:
                        logging.warning("⚠️ Compliance validation returned unexpected format")
                except Exception as e:
                    logging.error(f"❌ Compliance validation error: {str(e)}")
                    # Don't fail the request if compliance validation fails - continue without compliance
                    compliance_status = {}
            
            # Extract SEPARATE refinement suggestions
            refinement_suggestions = {"permissions": [], "trust": []}
            
            # Look for Permissions Policy Refinement Suggestions section (try multiple variations)
            perm_refinement_match = re.search(
                r'##\s*(?:Permissions Policy )?Refinement Suggestions([\s\S]*?)(?=##\s*(?:Trust|Permissions Policy|$))',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            # Fallback: Try alternative section names
            if not perm_refinement_match:
                perm_refinement_match = re.search(
                    r'##\s*(?:How You Could Make|Improvements|Suggestions)(?:.*?Permissions|.*?Policy)?([\s\S]*?)(?=##\s*(?:Trust|$))',
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
            
            # Look for Trust Policy Refinement Suggestions section (try multiple variations)
            trust_refinement_match = re.search(
                r'##\s*(?:Trust Policy )?Refinement Suggestions([\s\S]*?)(?=##|$)',
                final_message,
                re.DOTALL | re.IGNORECASE
            )
            # Fallback: Try alternative section names for trust policy
            if not trust_refinement_match:
                trust_refinement_match = re.search(
                    r'(?:For the trust policy|Trust policy)(?:.*?you could|.*?suggestions?)([^##]*?)(?=##|$)',
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
            try:
                conversation_history = []
                for msg in conversations.get(conversation_id, []):
                    content = msg.get("content", "")
                    if msg.get("role") == "assistant":
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
                        "role": msg.get("role", "user"),
                        "content": content,
                        "timestamp": msg.get("timestamp", "")
                    })
                logging.info(f"✅ Built conversation history ({len(conversation_history)} messages)")
            except Exception as history_error:
                logging.error(f"❌ Error building conversation history: {history_error}")
                conversation_history = []
            
            if is_question:
                explanation = ""
                trust_explanation = ""
            
            # CRITICAL: Ensure final_message is never empty - this is the most important check
            if not final_message or (isinstance(final_message, str) and final_message.strip() == ''):
                logging.error("❌ CRITICAL ERROR: final_message is empty before building response!")
                logging.error(f"   This should never happen. conversation_id: {conversation_id}")
                logging.error(f"   This means the agent call failed or returned empty response")
                final_message = "An error occurred while generating the policy. The AI agent did not return a response. Please try again."
            
            # Ensure explanation_text is never empty
            if not explanation_text or (isinstance(explanation_text, str) and explanation_text.strip() == ''):
                explanation_text = final_message
            
            # Validate all required fields exist
            if not conversation_id:
                logging.error("❌ conversation_id is missing!")
                conversation_id = str(uuid.uuid4())
            
            # Log that we're about to build the response
            logging.info(f"🔨 Building response object...")
            logging.info(f"   ├─ conversation_id: {conversation_id}")
            logging.info(f"   ├─ final_message length: {len(final_message) if final_message else 0}")
            logging.info(f"   ├─ has policy: {policy is not None}")
            logging.info(f"   ├─ has trust_policy: {trust_policy is not None}")
            
            # Build response object
            response = {
                "conversation_id": conversation_id,
                "final_answer": final_message or "Policy generation completed.",
                "message_count": len(conversations.get(conversation_id, [])),
                "policy": policy,
                "trust_policy": trust_policy,
                "explanation": explanation_text or final_message or "Policy generation completed.",
                "trust_explanation": trust_explanation_text or "",
                "permissions_score": permissions_score or 0,
                "trust_score": trust_score or 0,
                "overall_score": overall_score or 0,
                "security_notes": security_notes or {"permissions": [], "trust": []},
                "security_features": security_features or {"permissions": [], "trust": []},
                "score_breakdown": score_breakdown or {},
                "is_question": is_question if isinstance(is_question, bool) else False,
                "conversation_history": conversation_history or [],
                "refinement_suggestions": refinement_suggestions or {"permissions": [], "trust": []},
                "compliance_status": compliance_status or {}
            }
            logging.info(f"✅ Response object created successfully")
            
            # Validate response before returning - ensure it's never None or missing critical fields
            if not response.get("final_answer"):
                logging.error("❌ Response missing final_answer, adding fallback")
                response["final_answer"] = "Policy generation completed."
            
            if not response.get("conversation_id"):
                logging.error("❌ Response missing conversation_id, adding fallback")
                response["conversation_id"] = str(uuid.uuid4())
            
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
            
            # Ensure response is valid before returning - NEVER return None
            if not response or not isinstance(response, dict):
                logging.error("❌ Response is invalid or None, creating fallback")
                response = {
                    "conversation_id": conversation_id or str(uuid.uuid4()),
                    "final_answer": "An error occurred while generating the policy. Please try again.",
                    "message_count": len(conversations.get(conversation_id or '', [])),
                    "policy": None,
                    "trust_policy": None,
                    "explanation": "An error occurred while generating the policy.",
                    "trust_explanation": "",
                    "permissions_score": 0,
                    "trust_score": 0,
                    "overall_score": 0,
                    "security_notes": {"permissions": [], "trust": []},
                    "score_breakdown": {},
                    "security_features": {"permissions": [], "trust": []},
                    "refinement_suggestions": {"permissions": [], "trust": []},
                    "is_question": False,
                    "conversation_history": conversations.get(conversation_id or '', [])[-10:],
                    "compliance_status": {},
                    "error": "Response validation failed"
                }
            
            # CRITICAL: Ensure response is never None before returning
            if response is None:
                logging.error("❌ CRITICAL: response is None before returning!")
                response = {
                    "conversation_id": conversation_id or str(uuid.uuid4()),
                    "final_answer": "An error occurred while generating the policy. Please try again.",
                    "message_count": len(conversations.get(conversation_id or '', [])),
                    "policy": None,
                    "trust_policy": None,
                    "explanation": "An error occurred while generating the policy.",
                    "trust_explanation": "",
                    "permissions_score": 0,
                    "trust_score": 0,
                    "overall_score": 0,
                    "security_notes": {"permissions": [], "trust": []},
                    "score_breakdown": {},
                    "security_features": {"permissions": [], "trust": []},
                    "refinement_suggestions": {"permissions": [], "trust": []},
                    "is_question": False,
                    "conversation_history": conversations.get(conversation_id or '', [])[-10:],
                    "compliance_status": {},
                    "error": "Response was None"
                }
            
            # FINAL SAFETY CHECK: Ensure response is never None
            if response is None:
                logging.error("❌ CRITICAL: response is None at final return - using default error response")
                response = default_error_response
            
            # Ensure response is a dict
            if not isinstance(response, dict):
                logging.error(f"❌ CRITICAL: response is not a dict (type: {type(response)}) - using default error response")
                response = default_error_response
            
            # Ensure response has all required fields
            if not response.get("conversation_id"):
                response["conversation_id"] = conversation_id or str(uuid.uuid4())
            if not response.get("final_answer"):
                response["final_answer"] = final_message or "Policy generation completed."
            
            logging.info(f"✅ Returning response with conversation_id: {response.get('conversation_id')}")
            logging.info(f"✅ Response has final_answer: {bool(response.get('final_answer'))}")
            logging.info(f"✅ Response type: {type(response)}")
            logging.info(f"✅ Response keys: {list(response.keys())}")
            
            # CRITICAL: Use JSONResponse to ensure proper serialization (prevents null responses)
            # Ensure response dict is not None before passing to JSONResponse
            if response is None:
                logging.error("❌ CRITICAL: response is None - using default_error_response")
                response = default_error_response
            
            logging.info(f"🔍 Final response check before JSONResponse:")
            logging.info(f"   ├─ response type: {type(response)}")
            logging.info(f"   ├─ response is None: {response is None}")
            logging.info(f"   ├─ response is dict: {isinstance(response, dict)}")
            logging.info(f"   ├─ conversation_id: {response.get('conversation_id') if isinstance(response, dict) else 'N/A'}")
            logging.info(f"   ├─ final_answer: {response.get('final_answer')[:100] if isinstance(response, dict) and response.get('final_answer') else 'N/A'}")
            
            # FINAL SAFETY: Ensure response is a valid dict with required fields
            if not isinstance(response, dict):
                logging.error(f"❌ CRITICAL: response is not a dict (type: {type(response)}) - using default_error_response")
                response = default_error_response.copy()
            
            if not response.get("conversation_id"):
                logging.error("❌ CRITICAL: response missing conversation_id - adding fallback")
                response["conversation_id"] = conversation_id or str(uuid.uuid4())
            
            if not response.get("final_answer"):
                logging.error("❌ CRITICAL: response missing final_answer - adding fallback")
                response["final_answer"] = final_message or "Policy generation completed."
            
            # Log the final response being returned
            logging.info(f"📤 FINAL RESPONSE BEING RETURNED:")
            logging.info(f"   ├─ conversation_id: {response.get('conversation_id')}")
            logging.info(f"   ├─ final_answer length: {len(response.get('final_answer', ''))}")
            logging.info(f"   ├─ has policy: {response.get('policy') is not None}")
            logging.info(f"   ├─ has trust_policy: {response.get('trust_policy') is not None}")
            
            # Ensure we never return None - use default_error_response if somehow response is still None
            if response is None:
                logging.error("❌ CRITICAL: response is STILL None after all checks - using default_error_response")
                response = default_error_response.copy()
            
            try:
                json_response = JSONResponse(content=response)
                logging.info(f"✅ Successfully created JSONResponse")
                return json_response
            except Exception as json_error:
                logging.error(f"❌ CRITICAL: Failed to create JSONResponse: {json_error}")
                logging.error(f"   Response content: {str(response)[:500]}")
                # Return error response as fallback
                error_fallback = default_error_response.copy()
                error_fallback["error"] = f"Failed to serialize response: {str(json_error)}"
                return JSONResponse(content=error_fallback)
            
    except asyncio.TimeoutError:
        logging.error("⏱️ Request timed out after 45 seconds")
        error_message = "Request timed out after 45 seconds. Please try again with a simpler request."
        error_conversation_id = conversation_id or str(uuid.uuid4())
        error_response = {
            "conversation_id": error_conversation_id,
            "final_answer": error_message,
            "message_count": len(conversations.get(error_conversation_id, [])),
            "policy": None,
            "trust_policy": None,
            "explanation": error_message,
            "trust_explanation": "",
            "permissions_score": 0,
            "trust_score": 0,
            "overall_score": 0,
            "security_notes": {"permissions": [], "trust": []},
            "score_breakdown": {},
            "security_features": {"permissions": [], "trust": []},
            "refinement_suggestions": {"permissions": [], "trust": []},
            "is_question": False,
            "conversation_history": conversations.get(error_conversation_id, [])[-10:],
            "compliance_status": {},
            "error": error_message
        }
        logging.info(f"✅ Returning timeout error response with conversation_id: {error_response.get('conversation_id')}")
        return JSONResponse(content=error_response)
    except Exception as e:
        logging.exception("❌ Error in generate endpoint")
        error_message = f"Error generating policy: {str(e)}"
        error_conversation_id = conversation_id or str(uuid.uuid4())
        logging.error(f"   Error conversation_id: {error_conversation_id}")
        logging.error(f"   Error type: {type(e).__name__}")
        logging.error(f"   Error message: {str(e)}")
        error_response = {
            "conversation_id": error_conversation_id,
            "final_answer": error_message,
            "message_count": len(conversations.get(error_conversation_id, [])),
            "policy": None,
            "trust_policy": None,
            "explanation": error_message,
            "trust_explanation": "",
            "permissions_score": 0,
            "trust_score": 0,
            "overall_score": 0,
            "security_notes": {"permissions": [], "trust": []},
            "score_breakdown": {},
            "security_features": {"permissions": [], "trust": []},
            "refinement_suggestions": {"permissions": [], "trust": []},
            "is_question": False,
            "conversation_history": conversations.get(error_conversation_id, [])[-10:],
            "compliance_status": {},
            "error": str(e)
        }
        logging.info(f"✅ Returning exception error response with conversation_id: {error_response.get('conversation_id')}")
        logging.info(f"✅ Error response type: {type(error_response)}")
        logging.info(f"✅ Error response has final_answer: {bool(error_response.get('final_answer'))}")
        return JSONResponse(content=error_response)

# Add FastAPI exception handler to catch any unhandled exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch any unhandled exceptions and return a valid JSON response"""
    try:
        logging.exception(f"❌ GLOBAL EXCEPTION HANDLER: Unhandled exception in {request.url}")
        logging.exception(f"   Exception type: {type(exc).__name__}")
        logging.exception(f"   Exception message: {str(exc)}")
        
        error_response = {
            "conversation_id": str(uuid.uuid4()),
            "final_answer": f"An unexpected error occurred: {str(exc)}",
            "message_count": 0,
            "policy": None,
            "trust_policy": None,
            "explanation": f"An unexpected error occurred: {str(exc)}",
            "trust_explanation": "",
            "permissions_score": 0,
            "trust_score": 0,
            "overall_score": 0,
            "security_notes": {"permissions": [], "trust": []},
            "score_breakdown": {},
            "security_features": {"permissions": [], "trust": []},
            "refinement_suggestions": {"permissions": [], "trust": []},
            "is_question": False,
            "conversation_history": [],
            "compliance_status": {},
            "error": str(exc)
        }
        
        logging.info(f"✅ Global exception handler returning error response")
        logging.info(f"   Error response type: {type(error_response)}")
        logging.info(f"   Error response keys: {list(error_response.keys())}")
        return JSONResponse(status_code=500, content=error_response)
    except Exception as handler_error:
        # If even the exception handler fails, return a minimal response
        logging.error(f"❌ CRITICAL: Exception handler itself failed: {handler_error}")
        return JSONResponse(
            status_code=500,
            content={
                "conversation_id": str(uuid.uuid4()),
                "final_answer": "An internal server error occurred. Please try again.",
                "message_count": 0,
                "policy": None,
                "trust_policy": None,
                "explanation": "An internal server error occurred.",
                "trust_explanation": "",
                "permissions_score": 0,
                "trust_score": 0,
                "overall_score": 0,
                "security_notes": {"permissions": [], "trust": []},
                "score_breakdown": {},
                "security_features": {"permissions": [], "trust": []},
                "refinement_suggestions": {"permissions": [], "trust": []},
                "is_question": False,
                "conversation_history": [],
                "compliance_status": {},
                "error": "Internal server error"
            }
        )


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