import logging
import boto3
import json
from strands import tool
from utils.service_utils import get_service_principal, detect_service_from_description
from contextvars import ContextVar

logging.basicConfig(level=logging.INFO)

bedrock_runtime = None
MODEL_ID = 'us.anthropic.claude-3-7-sonnet-20250219-v1:0'

# Context variable for user credentials (request-scoped, thread-safe)
# SECURITY: Credentials stored only for duration of request, automatically cleared
_user_credentials: ContextVar[dict] = ContextVar('user_credentials', default=None)

def get_bedrock_client(aws_credentials: dict = None):
    """
    Get Bedrock client with optional user credentials
    
    Args:
        aws_credentials: Optional dict with access_key_id, secret_access_key, region
                        If None, checks context variable, then falls back to default credentials
    
    SECURITY: User credentials are used only for this client instance, never stored
    """
    # Check explicit parameter first
    creds = aws_credentials
    
    # If not provided, check context variable (set by endpoint)
    if not creds:
        try:
            creds = _user_credentials.get()
            if creds:
                logging.info(f"✅ Retrieved credentials from context variable (region: {creds.get('region', 'us-east-1')})")
            else:
                logging.warning("⚠️ No credentials in context variable")
        except LookupError:
            logging.warning("⚠️ Context variable not set (LookupError)")
            creds = None
    
    if creds:
        # Validate credentials structure
        if not creds.get('access_key_id') or not creds.get('secret_access_key'):
            logging.error("❌ Invalid credentials structure: missing access_key_id or secret_access_key")
            raise ValueError("Invalid credentials: missing required fields")
        
        # Use user-provided credentials
        region = creds.get('region', 'us-east-1')
        access_key_id = creds['access_key_id']
        secret_access_key = creds['secret_access_key']
        
        logging.info(f"🔧 Creating Bedrock client with user credentials")
        logging.info(f"   Region: {region}")
        logging.info(f"   Access Key ID: {access_key_id[:8]}...{access_key_id[-4:] if len(access_key_id) > 12 else '****'}")
        
        try:
            client = boto3.client(
                service_name='bedrock-runtime',
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                region_name=region
            )
            logging.info("✅ Bedrock client created successfully with user credentials")
            return client
        except Exception as e:
            logging.error(f"❌ Failed to create Bedrock client with user credentials: {e}")
            raise
    else:
        # Use default credentials (for development/testing only)
        logging.warning("⚠️ No user credentials provided, attempting to use default credentials (may fail)")
        global bedrock_runtime
        if bedrock_runtime is None:
            logging.info("🔧 Initializing Bedrock client with default credentials...")
            try:
                bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
                logging.info("✅ Bedrock client initialized with default credentials")
            except Exception as e:
                logging.error(f"❌ Failed to initialize Bedrock client with default credentials: {e}")
                raise ValueError(f"Cannot create Bedrock client: {e}. Please provide valid AWS credentials.")
        return bedrock_runtime

def set_user_credentials(credentials: dict):
    """Set user credentials for current request context"""
    if credentials:
        logging.info(f"🔐 Setting user credentials in context (region: {credentials.get('region', 'us-east-1')})")
        _user_credentials.set(credentials)
    else:
        logging.warning("⚠️ Attempted to set None credentials")
        _user_credentials.set(None)

def clear_user_credentials():
    """Clear user credentials after request"""
    _user_credentials.set(None)


@tool
def generate_policy_from_bedrock(description: str, service: str, compliance: str = 'general') -> str:
    """Generate IAM policies with GUARANTEED scoring - Direct Bedrock approach
    
    Args:
        description: User's policy requirements description
        service: AWS service (e.g., lambda, ec2, s3)
        compliance: Compliance framework (general, pci-dss, hipaa, sox, gdpr, cis)
    """
    logging.info("=" * 80)
    logging.info("🔧 generate_policy_from_bedrock called")
    logging.info(f"   Service: {service}")
    logging.info(f"   Compliance: {compliance}")
    logging.info(f"   Description length: {len(description)}")
    
    bedrock = get_bedrock_client()
    logging.info("✅ Bedrock client obtained in generate_policy_from_bedrock")
    
    # Compliance framework requirements mapping
    compliance_requirements = {
        'general': 'Follow AWS security best practices and least-privilege principles.',
        'pci-dss': 'PCI DSS Compliance Requirements:\n- Implement least-privilege access (Requirement 7.1.2)\n- Require MFA for sensitive operations (Requirement 8.3)\n- Enable access logging and monitoring (Requirement 10)\n- Restrict access to cardholder data environments\n- Use resource-level permissions and conditions\n- Implement network segmentation principles',
        'hipaa': 'HIPAA Compliance Requirements:\n- Implement access controls (164.308(a)(4))\n- Require encryption in transit and at rest (164.312(a)(2)(iv), 164.312(e)(2)(ii))\n- Enable audit logging and monitoring (164.312(b))\n- Restrict access to PHI (Protected Health Information)\n- Use least-privilege principles\n- Implement audit controls for access to ePHI',
        'sox': 'SOX Compliance Requirements:\n- Implement access controls and segregation of duties\n- Enable comprehensive audit logging\n- Restrict access to financial data and systems\n- Require MFA for sensitive operations\n- Implement change management controls\n- Use least-privilege access principles',
        'gdpr': 'GDPR Compliance Requirements:\n- Implement data minimization principles (Article 5)\n- Restrict access to personal data\n- Enable audit logging for data access\n- Use encryption for data protection\n- Implement access controls (Article 32)\n- Ensure data subject rights can be exercised',
        'cis': 'CIS AWS Benchmarks Compliance:\n- Follow CIS Benchmark recommendations for IAM\n- Implement least-privilege access\n- Enable CloudTrail logging\n- Require MFA for sensitive operations\n- Use resource-level permissions\n- Implement security best practices'
    }
    
    compliance_guidance = compliance_requirements.get(compliance.lower().replace('_', '-'), compliance_requirements['general'])
    
    # System prompt - Optimized for speed (reduced verbosity)
    system_prompt = """You are an AWS IAM policy generator. Generate secure IAM policies efficiently.

CRITICAL RULES:
1. ALWAYS use ## (two hashes) for headers
2. ALWAYS include THREE scores: Permissions, Trust, Overall (1-100)
3. ALWAYS include both Permissions Policy AND Trust Policy in JSON format
4. Generate policies based on ACTUAL requirements
5. Use appropriate service principals (lambda.amazonaws.com, ec2.amazonaws.com, etc.)
6. For S3: Separate bucket operations (ListBucket) and object operations (GetObject) into TWO statements
7. Add CloudWatch Logs permissions for Lambda/ECS services
8. Use {{ACCOUNT_ID}}, {{REGION}} placeholders when values not provided
9. Be concise but complete - focus on essential information
10. **CRITICAL**: Adhere to compliance framework requirements when specified"""

    # User prompt - Dynamic based on actual request
    user_prompt = f"""🚨🚨🚨 CRITICAL: YOU MUST RETURN BOTH POLICIES 🚨🚨🚨

YOU MUST RETURN **BOTH** POLICIES:
1. Permissions Policy
2. Trust Policy

RETURNING ONLY ONE POLICY IS UNACCEPTABLE.

Both policies MUST be in properly formatted JSON with:
- Proper indentation (2 spaces)
- Line breaks between properties
- Clean, readable format

---

Generate an IAM policy based on this request:

**User Request:** {description}
**AWS Service:** {service}
**Compliance Framework:** {compliance.upper() if compliance != 'general' else 'General Security'}

**Compliance Requirements:**
{compliance_guidance}

**CRITICAL**: The generated policy MUST adhere to the compliance framework requirements above. Include:
- Appropriate condition keys (MFA, encryption, logging) as required
- Least-privilege access controls
- Resource-level restrictions
- Audit logging permissions where needed
- Any framework-specific security controls

Analyze the request and generate appropriate policies that comply with the specified framework.

🚨 REMINDER: YOU MUST INCLUDE BOTH PERMISSIONS POLICY **AND** TRUST POLICY 🚨
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "DescriptiveName",
      "Effect": "Allow",
      "Action": ["service:Action1", "service:Action2"],
      "Resource": "arn:aws:service:{{{{REGION}}}}:{{{{ACCOUNT_ID}}}}:resource-type/resource-name"
    }}
  ]
}}
```

## Trust Policy

```json
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Principal": {{"Service": "service.amazonaws.com"}},
      "Action": "sts:AssumeRole"
    }}
  ]
}}
```

## Permissions Policy Security Score: XX/100

**Score Calculation:**
- Base: 100 points
- [List deductions based on actual policy]
- **Final: XX/100**

## Permissions Policy Security Analysis

**Positive:**
- [List actual positive aspects of the generated policy]

**Could Improve:**
- [List actual improvements for the generated policy]

## Trust Policy Security Score: XX/100

**Score Calculation:**
- Base: 100 points
- [List deductions based on actual trust policy]
- **Final: XX/100**

## Trust Policy Security Analysis

**Positive:**
- [List actual positive aspects]

**Could Improve:**
- [List actual improvements]

## Overall Security Score: XX/100

## Permissions Policy Explanation

YOU MUST explain EACH statement in the permissions policy you generated. Use this EXACT format:

1. S3 Bucket Access
Permission: s3:ListBucket, s3:GetBucketLocation
Purpose: Allows the Lambda function to list objects in the S3 bucket and get its location information
Security: Limited to the specific bucket "customer-uploads-prod" only

2. S3 Object Operations
Permission: s3:GetObject
Purpose: Allows the Lambda function to read/download objects from the S3 bucket
Security: Limited to objects within the specific bucket "customer-uploads-prod"

3. DynamoDB Operations
Permission: dynamodb:PutItem, dynamodb:BatchWriteItem
Purpose: Allows the Lambda function to write individual items or batches of items to the DynamoDB table
Security: Limited to the specific table "transaction-logs"

[Continue for ALL statements - use numbered format: 1., 2., 3., etc.]
[Each statement MUST have: Permission:, Purpose:, Security: on separate lines]
[NO markdown bold (**), NO bullet points (-), just plain text with colons]

## Trust Policy Explanation

YOU MUST explain the trust policy in detail:

**Trusted Entity:** [The service principal, e.g., lambda.amazonaws.com]

**What It Means:** Only the AWS Lambda service can assume this role to execute functions. This prevents other AWS services or accounts from using these permissions.

**Security:** Prevents other services or accounts from using these permissions. The role can only be assumed by Lambda functions in your AWS account.

## Permissions Policy Security Features

YOU MUST list the ACTUAL security features present in the permissions policy you generated:
- [Feature 1, e.g., "Scoped to specific S3 bucket ARN instead of wildcard"]
- [Feature 2, e.g., "Separate statements for bucket and object operations"]
- [Feature 3, e.g., "CloudWatch Logs permissions limited to specific log group"]

## Trust Policy Security Features

YOU MUST list the ACTUAL security features in the trust policy:
- [Feature 1, e.g., "Explicitly defines lambda.amazonaws.com as trusted principal"]
- [Feature 2, e.g., "Uses sts:AssumeRole action for role assumption"]

## Permissions Policy Considerations

YOU MUST list considerations for the permissions policy:
- [Consideration 1, e.g., "Resource uses placeholders - replace {{ACCOUNT_ID}} with actual account ID"]
- [Consideration 2, e.g., "Consider adding condition keys for additional security"]

## Trust Policy Considerations

YOU MUST list considerations for the trust policy:
- [Consideration 1, e.g., "Trust policy allows any Lambda function in the account to assume this role"]
- [Consideration 2, e.g., "Consider adding aws:SourceArn condition to limit to specific Lambda function"]

## Permissions Policy Refinement Suggestions

🚨🚨🚨 CRITICAL: YOU MUST INCLUDE THIS EXACT SECTION HEADER IN EVERY RESPONSE 🚨🚨🚨

Use this EXACT header: "## Permissions Policy Refinement Suggestions" (no variations, no emojis, no alternatives)

YOU MUST provide 3-5 ACTIONABLE, SERVICE-SPECIFIC refinement suggestions based on the ACTUAL policy you just generated and the user's specific use case.

Analyze the permissions policy you created and suggest improvements like:
- Adding condition keys (aws:SourceArn, aws:SourceAccount, aws:RequestedRegion, etc.)
- Narrowing resource ARNs (replace wildcards with specific resources)
- Adding encryption requirements
- Limiting to specific resource prefixes or tags
- Adding time-based or IP-based conditions if applicable

Format as bullet points starting with dash (-):
- [Suggestion 1 based on actual policy]
- [Suggestion 2 based on actual policy]
- [Suggestion 3 based on actual policy]
- [Suggestion 4 based on actual policy]
- [Suggestion 5 based on actual policy]

IMPORTANT: Generate suggestions specific to the services in THIS policy, not generic examples

## Trust Policy Refinement Suggestions

🚨🚨🚨 CRITICAL: YOU MUST INCLUDE THIS EXACT SECTION HEADER IN EVERY RESPONSE 🚨🚨🚨

Use this EXACT header: "## Trust Policy Refinement Suggestions" (no variations, no emojis, no alternatives)

YOU MUST provide 2-3 ACTIONABLE trust policy refinements based on the ACTUAL trust policy you just generated.

Analyze the trust policy and suggest improvements like:
- Adding aws:SourceArn condition to limit which specific resource can assume the role
- Adding aws:SourceAccount condition to prevent cross-account access
- Adding external ID for third-party access
- Adding condition keys specific to the service principal
- Restricting to specific organizational units or accounts

Format as bullet points starting with dash (-):
- [Suggestion 1 based on actual trust policy]
- [Suggestion 2 based on actual trust policy]
- [Suggestion 3 based on actual trust policy]

IMPORTANT: Generate suggestions specific to THIS trust policy and service principal, not generic examples

## Why Both Policies Are Essential
**Permissions Policy**: Defines WHAT actions the role can perform
**Trust Policy**: Defines WHO can assume the role

Together they create a complete, secure IAM role.

CRITICAL REMINDERS:
- Generate policies based on the ACTUAL user request, not templates
- Use appropriate service principal for the trust policy (lambda.amazonaws.com, ec2.amazonaws.com, ecs-tasks.amazonaws.com, etc.)
- Calculate REAL scores (1-100) based on actual policy security
- For S3: Always separate bucket operations (ListBucket) and object operations (GetObject, PutObject) into TWO statements
- Include CloudWatch Logs for services that need logging
- Use placeholders ({{{{ACCOUNT_ID}}}}, {{{{REGION}}}}, {{{{RESOURCE_NAME}}}}) when specific values aren't provided
- Provide context-specific analysis and suggestions, not generic ones"""

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4000,  # Optimized - actual usage is ~1500-2000 tokens
        "system": system_prompt,  # Add system prompt here
        "messages": [{"role": "user", "content": [{"type": "text", "text": user_prompt}]}],
        "temperature": 0.1  # Low temperature for consistent, fast responses
    })

    try:
        logging.info("📡 Calling Bedrock invoke_model in generate_policy_from_bedrock")
        logging.info(f"   Model ID: {MODEL_ID}")
        logging.info(f"   Body length: {len(body)} chars")
        response = bedrock.invoke_model(body=body, modelId=MODEL_ID)
        logging.info("✅ Bedrock invoke_model succeeded in generate_policy_from_bedrock")
        body_bytes = response.get('body').read()
        
        try:
            response_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            response_body = json.loads(body_bytes.decode('utf-8'))
        
        raw_response_text = response_body.get('content', [{}])[0].get('text', '')
        
        # Extract token usage for cost tracking
        usage = response_body.get('usage', {})
        input_tokens = usage.get('input_tokens', 0)
        output_tokens = usage.get('output_tokens', 0)
        
        # Claude 3.7 Sonnet pricing (us-east-1, as of 2024):
        # Input: $3.00 per 1M tokens
        # Output: $15.00 per 1M tokens
        INPUT_COST_PER_1M = 3.00
        OUTPUT_COST_PER_1M = 15.00
        
        input_cost = (input_tokens / 1_000_000) * INPUT_COST_PER_1M
        output_cost = (output_tokens / 1_000_000) * OUTPUT_COST_PER_1M
        total_cost = input_cost + output_cost
        
        # Log what we got + token usage
        logging.info("=" * 80)
        logging.info("💰 TOKEN USAGE & COST (AWS Bedrock Claude 3.7 Sonnet):")
        logging.info(f"   Input tokens: {input_tokens:,} → ${input_cost:.6f}")
        logging.info(f"   Output tokens: {output_tokens:,} → ${output_cost:.6f}")
        logging.info(f"   💵 ESTIMATED COST: ${total_cost:.6f} per request")
        logging.info(f"   Response length: {len(raw_response_text):,} chars")
        logging.info(f"   Note: max_tokens=4000 is a LIMIT, not actual usage. You pay for {output_tokens:,} tokens generated.")
        logging.info("CHECKING FOR REQUIRED SECTIONS:")
        logging.info("  Has Permissions Policy: {}".format("## Permissions Policy" in raw_response_text))
        logging.info("  Has Trust Policy: {}".format("## Trust Policy" in raw_response_text))
        logging.info("  Has Permissions Score: {}".format("Permissions Policy Security Score:" in raw_response_text))
        logging.info("  Has Trust Score: {}".format("Trust Policy Security Score:" in raw_response_text))
        logging.info("  Has Overall Score: {}".format("Overall Security Score:" in raw_response_text))
        
        # 🚨 CRITICAL: Validate that BOTH policies are present
        has_permissions_policy = "## Permissions Policy" in raw_response_text
        has_trust_policy = "## Trust Policy" in raw_response_text
        
        if has_permissions_policy and not has_trust_policy:
            logging.error("❌ CRITICAL: Bedrock returned only Permissions Policy, missing Trust Policy!")
            logging.info("🔧 Auto-generating Trust Policy based on service...")
            
            # Determine service principal using comprehensive mapping
            detected_service = service or detect_service_from_description(description)
            service_principal = get_service_principal(detected_service)
            logging.info(f"✅ Using service principal: {service_principal} for service: {detected_service}")
            
            # Generate Trust Policy section
            trust_policy_section = f'''\n\n## Trust Policy\n\n```json\n{{\n  "Version": "2012-10-17",\n  "Statement": [\n    {{\n      "Effect": "Allow",\n      "Principal": {{\n        "Service": "{service_principal}"\n      }},\n      "Action": "sts:AssumeRole"\n    }}\n  ]\n}}\n```\n\n## Trust Policy Security Score: 85/100\n\n**Score Calculation:**\n- Base: 100 points\n- No conditions to restrict role assumption (-15)\n- **Final: 85/100**\n\n## Trust Policy Security Analysis\n\n**Positive:**\n- Uses specific service principal\n- Follows least privilege for trust relationships\n\n**Could Improve:**\n- Add aws:SourceAccount condition to prevent confused deputy\n- Add aws:SourceArn for additional security\n\n## Trust Policy Explanation\n\nThis trust policy allows the {service} service to assume this role. The service principal "{service_principal}" is the only entity that can assume this role.\n\n## Trust Policy Security Features\n\n- Service-specific principal\n- Standard AssumeRole action\n\n## Trust Policy Considerations\n\n- Consider adding condition keys for additional security\n- Review if cross-account access is needed\n\n## Trust Policy Refinement Suggestions\n\n- Add aws:SourceAccount condition to restrict which account can use this role\n- Add aws:SourceArn condition to restrict which specific resources can assume the role\n'''
            
            # Insert Trust Policy after Permissions Policy
            # Find where to insert (after first policy section)
            insert_pos = raw_response_text.find("## Permissions Policy Security Score:")
            if insert_pos > 0:
                raw_response_text = raw_response_text[:insert_pos] + trust_policy_section + raw_response_text[insert_pos:]
                logging.info("✅ Successfully added Trust Policy section")
            else:
                # Fallback: append at the end
                raw_response_text += trust_policy_section
                logging.info("✅ Appended Trust Policy section at end")
        
        # Fix improperly formatted JSON blocks (Claude sometimes outputs JSON on one line)
        # Use regex to extract JSON content from ```json ... ``` blocks
        import re
        json_block_pattern = r'```json\s*([\s\S]*?)```'
        matches = list(re.finditer(json_block_pattern, raw_response_text, re.IGNORECASE))
        
        for match in matches:
            full_match = match.group(0)  # Full match including ```json and ```
            json_content = match.group(1).strip()  # Just the JSON content
            
            # Try to parse the JSON
            try:
                # If it parses successfully, it's valid JSON - no fix needed
                json.loads(json_content)
            except json.JSONDecodeError:
                # JSON is invalid - try to fix formatting
                logging.warning("❌ Improperly formatted JSON block detected. Attempting to fix...")
                
                # Try to extract valid JSON from the content (might have extra text)
                # Find the first { and last } to extract the JSON object
                first_brace = json_content.find('{')
                last_brace = json_content.rfind('}')
                
                if first_brace >= 0 and last_brace > first_brace:
                    json_only = json_content[first_brace:last_brace + 1]
                    try:
                        # Try parsing the extracted JSON
                        parsed = json.loads(json_only)
                        # If successful, format it properly
                        formatted_json = json.dumps(parsed, indent=2)
                        # Replace the old block with properly formatted JSON
                        new_block = f'```json\n{formatted_json}\n```'
                        raw_response_text = raw_response_text.replace(full_match, new_block)
                        logging.info("✅ Successfully fixed JSON block")
                    except json.JSONDecodeError:
                        # Still invalid - try line-by-line formatting fix
                        lines = json_only.splitlines()
                        fixed_block = ''
                        indent_level = 0
                        for line in lines:
                            stripped = line.strip()
                            if stripped.startswith('}'):
                                indent_level = max(0, indent_level - 1)
                            fixed_block += '  ' * indent_level + stripped + '\n'
                            if stripped.startswith('{'):
                                indent_level += 1
                        # Try parsing the fixed version
                        try:
                            json.loads(fixed_block.strip())
                            new_block = f'```json\n{fixed_block}\n```'
                            raw_response_text = raw_response_text.replace(full_match, new_block)
                            logging.info("✅ Successfully fixed JSON block (line-by-line formatting)")
                        except json.JSONDecodeError:
                            # Couldn't fix it - leave as is
                            logging.warning(f"⚠️ Could not fix JSON block, leaving as-is")
                else:
                    logging.warning(f"⚠️ Could not find JSON structure in block, leaving as-is")
        
        logging.info("=" * 80)
        
        return raw_response_text

    except Exception as e:
        logging.exception("❌ Bedrock failed")
        return f"Error: {str(e)}"


@tool
def refine_policy_from_bedrock(user_message: str, conversation_context: str) -> str:
    """Refine policy - same format as generation"""
    logging.info("=" * 80)
    logging.info("🔧 refine_policy_from_bedrock called")
    logging.info(f"   User message length: {len(user_message)}")
    logging.info(f"   Conversation context length: {len(conversation_context)}")
    
    bedrock = get_bedrock_client()
    logging.info("✅ Bedrock client obtained in refine_policy_from_bedrock")
    
    prompt = f"""User wants to refine their IAM policy.

Previous context:
{conversation_context}

User request:
{user_message}

If user asks a question: Answer it clearly.
If user wants changes: Update the policy and output the SAME format as before with ALL sections including scores."""

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4000,  # Optimized - actual usage is ~1500-2000 tokens
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
        "temperature": 0.1
    })

    try:
        logging.info("📡 Calling Bedrock invoke_model in refine_policy_from_bedrock")
        logging.info(f"   Model ID: {MODEL_ID}")
        logging.info(f"   Body length: {len(body)} chars")
        response = bedrock.invoke_model(body=body, modelId=MODEL_ID)
        logging.info("✅ Bedrock invoke_model succeeded in refine_policy_from_bedrock")
        body_bytes = response.get('body').read()
        
        try:
            response_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            response_body = json.loads(body_bytes.decode('utf-8'))
        
        response_text = response_body.get('content', [{}])[0].get('text', '')
        logging.info(f"✅ Refinement response received: {len(response_text)} chars")
        return response_text

    except Exception as e:
        logging.error("=" * 80)
        logging.error("❌ CRITICAL: Refinement failed in refine_policy_from_bedrock")
        logging.error(f"   Error type: {type(e).__name__}")
        logging.error(f"   Error message: {str(e)}")
        logging.exception(e)
        logging.error("=" * 80)
        return f"Error: {str(e)}"