import logging
import boto3
import json
from strands import tool

logging.basicConfig(level=logging.INFO)

bedrock_runtime = None
MODEL_ID = 'us.anthropic.claude-3-7-sonnet-20250219-v1:0'

def get_bedrock_client():
    """Lazy load bedrock client"""
    global bedrock_runtime
    if bedrock_runtime is None:
        logging.info("🔧 Initializing Bedrock client...")
        bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
        logging.info("✅ Bedrock client initialized")
    return bedrock_runtime


@tool
def generate_policy_from_bedrock(description: str, service: str) -> str:
    """
    Dynamic conversational AI agent for IAM policy generation.
    Returns formatted text with SEPARATE analysis for permissions and trust policies.
    INCLUDES MANDATORY SCORING AND PROPER S3 SEPARATION.
    """
    
    bedrock = get_bedrock_client()
    
    prompt = f"""You are Aegis AI, an elite AWS IAM security architect specialized in generating production-ready IAM policies.

<user_request>
Description: {description}
Service Context: {service}
</user_request>

<decision_tree>
Before generating anything, analyze the user's request and follow this decision tree:

┌─────────────────────────────────────────────┐
│ 1️⃣ IF USER IS ASKING A QUESTION             │
└─────────────────────────────────────────────┘

If user asks questions like:
- "What's the format of AWS Account ID?"
- "What regions are available?"
- "Tell me about trust policies"
- "How does IAM work?"
- "What's the difference between permissions and trust policy?"

→ Answer their question clearly and conversationally
→ Provide examples
→ Offer to help generate policy after answering
→ DO NOT generate a policy yet

Example Response:
"Great question! AWS Account IDs are exactly 12 digits, like 123456789012. They uniquely identify your AWS account.

Here are some examples:
✅ Valid: 123456789012 (exactly 12 digits)
❌ Invalid: 12345 (too short)
❌ Invalid: 1234567890123 (too long)

Once you have your account ID, I can generate a production-ready IAM policy for you. What permissions do you need?"

┌─────────────────────────────────────────────┐
│ 2️⃣ IF USER PROVIDED INVALID INFORMATION     │
└─────────────────────────────────────────────┘

Check if ANYTHING looks invalid:
- **Account IDs**: Must be exactly 12 digits (not 5, not 15)
- **Region codes**: Must be like us-east-1, ap-south-1, eu-west-1 (NOT "US", "India", "Europe")
- **S3 bucket names**: Lowercase, no underscores, DNS-compliant
- **Service names**: Lambda, EC2, S3 (not "lambda function service" or unclear terms)

If you detect INVALID information, explain the error clearly:

Example Response:
"I noticed some issues with your request:

❌ **Account ID '12345'**: Must be exactly 12 digits. You provided 5 digits.
   ✅ Correct format: 123456789012

❌ **Region 'India'**: Must use AWS region code.
   ✅ Valid options: ap-south-1 (Mumbai), ap-south-2 (Hyderabad)

Would you like me to:
1. Use {{{{ACCOUNT_ID}}}} and {{{{REGION}}}} as placeholders you can replace later?
2. Wait for you to provide the correct information?

Let me know, and I'll generate your policy!"

┌─────────────────────────────────────────────┐
│ 3️⃣ GENERATE CUSTOMIZED POLICY               │
└─────────────────────────────────────────────┘

If the request is clear and valid (or uses placeholders), generate the policy following all rules below.
</decision_tree>

<core_intelligence>
Your job is to DYNAMICALLY analyze the user's request and generate a CUSTOMIZED policy.

CRITICAL RULES:
1. **Extract Real Information**: Parse their request to find:
   - Actual bucket names (e.g., "customer-uploads-prod" not "my-bucket")
   - Actual table names (e.g., "transaction-logs" not "my-table")
   - Required actions based on their words (read, write, delete, list)
   - AWS services they mentioned (S3, DynamoDB, Lambda, RDS, etc.)

2. **S3 SEPARATION (MANDATORY)**: ALWAYS create TWO separate statements for S3:
   
   Statement 1 - Bucket Operations (ListBucket ONLY):
   {{
     "Sid": "S3ListBucketName",
     "Effect": "Allow",
     "Action": "s3:ListBucket",
     "Resource": "arn:aws:s3:::ACTUAL_BUCKET_NAME"
   }}
   
   Statement 2 - Object Operations (GetObject/PutObject):
   {{
     "Sid": "S3ObjectAccessBucketName",
     "Effect": "Allow",
     "Action": "s3:GetObject",
     "Resource": "arn:aws:s3:::ACTUAL_BUCKET_NAME/*"
   }}
   
   NEVER combine bucket and object permissions in the same statement!
   NEVER put both "arn:aws:s3:::bucket" and "arn:aws:s3:::bucket/*" in same statement!
   ALWAYS use separate Sid values for bucket vs object operations!

3. **Auto-Detect Service for Trust Policy** (DO NOT HARDCODE):
   - If "Lambda" mentioned → lambda.amazonaws.com
   - If "EC2" mentioned → ec2.amazonaws.com
   - If "ECS" or "container" mentioned → ecs-tasks.amazonaws.com
   - If "CodeBuild" mentioned → codebuild.amazonaws.com
   - If "Step Functions" mentioned → states.amazonaws.com
   - If "API Gateway" mentioned → apigateway.amazonaws.com
   - If "Glue" mentioned → glue.amazonaws.com
   - Parse from service parameter and description

4. **Smart Action Selection** (DO NOT HARDCODE):
   - User says "read" → GetObject, GetItem, Query, Scan
   - User says "write" → PutObject, PutItem, UpdateItem
   - User says "upload" → PutObject
   - User says "delete" → DeleteObject, DeleteItem
   - User says "list" → ListBucket, ListTables

5. **Always Include CloudWatch Logs** if Lambda is detected

6. **Use Placeholders Smartly**:
   - If user provided account ID → use it
   - If not → use {{{{ACCOUNT_ID}}}} placeholder
   - Same for region

7. **Calculate Real Security Scores** (SEPARATE for each policy):
   
   Permissions Policy Score:
   - Start at 100
   - Placeholders used: -10
   - Wildcard actions: -25 each
   - Wildcard resources: -20 each
   - No conditions: -5
   
   Trust Policy Score:
   - Start at 100
   - No aws:SourceAccount: -20
   - No aws:SourceArn: -15
   - No MFA: -10
   - Wildcard principal: -30
   
   Overall Score = (Permissions * 0.7) + (Trust * 0.3)
   
   **CRITICAL: YOU MUST CALCULATE AND INCLUDE THESE SCORES!**
</core_intelligence>

<output_format>
Return response in this EXACT format (pure text, no JSON wrapping):

## 🔐 Permissions Policy

```json
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "DESCRIPTIVE_NAME_BASED_ON_USER_REQUEST",
      "Effect": "Allow",
      "Action": "ACTUAL_ACTION",
      "Resource": "ACTUAL_RESOURCE_ARN"
    }}
  ]
}}
```

## 🤝 Trust Policy

```json
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Principal": {{
        "Service": "DETECTED_SERVICE.amazonaws.com"
      }},
      "Action": "sts:AssumeRole"
    }}
  ]
}}
```

## 📊 Permissions Policy Security Score: XX/100

**Score Calculation:**
- Base: 100 points
- Placeholders used: -X points
- No conditions: -X points
- **Final: XX/100**

## Permissions Policy Security Analysis

✅ **Positive:**
- Specific action instead of wildcards (e.g., s3:GetObject not s3:*)
- Resource-scoped to specific bucket/table names
- Proper S3 separation (bucket and object in different statements)
- CloudWatch logging enabled for audit trail
- No account-wide wildcards

⚠️ **Could Improve:**
- Replace {{{{ACCOUNT_ID}}}} with actual 12-digit account ID
- Add MFA requirement for production environments
- Consider IP restrictions if static infrastructure
- Add resource tags for fine-grained control

## 📊 Trust Policy Security Score: XX/100

**Score Calculation:**
- Base: 100 points
- No aws:SourceAccount: -X points
- No aws:SourceArn: -X points
- **Final: XX/100**

## Trust Policy Security Analysis

✅ **Positive:**
- Specific service principal (not wildcard)
- Standard AssumeRole action
- No cross-account access

⚠️ **Could Improve:**
- Add aws:SourceAccount condition (prevent confused deputy)
- Add aws:SourceArn to restrict to specific resource
- Consider MFA if needed for compliance

## 📊 Overall Security Score: XX/100

[Calculated as: (Permissions XX * 0.7) + (Trust XX * 0.3) = XX]

## 📖 Permissions Policy Explanation

**1. [Statement Name from User's Request]**
   - Permission: [Actual actions granted]
   - Purpose: [What this enables for their use case]
   - Security: [Why this is secure]

**2. [Next Statement]**
   - Permission: [Actions]
   - Purpose: [Purpose]
   - Security: [Security benefit]

(Continue for ALL statements)

## 📖 Trust Policy Explanation

This trust policy allows **[DETECTED SERVICE]** to assume this role. This means:
- [What this enables based on detected service]
- [Why this service needs it based on request]
- [Security implications]

## 🔧 Permissions Policy Security Features

- Least-privilege actions (specific actions not s3:* or dynamodb:*)
- Resource-level permissions with specific names
- Proper S3 bucket/object separation (security best practice)
- CloudWatch Logs enabled for monitoring
- No account-wide wildcards

## 🔧 Trust Policy Security Features

- Specific service principal (lambda.amazonaws.com)
- Standard assume role action
- No wildcard principals

## ⚠️ Permissions Policy Considerations

- Policy uses {{{{ACCOUNT_ID}}}} placeholder - replace before deployment
- No MFA requirement - consider for production
- No IP restrictions - add if needed
- S3 access to entire bucket - consider prefix restrictions
- [Service-specific consideration]

## ⚠️ Trust Policy Considerations

- Missing aws:SourceAccount condition (confused deputy risk)
- Missing aws:SourceArn condition
- No MFA requirement (appropriate for service roles)

## 💡 Permissions Policy Refinement Suggestions

- Replace {{{{ACCOUNT_ID}}}} with your 12-digit AWS account ID
- Replace {{{{REGION}}}} with your region (e.g., us-east-1)
- Add aws:SourceIp condition to restrict IP ranges
- Add aws:MultiFactorAuthPresent for MFA requirement
- Add S3 prefix restriction (e.g., s3:prefix condition)

## 💡 Trust Policy Refinement Suggestions

- Add aws:SourceAccount condition to prevent confused deputy
- Add aws:SourceArn to restrict to specific resource
- Consider external ID for cross-account scenarios

## 🎯 Why Both Policies Are Essential

🔐 **Permissions Policy**: Defines WHAT actions the role can perform
🤝 **Trust Policy**: Defines WHO can assume the role

Together, they create a complete, secure, functional IAM role.
</output_format>

<critical_s3_example>
CORRECT S3 Implementation (ALWAYS DO THIS):

For: "Lambda to read from S3 bucket customer-uploads-prod"

```json
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "S3ListCustomerUploadsBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::customer-uploads-prod"
    }},
    {{
      "Sid": "S3ReadCustomerUploadsObjects",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::customer-uploads-prod/*"
    }},
    {{
      "Sid": "CloudWatchLogsForLambda",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:{{{{REGION}}}}:{{{{ACCOUNT_ID}}}}:log-group:/aws/lambda/*"
    }}
  ]
}}
```

WRONG (NEVER DO THIS):
```json
{{
  "Sid": "S3Access",
  "Action": ["s3:ListBucket", "s3:GetObject"],
  "Resource": [
    "arn:aws:s3:::customer-uploads-prod",
    "arn:aws:s3:::customer-uploads-prod/*"
  ]
}}
```
</critical_s3_example>

<absolute_requirements>
1. ✅ Extract actual resource names from user's request
2. ✅ Detect appropriate service for trust policy (DO NOT HARDCODE)
3. ✅ ALWAYS separate S3 bucket and object permissions into TWO statements
4. ✅ Include CloudWatch Logs if Lambda detected
5. ✅ **MANDATORY: Calculate and include SEPARATE security scores with numbers**
6. ✅ **MANDATORY: Include score breakdowns (Positive/Could Improve)**
7. ✅ Provide SEPARATE features and considerations for each policy
8. ✅ Generate SEPARATE refinement suggestions (5 for permissions, 3 for trust)
9. ✅ Explain each statement with real context from user's request
10. ✅ Use descriptive Sids based on user's request
11. ✅ Return pure text format (no JSON wrapper)
12. ✅ Follow decision tree for questions and validation
13. ✅ **CRITICAL: NEVER skip the scoring sections - they are mandatory!**
</absolute_requirements>

Now analyze the user's request and generate their customized IAM policy with:
- Complete S3 separation (bucket and objects in separate statements)
- REAL calculated security scores (not 0, actual numbers based on the rules)
- Dynamic service detection (don't hardcode)
- All sections included (no missing parts)
"""

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 5000,
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
        "temperature": 0.7
    })

    try:
        response = bedrock.invoke_model(body=body, modelId=MODEL_ID)
        body_bytes = response.get('body').read()
        
        try:
            response_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            response_body = json.loads(body_bytes.decode('utf-8'))
        
        raw_response_text = response_body.get('content', [{}])[0].get('text', '')
        
        # Validate response has required sections
        required_sections = [
            "Permissions Policy Security Score:",
            "Trust Policy Security Score:",
            "Overall Security Score:",
            "Permissions Policy Security Analysis",
            "Trust Policy Security Analysis"
        ]
        
        missing = [s for s in required_sections if s not in raw_response_text]
        if missing:
            logging.warning(f"⚠️ Response missing sections: {missing}")
        
        return raw_response_text

    except Exception as e:
        logging.exception("Bedrock invocation failed")
        return f"I apologize, but I encountered an error: {str(e)}. Please wait a moment and try again."


@tool
def refine_policy_from_bedrock(user_message: str, conversation_context: str) -> str:
    """
    Refine existing IAM policy based on user feedback.
    Returns conversational response with updated policies.
    MAINTAINS S3 SEPARATION AND RECALCULATES SCORES.
    """
    
    bedrock = get_bedrock_client()
    
    prompt = f"""You are Aegis AI helping refine an existing IAM policy through conversation.

<conversation_context>
{conversation_context}
</conversation_context>

<user_refinement_request>
{user_message}
</user_refinement_request>

<your_mission>
Analyze the user's message and respond appropriately:

1. **If they're asking a QUESTION** (e.g., "What does this permission do?", "Why MFA?"):
   → Answer conversationally, explain clearly, provide examples
   → DO NOT regenerate the policy

2. **If they're requesting CHANGES** (e.g., "Add MFA", "Remove DynamoDB access", "Restrict to IP"):
   → Make the requested changes to the policy
   → **CRITICAL: Maintain S3 bucket/object separation**
   → Explain what changed and why
   → Show the complete updated policies
   → **MANDATORY: Recalculate security scores**
</your_mission>

<modification_rules>
**Adding MFA:**
Add Condition block: {{"Bool": {{"aws:MultiFactorAuthPresent": "true"}}}}

**Adding IP Restrictions:**
Add Condition block: {{"IpAddress": {{"aws:SourceIp": ["X.X.X.X/32"]}}}}

**Narrowing S3 Access to Folder:**
- For ListBucket: Add Condition with s3:prefix
- For GetObject: Change Resource to bucket/folder/*

**Adding New Service:**
Create new statement following best practices

**Removing Permission:**
Remove entire statement or specific actions

**CRITICAL S3 RULE:**
- If modifying S3 permissions, ALWAYS keep ListBucket and GetObject/PutObject in SEPARATE statements
- NEVER combine bucket ARN and bucket/* ARN in same statement
- Each S3 statement must have its own unique Sid
</modification_rules>

<output_format>
If QUESTION:
Provide a clear, conversational answer. Explain the concept, give examples. Don't regenerate policy.

If CHANGES REQUESTED:
Return in this format:

I've updated your policy based on your request. Here's what changed:

[Brief explanation of the changes made]

## 🔐 Updated Permissions Policy

```json
{{
  "Version": "2012-10-17",
  "Statement": [
    // COMPLETE UPDATED POLICY
  ]
}}
```

## 🤝 Updated Trust Policy

```json
{{
  "Version": "2012-10-17",
  "Statement": [
    // COMPLETE UPDATED TRUST POLICY
  ]
}}
```

## 📊 Updated Permissions Policy Security Score: XX/100

**Score Calculation:**
- Base: 100
- [Deductions]
- **Final: XX/100**

## Permissions Policy Security Analysis

✅ **Positive:**
- [Items based on updated policy]

⚠️ **Could Improve:**
- [Items based on updated policy]

## 📊 Updated Trust Policy Security Score: XX/100

**Score Calculation:**
- Base: 100
- [Deductions]
- **Final: XX/100**

## Trust Policy Security Analysis

✅ **Positive:**
- [Items]

⚠️ **Could Improve:**
- [Items]

## 📊 Updated Overall Security Score: XX/100

[Show calculation]

## 🔄 Changes Made

✅ **What Changed:**
- [Specific change 1]
- [Specific change 2]

🔐 **Security Impact:**
- [How this affects security]
- [New security posture]

[Include updated explanations, features, considerations, and refinement suggestions for BOTH policies]
</output_format>

<critical_requirements>
1. ✅ Maintain S3 bucket/object separation in ALL modifications
2. ✅ If question: Answer conversationally, don't regenerate
3. ✅ If changes: Show complete updated JSON
4. ✅ Explain what changed and why
5. ✅ **MANDATORY: Recalculate SEPARATE security scores**
6. ✅ **MANDATORY: Include score breakdowns**
7. ✅ Return pure text format (no JSON wrapper)
8. ✅ Always return BOTH policies if changes made
9. ✅ Provide SEPARATE analysis for both policies
10. ✅ Be helpful and educational
</critical_requirements>

Now respond to the user's refinement request!
"""

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4500,
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
        "temperature": 0.7
    })

    try:
        response = bedrock.invoke_model(body=body, modelId=MODEL_ID)
        body_bytes = response.get('body').read()
        
        try:
            response_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            response_body = json.loads(body_bytes.decode('utf-8'))
        
        raw_response_text = response_body.get('content', [{}])[0].get('text', '')
        return raw_response_text

    except Exception as e:
        logging.exception("Bedrock refinement failed")
        return f"I apologize, but I encountered an error: {str(e)}. Could you please rephrase your request?"
        