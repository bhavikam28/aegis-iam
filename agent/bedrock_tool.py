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
    """Generate IAM policies with GUARANTEED scoring - Direct Bedrock approach"""
    
    bedrock = get_bedrock_client()
    
    # System prompt - This takes precedence
    system_prompt = """You are an AWS IAM policy generator. You MUST follow the exact output format specified.

CRITICAL RULES:
1. ALWAYS use ## (two hashes) for headers, NEVER ### (three hashes)
2. ALWAYS include THREE SEPARATE scores: Permissions, Trust, and Overall
3. ALWAYS separate S3 bucket and object permissions into TWO different statements
4. NEVER output 0 for scores - calculate real numbers
5. ALWAYS include all sections shown in the format"""

    # User prompt with example
    user_prompt = f"""Generate an IAM policy for: {description} (Service: {service})

YOU MUST OUTPUT EXACTLY THIS FORMAT:

## 🔐 Permissions Policy

```json
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "S3ListBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::BUCKET_NAME"
    }},
    {{
      "Sid": "S3ReadObjects",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::BUCKET_NAME/*"
    }},
    {{
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:{{{{REGION}}}}:{{{{ACCOUNT_ID}}}}:log-group:/aws/lambda/*"
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
      "Principal": {{"Service": "lambda.amazonaws.com"}},
      "Action": "sts:AssumeRole"
    }}
  ]
}}
```

## 📊 Permissions Policy Security Score: 75/100

**Score Calculation:**
- Base: 100 points
- Placeholders used: -15 points
- No conditions: -10 points
- **Final: 75/100**

## Permissions Policy Security Analysis

✅ **Positive:**
- S3 bucket and object permissions separated (AWS best practice)
- Specific actions instead of wildcards
- Resource-scoped to specific bucket
- CloudWatch Logs enabled for monitoring

⚠️ **Could Improve:**
- Replace {{{{ACCOUNT_ID}}}} with actual account ID
- Replace {{{{REGION}}}} with region (e.g., us-east-1)
- Add IP restriction using aws:SourceIp condition
- Consider MFA requirement for production

## 📊 Trust Policy Security Score: 85/100

**Score Calculation:**
- Base: 100 points
- No aws:SourceAccount: -10 points
- No aws:SourceArn: -5 points
- **Final: 85/100**

## Trust Policy Security Analysis

✅ **Positive:**
- Specific service principal (lambda.amazonaws.com)
- Standard AssumeRole action
- No cross-account access

⚠️ **Could Improve:**
- Add aws:SourceAccount condition
- Add aws:SourceArn to restrict to specific Lambda
- Consider external ID for cross-account scenarios

## 📊 Overall Security Score: 78/100

## 📖 Permissions Policy Explanation

**1. S3 Bucket Listing**
   - Permission: s3:ListBucket
   - Purpose: Allows listing bucket contents
   - Security: Scoped to specific bucket

**2. S3 Object Reading**
   - Permission: s3:GetObject
   - Purpose: Allows reading objects
   - Security: Separate from bucket operations

**3. CloudWatch Logging**
   - Permission: logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
   - Purpose: Enables Lambda logging
   - Security: Restricted to Lambda log groups

## 📖 Trust Policy Explanation

This trust policy allows AWS Lambda service to assume this role. Lambda functions can use the permissions defined above. Only Lambda service can assume this role.

## 🔧 Permissions Policy Security Features

- S3 permissions separated (bucket vs objects)
- Specific actions (no s3:*)
- Resource-level scoping
- CloudWatch Logs enabled

## 🔧 Trust Policy Security Features

- Specific service principal
- Standard assume role action
- No wildcard principals

## ⚠️ Permissions Policy Considerations

- Uses {{{{ACCOUNT_ID}}}} placeholder - replace before deployment
- Uses {{{{REGION}}}} placeholder - replace with region
- No MFA requirement
- No IP restrictions

## ⚠️ Trust Policy Considerations

- Missing aws:SourceAccount condition
- Missing aws:SourceArn condition
- No MFA requirement (appropriate for service roles)

## 💡 Permissions Policy Refinement Suggestions

- Replace {{{{ACCOUNT_ID}}}} with your 12-digit account ID
- Replace {{{{REGION}}}} with region (e.g., us-east-1)
- Add aws:SourceIp condition for IP restrictions
- Add aws:MultiFactorAuthPresent for MFA
- Add S3 prefix restrictions if needed

## 💡 Trust Policy Refinement Suggestions

- Add aws:SourceAccount condition with account ID
- Add aws:SourceArn to restrict to specific Lambda
- Consider external ID if needed

## 🎯 Why Both Policies Are Essential

🔐 **Permissions Policy**: Defines WHAT actions the role can perform
🤝 **Trust Policy**: Defines WHO can assume the role

Together they create a complete, secure IAM role.

REMEMBER: Replace BUCKET_NAME, table names, and service principals based on the user's request. Calculate real scores. Use TWO separate statements for S3."""

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 8000,
        "system": system_prompt,  # Add system prompt here
        "messages": [{"role": "user", "content": [{"type": "text", "text": user_prompt}]}],
        "temperature": 0.1
    })

    try:
        response = bedrock.invoke_model(body=body, modelId=MODEL_ID)
        body_bytes = response.get('body').read()
        
        try:
            response_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            response_body = json.loads(body_bytes.decode('utf-8'))
        
        raw_response_text = response_body.get('content', [{}])[0].get('text', '')
        
        # Log what we got
        logging.info("=" * 80)
        logging.info("BEDROCK RESPONSE LENGTH: {} chars".format(len(raw_response_text)))
        logging.info("CHECKING FOR REQUIRED SECTIONS:")
        logging.info("  Has Permissions Score: {}".format("Permissions Policy Security Score:" in raw_response_text))
        logging.info("  Has Trust Score: {}".format("Trust Policy Security Score:" in raw_response_text))
        logging.info("  Has Overall Score: {}".format("Overall Security Score:" in raw_response_text))
        logging.info("=" * 80)
        
        return raw_response_text

    except Exception as e:
        logging.exception("❌ Bedrock failed")
        return f"Error: {str(e)}"


@tool
def refine_policy_from_bedrock(user_message: str, conversation_context: str) -> str:
    """Refine policy - same format as generation"""
    
    bedrock = get_bedrock_client()
    
    prompt = f"""User wants to refine their IAM policy.

Previous context:
{conversation_context}

User request:
{user_message}

If user asks a question: Answer it clearly.
If user wants changes: Update the policy and output the SAME format as before with ALL sections including scores."""

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4000,
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
        "temperature": 0.1
    })

    try:
        response = bedrock.invoke_model(body=body, modelId=MODEL_ID)
        body_bytes = response.get('body').read()
        
        try:
            response_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            response_body = json.loads(body_bytes.decode('utf-8'))
        
        return response_body.get('content', [{}])[0].get('text', '')

    except Exception as e:
        logging.exception("❌ Refinement failed")
        return f"Error: {str(e)}"