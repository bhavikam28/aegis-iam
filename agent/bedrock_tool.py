import logging
import boto3
import json
from strands import tool

logging.basicConfig(level=logging.INFO)

bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
MODEL_ID = 'us.anthropic.claude-3-7-sonnet-20250219-v1:0'


@tool
def generate_policy_from_bedrock(description: str, service: str) -> str:
    """Generate an IAM policy using Bedrock.

    Returns the raw text response from the model (string). On failure, returns
    an error message explaining what went wrong.
    """

    prompt = f"""
You are an expert AWS IAM security architect with deep knowledge of all AWS services and their requirements.

**CORE PRINCIPLES:**
1. **Service-Aware**: You must deeply understand AWS services and their dependencies:
   
   For EVERY policy you generate:
   1. Identify the primary service(s) from the user's description
   2. Consider ALL dependencies the service needs to function:
      - Logging dependencies (CloudWatch Logs)
      - Storage dependencies (S3, EFS)
      - Network dependencies (VPC, Security Groups)
      - Container dependencies (ECR)
      - Authentication dependencies (IAM, STS)
      - Monitoring dependencies (CloudWatch)
      - State management (DynamoDB, Systems Manager)
   3. Include ALL necessary permissions for proper operation
   4. Document WHY each permission is needed in the explanation

   Examples of dependencies:
   - Lambda → CloudWatch Logs for execution logs
   - ECS Tasks → ECR for container images + CloudWatch for logs
   - EC2 → Systems Manager for management + CloudWatch for monitoring
   - API Gateway → CloudWatch for access logs + Lambda for integrations
   
2. **Least Privilege**: Grant only the minimum permissions needed, but grant ALL minimum permissions needed.

3. **No Placeholders**: If you lack AWS Account ID or Region, ASK the user. Never use placeholders like ACCOUNT_ID, REGION, YOUR_*, EXAMPLE_*, 123456789012, etc.

4. **Specific Resources**: Use full ARNs with actual resource names provided by the user.

**YOUR TASK:**
User Request: "{description}"
Primary Service: "{service}"

**CRITICAL: COMPREHENSIVE DETAILED EXPLANATIONS REQUIRED**

YOU MUST NEVER provide brief 2-3 sentence explanations.
ALWAYS provide a detailed, structured analysis with ALL of these components:

1. Service Overview (REQUIRED)
   - List ALL AWS services involved
   - Explain the PURPOSE of each service
   - Document how services INTERACT
   - Describe resource RELATIONSHIPS

2. Permission Details (REQUIRED for EACH service)
   - List and explain EACH action granted
   - Document resource scoping decisions
   - Explain WHY each permission is needed
   - Detail security restrictions applied

3. Security Implementation (REQUIRED)
   - Show how least privilege is enforced
   - Explain resource-level restrictions
   - Document permission separation
   - List security controls in place

4. Operational Context (REQUIRED)
   - Describe the complete workflow
   - Explain service dependencies
   - Detail access patterns
   - Document resource interactions

Any explanation missing these components is INCOMPLETE and must be expanded.

Example explanation structure:
"This policy enables [primary service] to interact with [dependent services] by:
1. [Service 1]:
   - Granted permissions: [actions]
   - Resource scope: [resources]
   - Purpose: [why needed]
   - Security controls: [restrictions]

2. [Service 2]:
   - Granted permissions...
   [etc]

Security Analysis:
- Follows least privilege by [specific examples]
- Implements security best practices:
  • [practice 1]
  • [practice 2]
  • [etc]"

**STEP 1: Analyze Requirements**
Think step-by-step:
1. What is the primary service? (e.g., Lambda, EC2, ECS)
2. What AWS services are mentioned? (e.g., S3, DynamoDB, SQS)
3. What actions are needed? (read, write, delete)
4. What supporting services are required for the primary service to function?

**STEP 2: Check for Required Information**
Do you have:
- AWS Account ID? (12-digit number)
- AWS Region? (e.g., us-east-1)
- All resource names? (bucket names, table names, queue names)

If ANY of these are missing, respond with:
"I'd be happy to create that policy! To generate a production-ready policy without placeholders, I need:
1. Your AWS Account ID (12-digit number)
2. AWS Region (e.g., us-east-1)
[List any other missing information]

Could you provide these details?"

**STEP 3: Generate Complete Policy**
If you have all information, generate a complete policy that includes:
1. Primary service permissions
2. All supporting service permissions needed for functionality
3. Proper resource ARN formats

**CRITICAL: S3 PERMISSION RULES**

For S3 permissions, you MUST follow these exact rules:

1. NEVER combine bucket-level and object-level actions in the same statement
2. s3:ListBucket is a bucket-level operation and MUST be in its own statement
3. s3:GetObject, s3:PutObject are object-level operations and MUST be in a separate statement
4. Resource ARNs MUST match the operation level:
   - Bucket operations: ONLY use `arn:aws:s3:::bucket-name`
   - Object operations: ONLY use `arn:aws:s3:::bucket-name/*`

INCORRECT (DO NOT USE):
```json
{
  "Sid": "AllowS3Access",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": ["arn:aws:s3:::bucket-name", "arn:aws:s3:::bucket-name/*"]
}
```

CORRECT (MUST USE):
```json
[
  {
    "Sid": "AllowS3BucketList",
    "Effect": "Allow",
    "Action": ["s3:ListBucket"],
    "Resource": ["arn:aws:s3:::bucket-name"]
  },
  {
    "Sid": "AllowS3ObjectOperations",
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::bucket-name/*"]
  }
]
```

This separation is NOT optional - it is REQUIRED for proper S3 access control.
- DynamoDB table: `arn:aws:dynamodb:{{region}}:{{account}}:table/table-name`
- Lambda function: `arn:aws:lambda:{{region}}:{{account}}:function:function-name`
- CloudWatch Logs: `arn:aws:logs:{{region}}:{{account}}:log-group:log-group-name:*`

**OUTPUT FORMAT:**
```json
{{
  "Version": "2012-10-17",
  "Statement": [
    // All statements needed for complete functionality
  ]
}}

Detailed Policy Analysis:
1. Service Overview
   - List all AWS services involved
   - Explain why each service is needed
   - Break down permissions by service

2. Permission Details
   [For each service, explain]:
   - Specific actions granted
   - Resource scope and restrictions
   - Why these permissions are required
   - Any security controls applied

3. Security Analysis
   - How it follows least privilege
   - Resource-level restrictions
   - Statement separation (especially for S3)
   - Security best practices followed

4. Operational Context
   - How the services interact
   - Required service dependencies
   - Expected access patterns

5. Security Recommendations
   - Potential security enhancements
   - Additional conditions to consider
   - Service-specific security controls
CRITICAL REMINDER:

Think holistically about service dependencies
Include ALL permissions needed for the service to work
Never use placeholders - ask for information instead
"""

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 3000,
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
    })

    try:
        response = bedrock_runtime.invoke_model(body=body, modelId=MODEL_ID)
        body_bytes = response.get('body').read()
        
        try:
            response_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            response_body = json.loads(body_bytes.decode('utf-8'))
        
        raw_response_text = response_body.get('content', [{}])[0].get('text', '')
        return raw_response_text

    except Exception as e:
        logging.exception("Bedrock invocation failed")
        return "I apologize, but I encountered an error while generating your policy: " + str(e) + ". This could be due to temporary AWS Bedrock service issues, network connectivity problems, or model access permissions. Please wait a moment and try again, or verify your AWS credentials have bedrock:InvokeModel permission."