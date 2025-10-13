"""
Dynamic input validation using AI agent
No hardcoded values - agent validates using its knowledge
"""

import logging
import boto3
import json

logging.basicConfig(level=logging.INFO)

# Lazy load Bedrock client
bedrock_runtime = None
MODEL_ID = 'us.anthropic.claude-3-7-sonnet-20250219-v1:0'

def get_bedrock_client():
    """Lazy load bedrock client"""
    global bedrock_runtime
    if bedrock_runtime is None:
        logging.info("🔧 Initializing Bedrock client for validation...")
        bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
        logging.info("✅ Bedrock client initialized")
    return bedrock_runtime


def validate_user_input_with_ai(user_description: str) -> dict:
    """
    Use AI agent to validate user input dynamically
    
    The agent checks for:
    - Invalid AWS regions
    - Invalid account IDs
    - Invalid resource names
    - Any other AWS-specific formatting issues
    
    Returns:
        dict with 'valid' (bool), 'issues' (list), and 'message' (str)
    """
    
    logging.info(f"🔍 Starting AI validation for input: {user_description[:100]}...")
    
    bedrock = get_bedrock_client()
    
    validation_prompt = f"""You are an AWS IAM expert validator. Your job is to analyze user input and identify ANY invalid AWS-specific information.

**USER INPUT TO VALIDATE:**
"{user_description}"

**YOUR TASK:**
Carefully analyze the input and check for ANY invalid AWS-specific information, including but not limited to:

1. **AWS Regions**: Check if any mentioned regions are invalid
   - Valid format: lowercase letters, hyphens, numbers (e.g., us-east-1, ap-south-1)
   - Common mistakes: "US, India, 25", "US East", "America", "Mumbai", "Virginia"
   
2. **AWS Account IDs**: Check if any mentioned account IDs are invalid
   - Valid format: exactly 12 digits
   - Common mistakes: "12345" (5 digits), "123" (3 digits), any non-12-digit number
   
3. **ARN Formats**: Check if any ARN patterns look incorrect
   - Valid format: arn:aws:service:region:account:resource
   
4. **Service Names**: Check if service names are valid AWS services
   
5. **Resource Names**: Check if resource naming follows AWS conventions
   - S3 buckets: lowercase, no underscores, 3-63 chars
   - DynamoDB tables: alphanumeric and certain special chars only
   
6. **Any Other AWS-Specific Issues**: Use your AWS knowledge to identify problems

**CRITICAL RULES:**
- Be STRICT about account IDs - they MUST be exactly 12 digits
- Be STRICT about regions - they MUST use AWS region codes (us-east-1, not "US" or "India")
- If you find ANY issues, set has_issues to true
- Provide clear, helpful suggestions

**RESPONSE FORMAT:**
Return a JSON object with this EXACT structure:

{{
  "has_issues": true or false,
  "issues": [
    {{
      "type": "invalid_region" | "invalid_account_id" | "invalid_arn" | "invalid_service" | "invalid_resource_name" | "other",
      "found": "the exact text that's invalid",
      "problem": "clear explanation of what's wrong",
      "suggestion": "how to fix it"
    }}
  ],
  "severity": "critical" | "warning" | "info",
  "user_friendly_message": "A conversational message explaining all issues to the user"
}}

**EXAMPLE 1:**
Input: "Lambda in US, India, 25 with account 12345"
Output:
{{
  "has_issues": true,
  "issues": [
    {{
      "type": "invalid_region",
      "found": "US, India, 25",
      "problem": "This isn't a valid AWS region format. AWS regions use codes like 'us-east-1', 'ap-south-1', 'eu-west-1'.",
      "suggestion": "Did you mean: us-east-1 (US East), ap-south-1 (India), or eu-west-1 (Europe)? Or I can use {{{{REGION}}}} as a placeholder."
    }},
    {{
      "type": "invalid_account_id",
      "found": "12345",
      "problem": "AWS Account IDs must be exactly 12 digits. You provided only 5 digits.",
      "suggestion": "AWS Account IDs look like: 123456789012. If you don't have it, I can use {{{{ACCOUNT_ID}}}} as a placeholder."
    }}
  ],
  "severity": "critical",
  "user_friendly_message": "⚠️ I found some issues with your input:\\n\\n**Invalid Region:** 'US, India, 25' isn't a valid AWS region. AWS regions use codes like us-east-1, ap-south-1, eu-west-1.\\n\\n**Invalid Account ID:** '12345' must be exactly 12 digits (you provided 5).\\n\\nPlease provide correct values, or let me know if you'd like me to use placeholders!"
}}

**EXAMPLE 2:**
Input: "S3 bucket My_Bucket_Name!"
Output:
{{
  "has_issues": true,
  "issues": [
    {{
      "type": "invalid_resource_name",
      "found": "My_Bucket_Name!",
      "problem": "S3 bucket names must be lowercase, cannot contain underscores or exclamation marks.",
      "suggestion": "Try: my-bucket-name (lowercase with hyphens)"
    }}
  ],
  "severity": "warning",
  "user_friendly_message": "⚠️ **S3 Bucket Name Issue**: 'My_Bucket_Name!' isn't a valid S3 bucket name. S3 buckets must be lowercase and can only use hyphens (not underscores or special characters).\\n\\nSuggestion: 'my-bucket-name'\\n\\nShould I use a placeholder instead?"
}}

**CRITICAL RULES:**
- If NO issues found, return: {{"has_issues": false, "issues": [], "severity": "info", "user_friendly_message": ""}}
- ONLY flag things that are CLEARLY invalid based on AWS standards
- Don't flag missing information (like no account ID) - that's okay
- Be helpful and provide clear suggestions
- Use your AWS expertise to catch issues I haven't explicitly listed

Now validate the user input above and return ONLY the JSON response."""

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2000,
        "messages": [{"role": "user", "content": [{"type": "text", "text": validation_prompt}]}],
        "temperature": 0.3  # Lower temperature for more consistent validation
    })

    try:
        logging.info("📡 Calling Bedrock for validation...")
        response = bedrock.invoke_model(body=body, modelId=MODEL_ID)
        body_bytes = response.get('body').read()
        
        try:
            response_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            response_body = json.loads(body_bytes.decode('utf-8'))
        
        raw_response = response_body.get('content', [{}])[0].get('text', '')
        logging.info(f"🤖 AI validation response: {raw_response[:200]}...")
        
        # Extract JSON from response (in case agent added extra text)
        import re
        json_match = re.search(r'\{[\s\S]*\}', raw_response)
        if json_match:
            validation_result = json.loads(json_match.group(0))
            logging.info(f"✅ Parsed validation result: has_issues={validation_result.get('has_issues')}, issues_count={len(validation_result.get('issues', []))}")
        else:
            # Fallback if JSON parsing fails
            logging.warning("⚠️ Failed to parse validation response - assuming valid")
            return {
                'valid': True,  # Assume valid if we can't validate
                'issues': [],
                'message': ''
            }
        
        # Convert AI response to our format
        has_issues = validation_result.get('has_issues', False)
        issues = validation_result.get('issues', [])
        
        result = {
            'valid': not has_issues,
            'issues': issues,
            'message': validation_result.get('user_friendly_message', ''),
            'severity': validation_result.get('severity', 'info')
        }
        
        if not result['valid']:
            logging.warning(f"❌ Validation FAILED: {len(issues)} issues found")
        else:
            logging.info("✅ Validation PASSED")
        
        return result
        
    except Exception as e:
        logging.error(f"❌ Validation error: {e}", exc_info=True)
        # On error, assume input is valid (fail open)
        return {
            'valid': True,
            'issues': [],
            'message': ''
        }


def should_validate_input(user_description: str) -> bool:
    """
    Determine if input needs validation
    
    Only validate if user mentions specific AWS resources/details
    """
    # Keywords that suggest user is providing specific details
    validation_keywords = [
        'region', 'account', 'arn:', 'bucket', 'table',
        'us-', 'eu-', 'ap-', 'id:', 'number',
        'india', 'virginia', 'oregon', 'mumbai',  # Region names
        'arn:aws:', '123', '456', '789'  # Account ID patterns
    ]
    
    description_lower = user_description.lower()
    
    for keyword in validation_keywords:
        if keyword in description_lower:
            return True
    
    # Check for numeric patterns that might be account IDs
    import re
    if re.search(r'\b\d{3,}\b', user_description):  # 3+ digit numbers
        return True
    
    return False