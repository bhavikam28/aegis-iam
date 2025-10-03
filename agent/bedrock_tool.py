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
You are an expert AWS IAM security professional. Generate a secure, least-privilege IAM policy.

CRITICAL RULES:
1. NEVER use placeholder values like ${{AWS::Region}}, <YOUR_ACCOUNT_ID>, REPLACE_WITH_, YOUR_, EXAMPLE_, or 123456789012
2. If you need AWS Account ID, Region, or resource names, ASK the user first
3. Only generate a policy when you have ALL required real values
4. Be Specific: Do not use wildcards (*) unless absolutely necessary
5. Use ARNs: Use full ARNs with actual values provided by the user
6. Least Privilege: Only grant necessary permissions
7. Format Correctly: Return ONLY a JSON code block with the policy, followed by explanation

Request: "{description}"
Primary AWS Service: "{service}"

If you are missing required information (AWS Account ID, Region, resource names), respond with:
"I'd be happy to create that policy! To generate a production-ready policy without placeholders, I need:
1. Your AWS Account ID (12-digit number)
2. AWS Region where resources are deployed (e.g., us-east-1)
3. [Any other specific information needed]

Could you provide these details?"

If you have all required information, format your response EXACTLY like this:
```json
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Action": [...],
      "Resource": [...]
    }}
  ]
}}
```

**Explanation:**
[Explain what the policy does in 2-3 sentences, focusing on the permissions granted and why it's secure]

**Next Steps:**
[Provide 3-5 specific, actionable suggestions for how the user could enhance this policy based on their specific use case. Each suggestion should be 5-15 words.]
"""

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
    })

    try:
        response = bedrock_runtime.invoke_model(body=body, modelId=MODEL_ID)
        # response.get('body') may be a StreamingBody; read() returns bytes
        body_bytes = response.get('body').read()
        try:
            response_body = json.loads(body_bytes)
        except Exception:
            # If bytes, decode and try again
            response_body = json.loads(body_bytes.decode('utf-8'))

        raw_response_text = response_body.get('content', [{}])[0].get('text', '')
        return raw_response_text

    except Exception as e:
        logging.exception("Bedrock invocation failed")
        # Return a helpful error message instead of a bad policy
        return f"""I apologize, but I encountered an error while generating your policy:

**Error:** {str(e)}

This could be due to:
- Temporary AWS Bedrock service issues
- Network connectivity problems
- Model access permissions

**What to do:**
1. Wait a moment and try again
2. Verify your AWS credentials have bedrock:InvokeModel permission
3. Check that Claude 3.7 Sonnet model access is enabled in AWS Bedrock console
4. If the problem persists, contact support with this error message

I'm ready to help once the service connection is restored!"""