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
    a small fallback policy and logs the exception.
    """

    prompt = f"""
You are an expert AWS IAM security professional. Generate a secure, least-privilege IAM policy.

Follow these rules:
1. Be Specific: Do not use wildcards (*).
2. Use ARNs: Use full ARNs, with placeholders if needed.
3. Least Privilege: Only grant necessary permissions.
4. Format Correctly: Return ONLY a JSON code block with the policy, followed by explanation.

Request: "{description}"
Primary AWS Service: "{service}"

Format your response exactly like this:
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

Explanation:
[Explain what the policy does in 2-3 sentences, focusing on the permissions granted]

Next Steps:
[Provide 3-5 specific, actionable suggestions for how the user could enhance this policy based on their specific use case.]
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
        # Return a simple fallback policy string (not meant for production use)
        return f"""```json
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::example-bucket/*"
      ]
    }}
  ]
}}
Explanation:
Fallback policy generated due to Bedrock error: {str(e)}. This is a basic S3 read policy for demonstration.
Next Steps:
Contact support to resolve the connection issue.
```"""