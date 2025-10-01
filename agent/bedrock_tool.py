import boto3
import json
from strands import tool

bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name='us-east-1')
# Use Claude 3.7 Sonnet (latest model)
MODEL_ID = 'us.anthropic.claude-3-7-sonnet-20250219-v1:0'

@tool
def generate_policy_from_bedrock(description: str, service: str) -> dict:
    prompt = f"""
    You are an expert AWS IAM security professional. Generate a secure, least-privilege IAM policy.
    
    **Follow these rules:**
    1. Be Specific: Do not use wildcards (*).
    2. Use ARNs: Use full ARNs, with placeholders if needed.
    3. Least Privilege: Only grant necessary permissions.
    4. Format Correctly: Return ONLY a JSON code block with the policy, followed by explanation.
    
    **Request:** "{description}"
    **Primary AWS Service:** "{service}"
    
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
    
    **Explanation:**
    [Your explanation here]
    """
    
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31", 
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
    })
    
    try:
        response = bedrock_runtime.invoke_model(body=body, modelId=MODEL_ID)
        response_body = json.loads(response.get('body').read())
        raw_response_text = response_body['content'][0]['text']
        
        # Return the raw response so the agent can process it
        return raw_response_text  # Return string directly, not in a dict
        
    except Exception as e:
        # Return a properly formatted fallback response
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
```

**Explanation:**
Fallback policy generated due to Bedrock error: {str(e)}. This is a basic S3 read policy for demonstration.
"""