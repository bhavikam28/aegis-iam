from strands import Agent
from bedrock_tool import generate_policy_from_bedrock

SYSTEM_PROMPT = """You are Aegis, an AI agent for generating secure AWS IAM policies. 

Use the 'generate_policy_from_bedrock' tool to fulfill user requests. When you get the response from the tool, return the bedrock_response content directly to the user without any additional formatting or explanation."""

class PolicyAgent:
    def __init__(self):
        # Use Claude 3.7 Sonnet model
        self.agent = Agent(
            model="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
            system_prompt=SYSTEM_PROMPT,
            tools=[generate_policy_from_bedrock]
        )
    
    def run(self, user_request: str, service: str):
        prompt = f"Generate an IAM policy for: '{user_request}' for the AWS service '{service}'."
        result = self.agent(prompt)
        return result