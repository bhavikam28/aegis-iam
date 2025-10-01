"""
Security validation for IAM policies.
Based on AWS Foundational Security Best Practices.

Architecture: Easily extensible to use AWS Security Hub API in future.
"""

class SecurityValidator:
    """Validates IAM policies against security best practices"""
    
    def __init__(self):
        self.controls = [
            {
                "id": "IAM.1",
                "title": "No full administrative privileges",
                "severity": "HIGH",
            },
            {
                "id": "IAM.21",
                "title": "No wildcard service actions",
                "severity": "LOW",
            },
            {
                "id": "RESOURCE_WILDCARD",
                "title": "No wildcard resources",
                "severity": "MEDIUM",
            },
            {
                "id": "CONDITIONS",
                "title": "Use conditions to restrict access",
                "severity": "MEDIUM",
            }
        ]
    
    def validate_policy(self, policy_json: dict) -> dict:
        """Validate policy and return security score"""
        score = 100
        issues = []
        
        statements = policy_json.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        # Check IAM.1: No full admin
        if any(s.get('Action') == '*' and s.get('Resource') == '*' for s in statements):
            score -= 35
            issues.append("IAM.1: Full administrative access detected")
        
        # Check IAM.21: No wildcard actions
        for stmt in statements:
            actions = stmt.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]
            if any(':*' in str(a) for a in actions):
                score -= 10
                issues.append("IAM.21: Wildcard service actions detected")
                break
        
        # Check wildcard resources
        if any(s.get('Resource') == '*' for s in statements):
            score -= 20
            issues.append("Resource wildcards detected")
        
        # Check for conditions
        if not any('Condition' in s for s in statements):
            score -= 10
            issues.append("No conditions to restrict access")
        
        return {
            'score': max(0, score),
            'issues': issues,
            'recommendations': [f"Fix: {issue}" for issue in issues]
        }

# Global instance - easy to swap with AWS Security Hub validator in future
validator = SecurityValidator()

def calculate_security_score(policy_json: dict) -> dict:
    """Main function used by your app"""
    return validator.validate_policy(policy_json)