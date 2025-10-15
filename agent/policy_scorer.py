"""
Policy Scoring Module
Provides reusable security scoring for IAM policies across Generate, Validate, and Audit features.
"""

import json
import logging
from typing import Dict, List, Tuple


def calculate_policy_scores(policy: dict, trust_policy: dict = None) -> Tuple[int, int, int]:
    """
    Calculate security scores for IAM policies.
    
    Args:
        policy: Permissions policy JSON
        trust_policy: Trust policy JSON (optional)
    
    Returns:
        Tuple of (permissions_score, trust_score, overall_score)
    """
    permissions_score = calculate_permissions_score(policy)
    trust_score = calculate_trust_score(trust_policy) if trust_policy else 100
    overall_score = int((permissions_score * 0.6) + (trust_score * 0.4))
    
    return permissions_score, trust_score, overall_score


def calculate_permissions_score(policy: dict) -> int:
    """
    Calculate security score for permissions policy.
    Starts at 100 and deducts points for security issues.
    """
    if not policy or 'Statement' not in policy:
        return 0
    
    score = 100
    issues = []
    
    for statement in policy['Statement']:
        # Check for wildcard actions
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        for action in actions:
            if action == '*':
                score -= 30
                issues.append("Universal wildcard action (*)")
                break
            elif '*' in action:
                score -= 20
                issues.append(f"Wildcard action ({action})")
                break
        
        # Check for wildcard resources
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        
        for resource in resources:
            if resource == '*':
                score -= 25
                issues.append("Universal wildcard resource (*)")
                break
            elif resource.endswith('/*'):
                # This is OK for object-level permissions
                continue
            elif '*' in resource:
                score -= 15
                issues.append(f"Partial wildcard resource ({resource})")
                break
        
        # Check for missing conditions
        if not statement.get('Condition'):
            score -= 5
            issues.append("Missing condition block")
        
        # Check for overly permissive effects
        if statement.get('Effect') == 'Allow' and statement.get('NotAction'):
            score -= 20
            issues.append("Uses NotAction (inverse logic)")
    
    # Check for placeholders
    policy_str = json.dumps(policy)
    if '{{ACCOUNT_ID}}' in policy_str or '{{REGION}}' in policy_str:
        score -= 10
        issues.append("Contains placeholders")
    
    # Ensure score is within bounds
    score = max(0, min(100, score))
    
    if issues:
        logging.info(f"Permissions policy issues found: {', '.join(issues)}")
    
    return score


def calculate_trust_score(trust_policy: dict) -> int:
    """
    Calculate security score for trust policy.
    Starts at 100 and deducts points for security issues.
    """
    if not trust_policy or 'Statement' not in trust_policy:
        return 0
    
    score = 100
    issues = []
    
    for statement in trust_policy['Statement']:
        principal = statement.get('Principal', {})
        
        # Check for wildcard principals
        if principal == '*':
            score -= 40
            issues.append("Universal wildcard principal (*)")
        elif isinstance(principal, dict):
            if principal.get('AWS') == '*':
                score -= 35
                issues.append("Wildcard AWS principal")
            elif principal.get('Service') == '*':
                score -= 30
                issues.append("Wildcard service principal")
        
        # Check for missing conditions
        condition = statement.get('Condition', {})
        if not condition:
            score -= 10
            issues.append("Missing condition block")
        else:
            # Check for specific security conditions
            string_equals = condition.get('StringEquals', {})
            
            if 'aws:SourceAccount' not in string_equals:
                score -= 8
                issues.append("Missing aws:SourceAccount condition")
            
            # Check for SourceArn
            has_source_arn = False
            for condition_type in ['ArnLike', 'StringLike', 'ArnEquals', 'StringEquals']:
                if condition.get(condition_type, {}).get('aws:SourceArn'):
                    has_source_arn = True
                    break
            
            if not has_source_arn:
                score -= 7
                issues.append("Missing aws:SourceArn condition")
        
        # Check for cross-account access without external ID
        if isinstance(principal, dict) and principal.get('AWS'):
            aws_principal = principal['AWS']
            if isinstance(aws_principal, str) and aws_principal.startswith('arn:aws:iam::'):
                if not condition.get('StringEquals', {}).get('sts:ExternalId'):
                    score -= 12
                    issues.append("Cross-account access without ExternalId")
    
    # Ensure score is within bounds
    score = max(0, min(100, score))
    
    if issues:
        logging.info(f"Trust policy issues found: {', '.join(issues)}")
    
    return score


def generate_score_breakdown(policy: dict, trust_policy: dict = None, 
                            permissions_score: int = 0, trust_score: int = 0) -> Dict:
    """
    Generate detailed score breakdown with positive points and improvements.
    
    Returns:
        Dict with structure:
        {
            "permissions": {"positive": [...], "improvements": [...]},
            "trust": {"positive": [...], "improvements": [...]}
        }
    """
    breakdown = {
        "permissions": {"positive": [], "improvements": []},
        "trust": {"positive": [], "improvements": []}
    }
    
    # Analyze permissions policy
    if policy and 'Statement' in policy:
        has_wildcards = False
        has_specific_actions = False
        has_conditions = False
        has_resource_scoping = False
        statement_count = len(policy['Statement'])
        
        for statement in policy['Statement']:
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            
            # Check for specific actions
            if not any('*' in action for action in actions):
                has_specific_actions = True
            else:
                has_wildcards = True
            
            # Check for resource scoping
            if not any(r == '*' for r in resources):
                has_resource_scoping = True
            
            if statement.get('Condition'):
                has_conditions = True
        
        # Positive points
        if has_specific_actions:
            breakdown["permissions"]["positive"].append("Uses specific actions instead of wildcards")
        if has_resource_scoping:
            breakdown["permissions"]["positive"].append("Resources are scoped to specific ARNs")
        if statement_count > 1:
            breakdown["permissions"]["positive"].append("Separates permissions into multiple focused statements")
        if has_conditions:
            breakdown["permissions"]["positive"].append("Includes conditional restrictions for enhanced security")
        if permissions_score >= 90:
            breakdown["permissions"]["positive"].append("Follows AWS least-privilege best practices")
        
        # Improvements
        if has_wildcards:
            breakdown["permissions"]["improvements"].append("Replace wildcard actions with specific permissions")
        if not has_resource_scoping:
            breakdown["permissions"]["improvements"].append("Scope resources to specific ARNs instead of wildcards")
        if not has_conditions:
            breakdown["permissions"]["improvements"].append("Add conditions like aws:SourceIp or aws:SourceVpc for additional security")
        
        policy_str = json.dumps(policy)
        if '{{ACCOUNT_ID}}' in policy_str or '{{REGION}}' in policy_str:
            breakdown["permissions"]["improvements"].append("Replace placeholders with actual account ID and region")
        
        if permissions_score < 80:
            breakdown["permissions"]["improvements"].append("Consider implementing MFA requirements for sensitive operations")
    
    # Analyze trust policy
    if trust_policy and 'Statement' in trust_policy:
        for statement in trust_policy['Statement']:
            principal = statement.get('Principal', {})
            condition = statement.get('Condition', {})
            
            # Positive points
            if isinstance(principal, dict):
                if 'Service' in principal and principal['Service'] != '*':
                    breakdown["trust"]["positive"].append("Uses specific service principal")
                if 'AWS' in principal and principal['AWS'] != '*':
                    breakdown["trust"]["positive"].append("Restricts access to specific AWS accounts")
            
            if condition:
                breakdown["trust"]["positive"].append("Includes conditional restrictions")
                if condition.get('StringEquals', {}).get('aws:SourceAccount'):
                    breakdown["trust"]["positive"].append("Validates source account for additional security")
            
            if trust_score >= 90:
                breakdown["trust"]["positive"].append("Follows AWS trust policy best practices")
            
            # Improvements
            if not condition:
                breakdown["trust"]["improvements"].append("Add aws:SourceAccount condition to restrict access")
                breakdown["trust"]["improvements"].append("Add aws:SourceArn condition for resource-level restrictions")
            else:
                if not condition.get('StringEquals', {}).get('aws:SourceAccount'):
                    breakdown["trust"]["improvements"].append("Add aws:SourceAccount condition")
                
                has_source_arn = any(
                    condition.get(ct, {}).get('aws:SourceArn')
                    for ct in ['ArnLike', 'StringLike', 'ArnEquals', 'StringEquals']
                )
                if not has_source_arn:
                    breakdown["trust"]["improvements"].append("Add aws:SourceArn condition")
            
            # Check for cross-account without external ID
            if isinstance(principal, dict) and principal.get('AWS'):
                aws_principal = principal['AWS']
                if isinstance(aws_principal, str) and aws_principal.startswith('arn:aws:iam::'):
                    if not condition.get('StringEquals', {}).get('sts:ExternalId'):
                        breakdown["trust"]["improvements"].append("Add ExternalId for cross-account access security")
    
    return breakdown


def generate_security_recommendations(policy: dict, trust_policy: dict = None, 
                                     permissions_score: int = 0, trust_score: int = 0) -> List[str]:
    """
    Generate actionable security recommendations based on policy analysis.
    
    Returns:
        List of recommendation strings
    """
    recommendations = []
    
    # Permissions policy recommendations
    if policy and 'Statement' in policy:
        for statement in policy['Statement']:
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            
            # Wildcard recommendations
            if any('*' in action for action in actions):
                recommendations.append("Replace wildcard actions with specific AWS service actions")
            
            if any(r == '*' for r in resources):
                recommendations.append("Specify exact resource ARNs instead of using wildcard (*)")
            
            # Condition recommendations
            if not statement.get('Condition'):
                recommendations.append("Add IP address restrictions using aws:SourceIp condition")
                recommendations.append("Consider adding MFA requirement using aws:MultiFactorAuthPresent")
    
    # Trust policy recommendations
    if trust_policy and 'Statement' in trust_policy:
        for statement in trust_policy['Statement']:
            condition = statement.get('Condition', {})
            
            if not condition:
                recommendations.append("Add aws:SourceAccount condition to trust policy")
                recommendations.append("Add aws:SourceArn condition for resource-level security")
    
    # Score-based recommendations
    if permissions_score < 70:
        recommendations.append("Review and tighten permissions to follow least-privilege principle")
    
    if trust_score < 70:
        recommendations.append("Strengthen trust policy with additional conditional restrictions")
    
    return recommendations[:5]  # Limit to top 5 recommendations
