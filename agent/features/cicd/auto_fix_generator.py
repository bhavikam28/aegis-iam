# agent/auto_fix_generator.py
"""
Auto-Fix Code Generator
Generates ready-to-apply code fixes for IAM policy issues
"""
from typing import Dict, List, Any, Optional
import json


class AutoFixGenerator:
    """Generate code fixes for IAM policy issues"""
    
    @staticmethod
    def generate_fixes(
        policy: Dict[str, Any],
        findings: List[Dict[str, Any]],
        policy_format: str,
        source_file: str
    ) -> List[Dict[str, Any]]:
        """
        Generate auto-fix code for policy issues
        
        Returns:
            List of fix objects with code snippets
        """
        fixes = []
        
        for finding in findings:
            finding_type = finding.get('type', '').lower()
            severity = finding.get('severity', '')
            
            # Only generate fixes for high/critical issues
            if severity not in ['Critical', 'High']:
                continue
            
            if 'wildcard' in finding_type or 'wildcard' in finding.get('title', '').lower():
                fix = AutoFixGenerator._fix_wildcard_permissions(
                    policy, finding, policy_format, source_file
                )
                if fix:
                    fixes.append(fix)
            
            elif 'unused' in finding_type or 'unused' in finding.get('title', '').lower():
                fix = AutoFixGenerator._fix_unused_permissions(
                    policy, finding, policy_format, source_file
                )
                if fix:
                    fixes.append(fix)
            
            elif 'resource' in finding_type and 'wildcard' in finding.get('description', '').lower():
                fix = AutoFixGenerator._fix_wildcard_resources(
                    policy, finding, policy_format, source_file
                )
                if fix:
                    fixes.append(fix)
        
        return fixes
    
    @staticmethod
    def _fix_wildcard_permissions(
        policy: Dict[str, Any],
        finding: Dict[str, Any],
        policy_format: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """Generate fix for wildcard permissions"""
        wildcard_actions = finding.get('actions', [])
        if not wildcard_actions:
            return None
        
        # Get actual used actions from CloudTrail if available
        used_actions = finding.get('cloudtrail_used_actions', [])
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        fixed_statements = []
        for stmt in statements:
            fixed_stmt = stmt.copy()
            actions = stmt.get('Action', [])
            
            if isinstance(actions, str):
                actions = [actions]
            
            # Replace wildcards with specific actions
            fixed_actions = []
            for action in actions:
                if '*' in action or action == '*:*':
                    # If we have CloudTrail data, use those
                    if used_actions:
                        # Find matching used actions
                        service = action.split(':')[0] if ':' in action else '*'
                        matching_used = [
                            a for a in used_actions
                            if a.startswith(service + ':') or service == '*'
                        ]
                        if matching_used:
                            fixed_actions.extend(matching_used[:10])  # Limit to 10
                        else:
                            # Can't auto-fix without usage data
                            continue
                    else:
                        # Suggest common actions for the service
                        if action == '*:*':
                            fixed_actions.append('s3:GetObject')  # Placeholder
                        elif action.startswith('s3:'):
                            fixed_actions.append('s3:GetObject')
                            fixed_actions.append('s3:PutObject')
                else:
                    fixed_actions.append(action)
            
            if fixed_actions:
                fixed_stmt['Action'] = fixed_actions if len(fixed_actions) > 1 else fixed_actions[0]
                fixed_statements.append(fixed_stmt)
        
        if not fixed_statements:
            return None
        
        fixed_policy = policy.copy()
        fixed_policy['Statement'] = fixed_statements
        
        return {
            'finding_id': finding.get('id', 'unknown'),
            'title': finding.get('title', ''),
            'issue': 'Wildcard Permissions',
            'before_code': AutoFixGenerator._format_code(policy, policy_format, source_file),
            'after_code': AutoFixGenerator._format_code(fixed_policy, policy_format, source_file),
            'explanation': f'Replaced wildcard actions with specific permissions based on CloudTrail usage'
        }
    
    @staticmethod
    def _fix_unused_permissions(
        policy: Dict[str, Any],
        finding: Dict[str, Any],
        policy_format: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """Generate fix for unused permissions"""
        unused_actions = finding.get('actions', [])
        if not unused_actions:
            return None
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        fixed_statements = []
        for stmt in statements:
            fixed_stmt = stmt.copy()
            actions = stmt.get('Action', [])
            
            if isinstance(actions, str):
                actions = [actions]
            
            # Remove unused actions
            fixed_actions = [a for a in actions if a not in unused_actions]
            
            if fixed_actions:
                fixed_stmt['Action'] = fixed_actions if len(fixed_actions) > 1 else fixed_actions[0]
                fixed_statements.append(fixed_stmt)
        
        if not fixed_statements:
            return None
        
        fixed_policy = policy.copy()
        fixed_policy['Statement'] = fixed_statements
        
        return {
            'finding_id': finding.get('id', 'unknown'),
            'title': finding.get('title', ''),
            'issue': 'Unused Permissions',
            'before_code': AutoFixGenerator._format_code(policy, policy_format, source_file),
            'after_code': AutoFixGenerator._format_code(fixed_policy, policy_format, source_file),
            'explanation': f'Removed {len(unused_actions)} unused permissions that were never used in CloudTrail'
        }
    
    @staticmethod
    def _fix_wildcard_resources(
        policy: Dict[str, Any],
        finding: Dict[str, Any],
        policy_format: str,
        source_file: str
    ) -> Optional[Dict[str, Any]]:
        """Generate fix for wildcard resources"""
        wildcard_resources = finding.get('resources', [])
        if not wildcard_resources:
            return None
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        fixed_statements = []
        for stmt in statements:
            fixed_stmt = stmt.copy()
            resources = stmt.get('Resource', [])
            
            if isinstance(resources, str):
                resources = [resources]
            
            # Suggest more specific resources
            fixed_resources = []
            for resource in resources:
                if '*' in resource:
                    # Suggest specific bucket/object pattern
                    if 's3' in resource.lower():
                        # Replace wildcard with specific bucket pattern
                        fixed_resources.append(resource.replace('*', 'my-bucket/*'))
                    elif 'dynamodb' in resource.lower():
                        fixed_resources.append(resource.replace('*', 'my-table'))
                    else:
                        # Keep but add comment
                        fixed_resources.append(resource)
                else:
                    fixed_resources.append(resource)
            
            fixed_stmt['Resource'] = fixed_resources if len(fixed_resources) > 1 else fixed_resources[0]
            fixed_statements.append(fixed_stmt)
        
        fixed_policy = policy.copy()
        fixed_policy['Statement'] = fixed_statements
        
        return {
            'finding_id': finding.get('id', 'unknown'),
            'title': finding.get('title', ''),
            'issue': 'Wildcard Resources',
            'before_code': AutoFixGenerator._format_code(policy, policy_format, source_file),
            'after_code': AutoFixGenerator._format_code(fixed_policy, policy_format, source_file),
            'explanation': 'Replaced wildcard resources with more specific ARN patterns'
        }
    
    @staticmethod
    def _format_code(
        policy: Dict[str, Any],
        policy_format: str,
        source_file: str
    ) -> str:
        """Format policy as code based on format"""
        if policy_format == 'terraform':
            return f'policy = jsonencode({json.dumps(policy, indent=2)})'
        elif policy_format == 'cloudformation':
            return f'PolicyDocument: {json.dumps(policy, indent=2)}'
        elif policy_format == 'json':
            return json.dumps(policy, indent=2)
        else:
            return json.dumps(policy, indent=2)

