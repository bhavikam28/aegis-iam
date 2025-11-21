# agent/policy_diff.py
"""
Policy Diff Generator
Compares two IAM policies and generates a diff showing what changed
"""
import json
from typing import Dict, List, Any, Set, Optional


class PolicyDiff:
    """Generate diffs between IAM policies"""
    
    @staticmethod
    def compare_policies(
        old_policy: Dict[str, Any],
        new_policy: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Compare two IAM policies and return what changed
        
        Returns:
            {
                'added_actions': List[str],
                'removed_actions': List[str],
                'added_resources': List[str],
                'removed_resources': List[str],
                'added_conditions': List[Dict],
                'removed_conditions': List[Dict],
                'changed_statements': List[Dict],
                'has_changes': bool
            }
        """
        old_statements = PolicyDiff._extract_statements(old_policy)
        new_statements = PolicyDiff._extract_statements(new_policy)
        
        old_actions = PolicyDiff._extract_actions(old_statements)
        new_actions = PolicyDiff._extract_actions(new_statements)
        
        old_resources = PolicyDiff._extract_resources(old_statements)
        new_resources = PolicyDiff._extract_resources(new_statements)
        
        old_conditions = PolicyDiff._extract_conditions(old_statements)
        new_conditions = PolicyDiff._extract_conditions(new_statements)
        
        added_actions = new_actions - old_actions
        removed_actions = old_actions - new_actions
        
        added_resources = new_resources - old_resources
        removed_resources = old_resources - new_resources
        
        # Compare conditions (simplified - just check if any changed)
        conditions_changed = old_conditions != new_conditions
        
        # Find changed statements
        changed_statements = PolicyDiff._find_changed_statements(old_statements, new_statements)
        
        has_changes = (
            len(added_actions) > 0 or
            len(removed_actions) > 0 or
            len(added_resources) > 0 or
            len(removed_resources) > 0 or
            conditions_changed or
            len(changed_statements) > 0
        )
        
        return {
            'added_actions': sorted(list(added_actions)),
            'removed_actions': sorted(list(removed_actions)),
            'added_resources': sorted(list(added_resources)),
            'removed_resources': sorted(list(removed_resources)),
            'added_conditions': list(new_conditions - old_conditions) if isinstance(new_conditions, set) else [],
            'removed_conditions': list(old_conditions - new_conditions) if isinstance(old_conditions, set) else [],
            'conditions_changed': conditions_changed,
            'changed_statements': changed_statements,
            'has_changes': has_changes,
            'unchanged_actions': sorted(list(old_actions & new_actions)),
            'unchanged_resources': sorted(list(old_resources & new_resources))
        }
    
    @staticmethod
    def _extract_statements(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract all statements from a policy"""
        if not isinstance(policy, dict):
            return []
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        return statements
    
    @staticmethod
    def _extract_actions(statements: List[Dict[str, Any]]) -> Set[str]:
        """Extract all actions from statements"""
        actions = set()
        
        for stmt in statements:
            if stmt.get('Effect') == 'Allow':
                action = stmt.get('Action', [])
                if isinstance(action, str):
                    actions.add(action)
                elif isinstance(action, list):
                    actions.update(action)
        
        return actions
    
    @staticmethod
    def _extract_resources(statements: List[Dict[str, Any]]) -> Set[str]:
        """Extract all resources from statements"""
        resources = set()
        
        for stmt in statements:
            resource = stmt.get('Resource', [])
            if isinstance(resource, str):
                resources.add(resource)
            elif isinstance(resource, list):
                resources.update(resource)
        
        return resources
    
    @staticmethod
    def _extract_conditions(statements: List[Dict[str, Any]]) -> Set[str]:
        """Extract conditions from statements (simplified - just keys)"""
        conditions = set()
        
        for stmt in statements:
            condition = stmt.get('Condition', {})
            if isinstance(condition, dict):
                conditions.update(condition.keys())
        
        return conditions
    
    @staticmethod
    def _find_changed_statements(
        old_statements: List[Dict[str, Any]],
        new_statements: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find statements that changed"""
        changed = []
        
        # Simple comparison - if statement count or structure changed
        if len(old_statements) != len(new_statements):
            changed.append({
                'type': 'statement_count_changed',
                'old_count': len(old_statements),
                'new_count': len(new_statements)
            })
        
        # Compare statement by statement (simplified)
        for idx, (old_stmt, new_stmt) in enumerate(zip(old_statements, new_statements)):
            if json.dumps(old_stmt, sort_keys=True) != json.dumps(new_stmt, sort_keys=True):
                changed.append({
                    'type': 'statement_modified',
                    'index': idx,
                    'old': old_stmt,
                    'new': new_stmt
                })
        
        return changed

