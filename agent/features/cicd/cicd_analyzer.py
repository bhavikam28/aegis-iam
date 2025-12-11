# agent/cicd_analyzer.py
"""
CI/CD Policy Analyzer
Compares requested policies against CloudTrail historical usage
Generates security analysis and recommendations for PR comments
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from features.cicd.policy_extractor import PolicyExtractor
from features.cicd.policy_diff import PolicyDiff
from features.cicd.auto_fix_generator import AutoFixGenerator
# Note: We don't need full ValidatorAgent for CI/CD - just policy validation logic
from core.fastmcp_client import get_mcp_client

logging.basicConfig(level=logging.INFO)


class CICDAnalyzer:
    """Analyze IAM policies in CI/CD context"""
    
    def __init__(self, aws_region: str = "us-east-1"):
        self.extractor = PolicyExtractor()
        self.aws_region = aws_region
        self._cloudtrail_client = None  # Lazy-load to save memory
    
    @property
    def cloudtrail_client(self):
        """Lazy-load CloudTrail client only when needed"""
        if self._cloudtrail_client is None:
            logging.info("🔄 Lazy-loading CloudTrail MCP client...")
            self._cloudtrail_client = get_mcp_client('aws-cloudtrail')
        return self._cloudtrail_client
    
    def analyze_pr_changes(
        self,
        changed_files: List[Dict[str, str]],
        lookback_days: int = 90
    ) -> Dict[str, Any]:
        """
        Analyze IAM policy changes in a PR
        
        Args:
            changed_files: List of {path: str, content: str, status: str}
            lookback_days: Days of CloudTrail history to analyze
        
        Returns:
            {
                'success': bool,
                'analysis': {
                    'policies_found': int,
                    'policies_analyzed': List[Dict],
                    'findings': List[Dict],
                    'recommendations': List[str],
                    'risk_score': int,
                    'summary': str
                },
                'errors': List[str]
            }
        """
        all_policies = []
        errors = []
        
        # Extract policies from all changed files
        for file_info in changed_files:
            file_path = file_info.get('path', '')
            file_content = file_info.get('content', '')
            file_status = file_info.get('status', 'modified')  # added, modified, deleted
            
            if file_status == 'deleted':
                continue
            
            try:
                result = self.extractor.extract_policies_from_file(file_path, file_content)
                if result['success']:
                    for policy in result['policies']:
                        policy['file_status'] = file_status
                        all_policies.append(policy)
                else:
                    if result.get('errors'):
                        errors.extend(result['errors'])
            except Exception as e:
                errors.append(f"Error processing {file_path}: {str(e)}")
                logging.error(f"Error extracting from {file_path}: {e}")
        
        if not all_policies:
            return {
                'success': False,
                'analysis': {
                    'policies_found': 0,
                    'policies_analyzed': [],
                    'findings': [],
                    'recommendations': ['No IAM policies found in changed files'],
                    'risk_score': 0,
                    'summary': 'No IAM policies detected in this PR'
                },
                'errors': errors
            }
        
        # Analyze each policy
        analyzed_policies = []
        all_findings = []
        all_recommendations = []
        all_auto_fixes = []
        policy_diffs = []
        total_risk_score = 0
        has_critical_issues = False
        
        for policy in all_policies:
            policy_analysis = self._analyze_single_policy(policy, lookback_days)
            analyzed_policies.append(policy_analysis)
            
            if policy_analysis.get('findings'):
                all_findings.extend(policy_analysis['findings'])
                # Check for critical issues
                critical_findings = [f for f in policy_analysis['findings'] if f.get('severity') == 'Critical']
                if critical_findings:
                    has_critical_issues = True
            
            if policy_analysis.get('recommendations'):
                all_recommendations.extend(policy_analysis['recommendations'])
            
            # Generate auto-fixes
            policy_doc = policy.get('policy', {})
            if policy_doc and isinstance(policy_doc, dict):
                policy_format = policy.get('format', 'json')
                source_file = policy.get('file_path', 'unknown')
                fixes = AutoFixGenerator.generate_fixes(
                    policy_doc,
                    policy_analysis.get('findings', []),
                    policy_format,
                    source_file
                )
                if fixes:
                    all_auto_fixes.extend(fixes)
            
            # Generate policy diff if this is a modified file
            if policy.get('file_status') == 'modified' and policy.get('old_policy'):
                diff = PolicyDiff.compare_policies(
                    policy.get('old_policy', {}),
                    policy_doc
                )
                if diff.get('has_changes'):
                    diff['policy_name'] = policy.get('name', 'unknown')
                    diff['file_path'] = policy.get('file_path', 'unknown')
                    policy_diffs.append(diff)
            
            total_risk_score += policy_analysis.get('risk_score', 0)
        
        avg_risk_score = total_risk_score // len(analyzed_policies) if analyzed_policies else 0
        
        # Generate summary
        summary = self._generate_summary(analyzed_policies, all_findings)
        
        return {
            'success': True,
            'analysis': {
                'policies_found': len(all_policies),
                'policies_analyzed': analyzed_policies,
                'findings': all_findings,
                'recommendations': list(set(all_recommendations)),  # Remove duplicates
                'risk_score': avg_risk_score,
                'summary': summary,
                'has_critical_issues': has_critical_issues,
                'auto_fixes': all_auto_fixes,
                'policy_diffs': policy_diffs
            },
            'errors': errors
        }
    
    def _analyze_single_policy(
        self,
        policy: Dict[str, Any],
        lookback_days: int
    ) -> Dict[str, Any]:
        """Analyze a single policy"""
        policy_doc = policy.get('policy', {})
        policy_name = policy.get('name', 'unknown')
        policy_type = policy.get('type', 'managed_policy')
        
        # Validate policy structure
        if not isinstance(policy_doc, dict) or 'Statement' not in policy_doc:
            return {
                'policy_name': policy_name,
                'policy_type': policy_type,
                'risk_score': 100,
                'findings': [{
                    'severity': 'High',
                    'type': 'Invalid Policy',
                    'title': 'Invalid Policy Structure',
                    'description': 'Policy document is missing required Statement field'
                }],
                'recommendations': ['Fix policy document structure'],
                'cloudtrail_analysis': None
            }
        
        # Extract actions and resources
        statements = policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        requested_actions = set()
        requested_resources = set()
        
        for stmt in statements:
            if stmt.get('Effect') == 'Allow':
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                requested_actions.update(actions)
                
                resources = stmt.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                requested_resources.update(resources)
        
        # Query CloudTrail for historical usage
        cloudtrail_analysis = self._query_cloudtrail_usage(
            list(requested_actions),
            lookback_days
        )
        
        # Compare requested vs actual
        unused_actions = requested_actions - set(cloudtrail_analysis.get('used_actions', []))
        
        # Generate findings
        findings = []
        recommendations = []
        
        # Check for unused permissions
        if unused_actions:
            findings.append({
                'severity': 'Medium',
                'type': 'Unused Permissions',
                'title': f'{len(unused_actions)} Unused Permissions Detected',
                'description': f'The following permissions are granted but not used in the last {lookback_days} days: {", ".join(list(unused_actions)[:5])}',
                'actions': list(unused_actions)
            })
            recommendations.append(f'Consider removing unused permissions: {", ".join(list(unused_actions)[:3])}')
        
        # Check for wildcards
        wildcard_actions = [a for a in requested_actions if '*' in a or ':*' in a]
        if wildcard_actions:
            findings.append({
                'severity': 'High',
                'type': 'Wildcard Permissions',
                'title': 'Wildcard Permissions Detected',
                'description': f'Policy contains wildcard actions: {", ".join(wildcard_actions)}',
                'actions': wildcard_actions
            })
            recommendations.append('Replace wildcard permissions with specific actions')
        
        # Check for resource wildcards
        wildcard_resources = [r for r in requested_resources if '*' in r or 'arn:aws:*' in r]
        if wildcard_resources:
            findings.append({
                'severity': 'High',
                'type': 'Wildcard Resources',
                'title': 'Wildcard Resources Detected',
                'description': f'Policy contains wildcard resources: {", ".join(wildcard_resources[:3])}',
                'resources': wildcard_resources
            })
            recommendations.append('Restrict resources to specific ARNs instead of wildcards')
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(findings, len(unused_actions), len(wildcard_actions))
        
        return {
            'policy_name': policy_name,
            'policy_type': policy_type,
            'source_file': policy.get('source'),
            'risk_score': risk_score,
            'findings': findings,
            'recommendations': recommendations,
            'cloudtrail_analysis': cloudtrail_analysis,
            'requested_actions_count': len(requested_actions),
            'used_actions_count': len(cloudtrail_analysis.get('used_actions', [])),
            'unused_actions_count': len(unused_actions)
        }
    
    def _query_cloudtrail_usage(
        self,
        actions: List[str],
        lookback_days: int
    ) -> Dict[str, Any]:
        """Query CloudTrail for actual usage of these actions"""
        if not self.cloudtrail_client:
            logging.warning("CloudTrail MCP client not available")
            return {
                'used_actions': [],
                'total_events': 0,
                'analysis_period_days': lookback_days
            }
        
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=lookback_days)
            
            # Query CloudTrail for events matching these actions
            result = self.cloudtrail_client.call_tool('lookup_events', {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'max_results': 1000
            })
            
            if result.get('success'):
                events_data = result.get('data', {})
                content = events_data.get('content', []) if isinstance(events_data, dict) else []
                
                used_actions = set()
                total_events = 0
                
                # Parse events
                for item in content:
                    if isinstance(item, dict) and 'text' in item:
                        try:
                            import json
                            event_data = json.loads(item['text'])
                            if isinstance(event_data, dict):
                                event_name = event_data.get('eventName') or event_data.get('EventName')
                                if event_name:
                                    # Convert event name to IAM action format
                                    # e.g., "GetObject" -> "s3:GetObject"
                                    service = event_data.get('eventSource', '').split('.')[0].lower()
                                    if service and event_name:
                                        iam_action = f"{service}:{event_name}"
                                        used_actions.add(iam_action)
                                    total_events += 1
                        except:
                            pass
                
                return {
                    'used_actions': list(used_actions),
                    'total_events': total_events,
                    'analysis_period_days': lookback_days
                }
        
        except Exception as e:
            logging.error(f"Error querying CloudTrail: {e}")
        
        return {
            'used_actions': [],
            'total_events': 0,
            'analysis_period_days': lookback_days
        }
    
    def _calculate_risk_score(
        self,
        findings: List[Dict],
        unused_count: int,
        wildcard_count: int
    ) -> int:
        """Calculate risk score (0-100, higher is worse)"""
        score = 0
        
        for finding in findings:
            severity = finding.get('severity', 'Low')
            if severity == 'Critical':
                score += 30
            elif severity == 'High':
                score += 20
            elif severity == 'Medium':
                score += 10
            else:
                score += 5
        
        # Add penalties
        score += min(unused_count * 2, 20)  # Max 20 points for unused
        score += min(wildcard_count * 15, 30)  # Max 30 points for wildcards
        
        return min(score, 100)
    
    def _generate_summary(
        self,
        analyzed_policies: List[Dict],
        findings: List[Dict]
    ) -> str:
        """Generate human-readable summary"""
        total_policies = len(analyzed_policies)
        critical_count = sum(1 for f in findings if f.get('severity') == 'Critical')
        high_count = sum(1 for f in findings if f.get('severity') == 'High')
        medium_count = sum(1 for f in findings if f.get('severity') == 'Medium')
        
        if critical_count > 0:
            return f"⚠️ **Critical Issues Found**: {critical_count} critical, {high_count} high, {medium_count} medium severity issues detected. Review required before merging."
        elif high_count > 0:
            return f"🔍 **Security Review Recommended**: {high_count} high and {medium_count} medium severity issues found. Consider addressing before merging."
        elif medium_count > 0:
            return f"ℹ️ **Minor Issues Detected**: {medium_count} medium severity issues found. Review recommended."
        else:
            return f"✅ **No Issues Found**: All {total_policies} policies analyzed with no security issues detected."

