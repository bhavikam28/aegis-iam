# agent/pr_comment_generator.py
"""
PR Comment Generator
Generates formatted comments for GitHub/GitLab PRs
"""
from typing import Dict, List, Any


class PRCommentGenerator:
    """Generate PR comments from policy analysis"""
    
    @staticmethod
    def generate_comment(analysis: Dict[str, Any]) -> str:
        """
        Generate a formatted PR comment
        
        Args:
            analysis: Result from CICDAnalyzer.analyze_pr_changes()
                     Can be either the full result dict or just the analysis dict
        
        Returns:
            Formatted markdown comment string
        """
        # Handle both full result and just analysis dict
        if 'analysis' in analysis:
            # Full result dict with 'success' and 'analysis' keys
            if not analysis.get('success'):
                return PRCommentGenerator._generate_error_comment(analysis)
            analysis_data = analysis.get('analysis', {})
        else:
            # Just the analysis dict itself
            analysis_data = analysis
        policies_found = analysis_data.get('policies_found', 0)
        findings = analysis_data.get('findings', [])
        recommendations = analysis_data.get('recommendations', [])
        risk_score = analysis_data.get('risk_score', 0)
        summary = analysis_data.get('summary', '')
        policies_analyzed = analysis_data.get('policies_analyzed', [])
        
        # Build comment
        comment = "## 🔒 IAM Policy Security Analysis\n\n"
        comment += f"{summary}\n\n"
        
        # Risk Score
        risk_emoji = "🟢" if risk_score < 30 else "🟡" if risk_score < 70 else "🔴"
        comment += f"### Security Score: {risk_score}/100 {risk_emoji}\n\n"
        
        # Policies Found
        comment += f"**Policies Analyzed:** {policies_found}\n\n"
        
        # Findings
        if findings:
            comment += "### ⚠️ Security Findings\n\n"
            
            # Group by severity
            critical = [f for f in findings if f.get('severity') == 'Critical']
            high = [f for f in findings if f.get('severity') == 'High']
            medium = [f for f in findings if f.get('severity') == 'Medium']
            low = [f for f in findings if f.get('severity') == 'Low']
            
            if critical:
                comment += "#### 🔴 Critical Issues\n\n"
                for finding in critical:
                    comment += PRCommentGenerator._format_finding(finding)
            
            if high:
                comment += "#### 🟠 High Priority Issues\n\n"
                for finding in high:
                    comment += PRCommentGenerator._format_finding(finding)
            
            if medium:
                comment += "#### 🟡 Medium Priority Issues\n\n"
                for finding in medium:
                    comment += PRCommentGenerator._format_finding(finding)
            
            if low:
                comment += "#### 🔵 Low Priority Issues\n\n"
                for finding in low:
                    comment += PRCommentGenerator._format_finding(finding)
        
        # Policy Details
        if policies_analyzed:
            comment += "\n### 📋 Policy Details\n\n"
            for policy in policies_analyzed:
                comment += PRCommentGenerator._format_policy_summary(policy)
        
        # Recommendations
        if recommendations:
            comment += "\n### 💡 Recommendations\n\n"
            for idx, rec in enumerate(recommendations[:10], 1):  # Limit to 10
                comment += f"{idx}. {rec}\n"
        
        # CloudTrail Analysis Summary
        cloudtrail_summary = PRCommentGenerator._generate_cloudtrail_summary(policies_analyzed)
        if cloudtrail_summary:
            comment += f"\n### 📊 CloudTrail Analysis (Last 90 Days)\n\n{cloudtrail_summary}\n"
        
        # Policy Diffs (if any)
        policy_diffs = analysis_data.get('policy_diffs', [])
        if policy_diffs:
            comment += "\n### 📊 Policy Changes Detected\n\n"
            for diff in policy_diffs:
                comment += PRCommentGenerator._format_policy_diff(diff)
        
        # Auto-Fixes (if any)
        auto_fixes = analysis_data.get('auto_fixes', [])
        if auto_fixes:
            comment += "\n### 🔧 Auto-Fix Available\n\n"
            comment += "The following fixes can be automatically applied:\n\n"
            for fix in auto_fixes[:5]:  # Limit to 5 fixes
                comment += PRCommentGenerator._format_auto_fix(fix)
        
        # Action Required
        has_critical = analysis_data.get('has_critical_issues', False)
        if has_critical:
            comment += "\n---\n\n"
            comment += "🚨 **BLOCKING:** Critical security issues detected. This PR cannot be merged until issues are resolved.\n"
        elif risk_score >= 70:
            comment += "\n---\n\n"
            comment += "⚠️ **Action Required:** High-risk issues detected. Please review and address before merging.\n"
        elif risk_score >= 30:
            comment += "\n---\n\n"
            comment += "ℹ️ **Review Recommended:** Consider addressing the issues above before merging.\n"
        else:
            comment += "\n---\n\n"
            comment += "✅ **Ready to Merge:** No critical issues detected.\n"
        
        # Footer
        comment += "\n---\n\n"
        comment += "*This analysis was performed by [Aegis IAM](https://github.com/your-repo/aegis-iam)*\n"
        
        return comment
    
    @staticmethod
    def _format_finding(finding: Dict[str, Any]) -> str:
        """Format a single finding"""
        title = finding.get('title', 'Unknown Issue')
        description = finding.get('description', '')
        finding_type = finding.get('type', '')
        
        formatted = f"**{title}**\n"
        formatted += f"- Type: `{finding_type}`\n"
        formatted += f"- Description: {description}\n"
        
        # Add specific details
        if finding.get('actions'):
            actions = finding['actions'][:5]  # Limit to 5
            formatted += f"- Affected Actions: `{', '.join(actions)}`\n"
        
        if finding.get('resources'):
            resources = finding['resources'][:3]  # Limit to 3
            formatted += f"- Affected Resources: `{', '.join(resources)}`\n"
        
        formatted += "\n"
        return formatted
    
    @staticmethod
    def _format_policy_summary(policy: Dict[str, Any]) -> str:
        """Format policy summary"""
        name = policy.get('policy_name', 'Unknown')
        policy_type = policy.get('policy_type', 'managed_policy')
        risk_score = policy.get('risk_score', 0)
        source = policy.get('source_file', '')
        
        formatted = f"#### Policy: `{name}` ({policy_type})\n"
        formatted += f"- **Risk Score:** {risk_score}/100\n"
        formatted += f"- **Source:** `{source}`\n"
        
        # CloudTrail stats
        cloudtrail = policy.get('cloudtrail_analysis', {})
        if cloudtrail:
            requested = policy.get('requested_actions_count', 0)
            used = policy.get('used_actions_count', 0)
            unused = policy.get('unused_actions_count', 0)
            
            formatted += f"- **Requested Actions:** {requested}\n"
            formatted += f"- **Used Actions:** {used}\n"
            if unused > 0:
                formatted += f"- **Unused Actions:** {unused} ⚠️\n"
        
        formatted += "\n"
        return formatted
    
    @staticmethod
    def _generate_cloudtrail_summary(policies_analyzed: List[Dict]) -> str:
        """Generate CloudTrail analysis summary"""
        total_requested = sum(p.get('requested_actions_count', 0) for p in policies_analyzed)
        total_used = sum(p.get('used_actions_count', 0) for p in policies_analyzed)
        total_unused = sum(p.get('unused_actions_count', 0) for p in policies_analyzed)
        
        if total_requested == 0:
            return ""
        
        summary = f"- **Total Actions Requested:** {total_requested}\n"
        summary += f"- **Actions Actually Used:** {total_used}\n"
        
        if total_unused > 0:
            summary += f"- **Unused Actions:** {total_unused} ({total_unused * 100 // total_requested}% of requested)\n"
            summary += f"  - Consider removing unused permissions to follow least-privilege principle\n"
        
        return summary
    
    @staticmethod
    def _format_policy_diff(diff: Dict[str, Any]) -> str:
        """Format policy diff visualization"""
        policy_name = diff.get('policy_name', 'Unknown Policy')
        file_path = diff.get('file_path', 'unknown')
        
        formatted = f"#### Policy: `{policy_name}` (`{file_path}`)\n\n"
        
        # Added Actions
        added_actions = diff.get('added_actions', [])
        if added_actions:
            formatted += "**✅ Added Permissions:**\n"
            for action in added_actions[:10]:  # Limit to 10
                formatted += f"- `{action}` (new)\n"
            formatted += "\n"
        
        # Removed Actions
        removed_actions = diff.get('removed_actions', [])
        if removed_actions:
            formatted += "**❌ Removed Permissions:**\n"
            for action in removed_actions[:10]:  # Limit to 10
                formatted += f"- `{action}` (removed"
                # Try to add context if available
                formatted += " - was unused" if len(removed_actions) > 0 else ""
                formatted += ")\n"
            formatted += "\n"
        
        # Unchanged Actions
        unchanged_actions = diff.get('unchanged_actions', [])
        if unchanged_actions and len(unchanged_actions) <= 20:  # Only show if not too many
            formatted += "**➡️ Unchanged Permissions:**\n"
            formatted += f"- {len(unchanged_actions)} permissions kept (actively used)\n"
            formatted += "\n"
        
        # Added Resources
        added_resources = diff.get('added_resources', [])
        if added_resources:
            formatted += "**✅ Added Resources:**\n"
            for resource in added_resources[:5]:  # Limit to 5
                formatted += f"- `{resource}`\n"
            formatted += "\n"
        
        # Removed Resources
        removed_resources = diff.get('removed_resources', [])
        if removed_resources:
            formatted += "**❌ Removed Resources:**\n"
            for resource in removed_resources[:5]:  # Limit to 5
                formatted += f"- `{resource}`\n"
            formatted += "\n"
        
        return formatted
    
    @staticmethod
    def _format_auto_fix(fix: Dict[str, Any]) -> str:
        """Format auto-fix code block"""
        title = fix.get('title', 'Fix Available')
        issue = fix.get('issue', 'Security Issue')
        explanation = fix.get('explanation', '')
        before_code = fix.get('before_code', '')
        after_code = fix.get('after_code', '')
        
        formatted = f"#### 🔧 {issue}: {title}\n\n"
        formatted += f"{explanation}\n\n"
        
        # Before/After code comparison
        if before_code and after_code:
            formatted += "**Before:**\n"
            formatted += f"```json\n{before_code}\n```\n\n"
            formatted += "**After (Suggested Fix):**\n"
            formatted += f"```json\n{after_code}\n```\n\n"
        
        formatted += "---\n\n"
        return formatted
    
    @staticmethod
    def _generate_error_comment(analysis: Dict[str, Any]) -> str:
        """Generate error comment"""
        errors = analysis.get('errors', [])
        comment = "## ⚠️ IAM Policy Analysis Error\n\n"
        comment += "Unable to analyze IAM policies in this PR.\n\n"
        
        if errors:
            comment += "**Errors:**\n"
            for error in errors[:5]:  # Limit to 5 errors
                comment += f"- {error}\n"
        
        return comment

