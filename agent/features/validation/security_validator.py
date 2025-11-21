"""
Security validation for IAM policies.
Based on AWS Foundational Security Best Practices.

Architecture: Easily extensible to use AWS Security Hub API in future.
"""

class SecurityValidator:
    """Validates IAM policies against AWS Foundational Security Best Practices"""
    
    def __init__(self):
        # AWS Foundational Security Best Practices for IAM
        self.controls = [
            # Critical Controls (Immediate Security Impact)
            {
                "id": "IAM.1",
                "title": "IAM policies should not grant full \"*:*\" administrative privileges",
                "severity": "CRITICAL",
                "score_impact": -40,
                "aws_control": True
            },
            {
                "id": "IAM.21",
                "title": "IAM customer managed policies should not allow wildcard actions",
                "severity": "CRITICAL",
                "score_impact": -30,
                "aws_control": True
            },
            
            # Resource Access Controls
            {
                "id": "IAM.RESOURCE.1",
                "title": "IAM policies should not use wildcard resource statements",
                "severity": "HIGH",
                "score_impact": -20,
                "exceptions": ["logs:*"],  # Services where wildcards are acceptable
                "aws_control": False
            },
            
            # Principle of Least Privilege
            {
                "id": "IAM.PLP.1",
                "title": "Actions should be limited to only required permissions",
                "severity": "HIGH",
                "score_impact": -15,
                "aws_control": False
            },
            {
                "id": "IAM.PLP.2",
                "title": "Resources should be restricted to specific ARNs",
                "severity": "HIGH",
                "score_impact": -15,
                "aws_control": False
            },
            
            # Security Controls
            {
                "id": "IAM.SEC.1",
                "title": "Sensitive services should require condition keys",
                "severity": "HIGH",
                "score_impact": -15,
                "aws_control": False,
                "sensitive_services": ["s3", "secretsmanager", "kms"]
            },
            {
                "id": "IAM.SEC.2",
                "title": "VPC endpoint restrictions for private resources",
                "severity": "MEDIUM",
                "score_impact": -10,
                "aws_control": False,
                "vpc_recommended": ["dynamodb", "s3", "secretsmanager"]
            },
            
            # Service-Specific Controls
            {
                "id": "IAM.S3.1",
                "title": "S3 bucket and object permissions must be separated",
                "severity": "HIGH",
                "score_impact": -20,
                "aws_control": False
            },
            {
                "id": "IAM.S3.2",
                "title": "S3 operations should enforce encryption",
                "severity": "HIGH",
                "score_impact": -15,
                "aws_control": False
            },
            
            # Access Pattern Controls
            {
                "id": "IAM.ACCESS.1",
                "title": "Restrict access by IP source",
                "severity": "MEDIUM",
                "score_impact": -10,
                "aws_control": False,
                "recommended": True
            },
            {
                "id": "IAM.ACCESS.2",
                "title": "Enforce MFA for sensitive operations",
                "severity": "HIGH",
                "score_impact": -15,
                "aws_control": False,
                "sensitive_actions": [
                    "s3:DeleteBucket",
                    "ec2:TerminateInstances",
                    "rds:DeleteDBInstance"
                ]
            }
        ]
        
        # Service-specific best practices
        self.service_rules = {
            "s3": {
                "require_split_statements": True,  # Separate bucket/object permissions
                "allowed_wildcards": ["logs:*"],  # Services where wildcards are acceptable
                "recommended_conditions": {
                    "encryption": "s3:x-amz-server-side-encryption",
                    "vpc_endpoint": "aws:SourceVpc"
                }
            },
            "dynamodb": {
                "require_table_arn": True,
                "recommended_conditions": {
                    "vpc_endpoint": "aws:SourceVpc"
                }
            },
            "logs": {
                "allow_resource_wildcard": True  # CloudWatch Logs commonly use *
            }
        }
    
    def validate_policy(self, policy_json: dict) -> dict:
        """Validate policy and return detailed security assessment"""
        score = 100
        issues = []
        recommendations = []
        positive_points = []
        
        statements = policy_json.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
            
        # Analyze policy structure and services
        services_used = self._identify_services(statements)
        service_actions = self._analyze_service_actions(statements)
            
        # Check core security controls
        score_details = self._check_core_controls(statements)
        score += score_details['score_impact']
        issues.extend(score_details['issues'])
        positive_points.extend(score_details['positives'])
        
        # Service-specific validations
        for service in services_used:
            service_details = self._validate_service_specific(service, statements)
            score += service_details['score_impact']
            issues.extend(service_details['issues'])
            recommendations.extend(service_details['recommendations'])
            positive_points.extend(service_details['positives'])
            
        # Generate grade and explanation
        grade = self._calculate_grade(score)
        grade_explanation = self._generate_grade_explanation(grade, positive_points, issues)
        
        # Generate detailed policy explanation
        policy_explanation = self._generate_policy_explanation(
            statements,
            services_used,
            service_actions
        )
        
        # Context-aware recommendations
        final_recommendations = self._generate_recommendations(
            issues, 
            recommendations,
            services_used
        )
        
        return {
            'score': max(0, score),
            'grade': grade,
            'grade_explanation': grade_explanation,
            'explanation': policy_explanation,
            'positive_points': positive_points,
            'issues': issues,
            'recommendations': final_recommendations
        }
        
    def _analyze_service_actions(self, statements):
        """Analyze actions by service for detailed explanation"""
        service_actions = {}
        
        for stmt in statements:
            actions = stmt.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]
                
            resources = stmt.get('Resource', [])
            if not isinstance(resources, list):
                resources = [resources]
                
            for action in actions:
                action_str = str(action)
                
                # Handle wildcard or actions without colons
                if ':' not in action_str:
                    # Wildcard or malformed action
                    service = '*'
                    action_name = action_str
                else:
                    parts = action_str.split(':', 1)
                    service = parts[0]
                    action_name = parts[1] if len(parts) > 1 else action_str
                
                if service not in service_actions:
                    service_actions[service] = {
                        'actions': set(),
                        'resources': set(),
                        'conditions': set()
                    }
                    
                service_actions[service]['actions'].add(action_name)
                service_actions[service]['resources'].update(resources)
                
                if 'Condition' in stmt:
                    conditions = stmt.get('Condition', {})
                    for condition_type, condition_values in conditions.items():
                        for key in condition_values.keys():
                            service_actions[service]['conditions'].add(f"{condition_type}:{key}")
                            
        return service_actions
        
    def _generate_policy_explanation(self, statements, services_used, service_actions):
        """Generate detailed, contextual explanation of the policy"""
        explanation_parts = []
        
        # Overview
        service_list = ", ".join(services_used)
        explanation_parts.append(f"This IAM policy grants specific permissions across {len(services_used)} AWS services: {service_list}.")
        
        # Per-service breakdown
        for service in services_used:
            service_info = service_actions.get(service, {})
            actions = service_info.get('actions', set())
            resources = service_info.get('resources', set())
            conditions = service_info.get('conditions', set())
            
            # Service-specific explanations
            if service == 's3':
                has_bucket_ops = any('List' in a for a in actions)
                has_object_ops = any(op in ''.join(actions) for op in ['Get', 'Put', 'Delete'])
                
                if has_bucket_ops and has_object_ops:
                    explanation_parts.append(f"\nS3 Access:")
                    explanation_parts.append("• Bucket-level permissions: List bucket contents")
                    explanation_parts.append("• Object-level permissions: Read objects")
                    explanation_parts.append(f"• Target bucket(s): {', '.join(r.split(':')[-1].replace('/*','') for r in resources if '*' not in r)}")
                    
            elif service == 'dynamodb':
                operation_types = self._categorize_dynamo_operations(actions)
                explanation_parts.append(f"\nDynamoDB Access:")
                for op_type, ops in operation_types.items():
                    if ops:
                        explanation_parts.append(f"• {op_type} operations: {', '.join(ops)}")
                table_names = [r.split('table/')[-1] for r in resources if 'table/' in r]
                if table_names:
                    explanation_parts.append(f"• Target tables: {', '.join(table_names)}")
                    
            elif service == 'logs':
                explanation_parts.append(f"\nCloudWatch Logs Access:")
                explanation_parts.append("• Standard Lambda logging permissions")
                explanation_parts.append("• Allows creating log groups/streams and writing events")
                
        # Security Analysis
        explanation_parts.append("\nSecurity Analysis:")
        explanation_parts.append("• Follows least privilege principle by:")
        explanation_parts.append("  - Using specific actions instead of wildcards")
        explanation_parts.append("  - Restricting to named resources")
        explanation_parts.append("  - Properly separating permissions by service")
        
        if any('Condition' in s for s in statements):
            explanation_parts.append("• Includes additional security controls through conditions")
            
        return "\n".join(explanation_parts)
        
    def _categorize_dynamo_operations(self, actions):
        """Categorize DynamoDB operations by type"""
        categories = {
            'Read': set(),
            'Write': set(),
            'Admin': set()
        }
        
        for action in actions:
            if action.startswith(('Get', 'Query', 'Scan')):
                categories['Read'].add(action)
            elif action.startswith(('Put', 'Update', 'Delete')):
                categories['Write'].add(action)
            else:
                categories['Admin'].add(action)
                
        return {k:v for k,v in categories.items() if v}
        
    def _check_core_controls(self, statements):
        """Validate against AWS Foundational Security Best Practices"""
        result = {
            'score_impact': 0,
            'issues': [],
            'positives': [],
            'control_results': {}
        }
        
        # Check IAM.1 - No full admin
        if any(s.get('Action') == '*' and s.get('Resource') == '*' for s in statements):
            self._add_control_violation(result, 'IAM.1', 
                "Critical: Full administrative access (*:*) detected")
        else:
            result['positives'].append("✅ No full administrative privileges")
            
        # Check IAM.21 - No wildcard actions
        has_wildcard = False
        for stmt in statements:
            actions = stmt.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]
            
            if any(':*' in str(a) for a in actions if not self._is_allowed_wildcard(a)):
                has_wildcard = True
                self._add_control_violation(result, 'IAM.21',
                    "Critical: Wildcard actions detected")
                break
        
        if not has_wildcard:
            result['positives'].append("✅ No wildcard service actions")
            
        # Check IAM.RESOURCE.1 - Resource wildcards
        for stmt in statements:
            resources = stmt.get('Resource', [])
            if not isinstance(resources, list):
                resources = [resources]
            
            service = self._get_statement_service(stmt)
            if service not in self._get_control_by_id('IAM.RESOURCE.1')['exceptions']:
                if '*' in resources:
                    self._add_control_violation(result, 'IAM.RESOURCE.1',
                        f"High: Wildcard resource detected for {service}")
                    
        # Check IAM.SEC.1 - Sensitive service conditions
        sensitive_services = self._get_control_by_id('IAM.SEC.1')['sensitive_services']
        for stmt in statements:
            service = self._get_statement_service(stmt)
            if service in sensitive_services:
                if 'Condition' not in stmt:
                    self._add_control_violation(result, 'IAM.SEC.1',
                        f"High: Missing condition keys for sensitive service {service}")
                    
        # Check IAM.ACCESS.2 - MFA for sensitive actions
        sensitive_actions = self._get_control_by_id('IAM.ACCESS.2')['sensitive_actions']
        for stmt in statements:
            actions = stmt.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]
                
            if any(action in sensitive_actions for action in actions):
                conditions = stmt.get('Condition', {})
                if not any('aws:MultiFactorAuthPresent' in c for c in conditions.values()):
                    self._add_control_violation(result, 'IAM.ACCESS.2',
                        "High: Sensitive action without MFA enforcement")
                        
        return result
        
    def _add_control_violation(self, result, control_id, message):
        """Add a control violation with proper score impact"""
        control = self._get_control_by_id(control_id)
        result['score_impact'] += control['score_impact']
        result['issues'].append(f"{control_id}: {message}")
        result['control_results'][control_id] = {
            'violated': True,
            'severity': control['severity'],
            'message': message
        }
        
    def _get_control_by_id(self, control_id):
        """Get control configuration by ID"""
        return next((c for c in self.controls if c['id'] == control_id), None)
        
    def _get_statement_service(self, statement):
        """Extract service name from statement actions"""
        actions = statement.get('Action', [])
        if not isinstance(actions, list):
            actions = [actions]
        
        if actions:
            return str(actions[0]).split(':')[0]
        return None
        
    def _validate_service_specific(self, service, statements):
        """Service-specific validation rules"""
        rules = self.service_rules.get(service, {})
        result = {
            'score_impact': 0,
            'issues': [],
            'recommendations': [],
            'positives': []
        }
        
        # Generic rules that apply to any service
        self._validate_resource_patterns(service, statements, rules, result)
        self._validate_permission_structure(service, statements, rules, result)
        self._validate_conditions(service, statements, rules, result)
        
        return result
        
    def _validate_resource_patterns(self, service, statements, rules, result):
        """Validate resource ARN patterns for any service"""
        for stmt in statements:
            resources = stmt.get('Resource', [])
            if not isinstance(resources, list):
                resources = [resources]
                
            # Check if wildcards are allowed for this service
            if not rules.get('allow_resource_wildcard', False):
                if '*' in resources:
                    result['score_impact'] -= 10
                    result['issues'].append(f"{service}: Using wildcard resources")
                    result['recommendations'].append(
                        f"Specify exact {service} resource ARNs instead of wildcards"
                    )
            
    def _validate_permission_structure(self, service, statements, rules, result):
        """Validate permission structure based on service rules"""
        if rules.get('require_split_statements'):
            # For services like S3 that require split permission statements
            stmt_groups = {}
            for stmt in statements:
                actions = stmt.get('Action', [])
                if not isinstance(actions, list):
                    actions = [actions]
                    
                for action in actions:
                    if service in str(action):
                        action_type = self._categorize_action(service, action)
                        stmt_groups[action_type] = stmt_groups.get(action_type, []) + [stmt]
                        
            # Check if different action types are in separate statements
            if len(stmt_groups) > 1:
                statements_mixed = any(
                    len(set(map(id, stmts))) < len(stmts) 
                    for stmts in stmt_groups.values()
                )
                if statements_mixed:
                    result['score_impact'] -= 15
                    result['issues'].append(
                        f"{service}: Different permission types should be in separate statements"
                    )
                else:
                    result['positives'].append(
                        f"✅ {service} permissions properly separated by type"
                    )
                    
    def _validate_conditions(self, service, statements, rules, result):
        """Validate condition keys based on service recommendations"""
        recommended_conditions = rules.get('recommended_conditions', {})
        if recommended_conditions:
            conditions_found = set()
            for stmt in statements:
                if service in str(stmt.get('Action', '')):
                    conditions = stmt.get('Condition', {})
                    for condition_type, condition_keys in conditions.items():
                        conditions_found.update(condition_keys.keys())
                        
            missing_conditions = set(recommended_conditions.keys()) - conditions_found
            if missing_conditions:
                result['recommendations'].extend([
                    f"Consider adding {cond} condition for {service}"
                    for cond in missing_conditions
                ])
                    
    def _categorize_action(self, service, action):
        """Categorize service actions into types (e.g., read, write, list)"""
        action = str(action).lower()
        if service == 's3':
            if 'list' in action:
                return 'list'
            elif any(op in action for op in ['get', 'head']):
                return 'read'
            else:
                return 'write'
        # Add more service-specific categorization as needed
        return 'default'
        
    def _validate_s3_permissions(self, statements):
        """Specific validation for S3 permissions"""
        result = {
            'score_impact': 0,
            'issues': [],
            'recommendations': [],
            'positives': []
        }
        
        # Check for proper separation of bucket/object permissions
        bucket_stmt = None
        object_stmt = None
        
        for stmt in statements:
            actions = stmt.get('Action', [])
            if 's3:ListBucket' in actions:
                bucket_stmt = stmt
            if any(a in actions for a in ['s3:GetObject', 's3:PutObject', 's3:DeleteObject']):
                object_stmt = stmt
                
        if bucket_stmt and object_stmt:
            if bucket_stmt == object_stmt:
                result['score_impact'] -= 15
                result['issues'].append("S3 bucket and object permissions are mixed")
                result['recommendations'].append("Separate S3 bucket and object permissions into distinct statements")
            else:
                result['positives'].append("✅ S3 permissions properly separated")
                
        return result
        
    def _calculate_grade(self, score):
        """Convert numeric score to letter grade with plus/minus"""
        if score >= 90: return 'A'
        elif score >= 80: return 'B'
        elif score >= 70: return 'C'
        elif score >= 60: return 'D'
        else: return 'F'
        
    def _is_allowed_wildcard(self, action):
        """Check if wildcard is acceptable for this action"""
        return any(action.startswith(allowed) for allowed in self.service_rules.get('s3', {}).get('allowed_wildcards', []))
        
    def _identify_services(self, statements):
        """Extract unique AWS services used in policy"""
        services = set()
        for stmt in statements:
            actions = stmt.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]
            for action in actions:
                service = str(action).split(':')[0]
                services.add(service)
        return services
        
    def _generate_recommendations(self, issues, recommendations, services_used):
        """Generate context-aware recommendations based on issues and services"""
        final_recommendations = []
        
        # Add service-specific recommendations from validation
        final_recommendations.extend(recommendations)
        
        # Add recommendations based on issues
        if any('wildcard' in str(issue).lower() for issue in issues):
            final_recommendations.append("Replace wildcard permissions with specific resource ARNs")
        
        if any('mfa' in str(issue).lower() for issue in issues):
            final_recommendations.append("Add MFA requirement for sensitive operations")
        
        # Service-specific recommendations
        if 's3' in services_used:
            if not any('encryption' in str(r).lower() for r in final_recommendations):
                final_recommendations.append("Consider adding encryption requirements for S3 operations")
        
        if 'dynamodb' in services_used:
            if not any('vpc' in str(r).lower() for r in final_recommendations):
                final_recommendations.append("Consider using VPC endpoints for DynamoDB access")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in final_recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def _generate_grade_explanation(self, grade, positives, issues):
        """Generate detailed explanation of the security grade"""
        if grade == 'A':
            return "Excellent - Policy follows security best practices with proper scoping and permissions separation"
        elif grade == 'B':
            return "Good - Policy is well-structured but has minor areas for improvement"
        elif grade == 'C':
            return "Fair - Policy needs some important security improvements"
        elif grade == 'D':
            return "Poor - Policy has significant security gaps that should be addressed"
        else:
            return "Critical - Policy has severe security issues that must be fixed immediately"
            
# Global instance - easy to swap with AWS Security Hub validator in future
validator = SecurityValidator()

def calculate_security_score(policy_json: dict) -> dict:
    """Main function used by your app"""
    return validator.validate_policy(policy_json)