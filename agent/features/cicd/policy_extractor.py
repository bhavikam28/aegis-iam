# agent/policy_extractor.py
"""
Policy Extractor Service
Extracts IAM policies from various Infrastructure as Code formats
Supports: Terraform, CloudFormation, AWS CDK, and raw JSON
"""
import json
import re
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

logging.basicConfig(level=logging.INFO)


class PolicyExtractor:
    """Extract IAM policies from various code formats"""
    
    def __init__(self):
        self.supported_formats = ['terraform', 'cloudformation', 'cdk', 'json']
    
    def extract_policies_from_file(self, file_path: str, file_content: str) -> Dict[str, Any]:
        """
        Extract IAM policies from a file based on its extension and content
        
        Returns:
            {
                'success': bool,
                'policies': List[Dict],  # List of extracted policies
                'format': str,  # Detected format
                'errors': List[str]  # Any errors encountered
            }
        """
        file_ext = Path(file_path).suffix.lower()
        file_name = Path(file_path).name.lower()
        
        # Detect format
        if file_ext == '.tf' or file_name.endswith('.tf'):
            return self.extract_from_terraform(file_content, file_path)
        elif file_ext in ['.yaml', '.yml'] or 'cloudformation' in file_name or 'cfn' in file_name:
            return self.extract_from_cloudformation(file_content, file_path)
        elif file_ext in ['.ts', '.js', '.py'] and ('cdk' in file_name or 'cdk' in file_content[:500]):
            return self.extract_from_cdk(file_content, file_path, file_ext)
        elif file_ext == '.json':
            return self.extract_from_json(file_content, file_path)
        else:
            # Try to auto-detect
            return self._auto_detect_and_extract(file_content, file_path)
    
    def extract_from_terraform(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract IAM policies from Terraform files"""
        policies = []
        errors = []
        
        try:
            # Pattern 1: aws_iam_policy resource
            policy_pattern = r'resource\s+"aws_iam_policy"\s+"([^"]+)"\s*\{([^}]+)\}'
            matches = re.finditer(policy_pattern, content, re.DOTALL | re.IGNORECASE)
            
            for match in matches:
                policy_name = match.group(1)
                policy_block = match.group(2)
                
                # Extract policy document
                policy_doc_pattern = r'policy\s*=\s*<<-EOF\s*\n(.*?)\nEOF|policy\s*=\s*jsonencode\(([^)]+)\)|policy\s*=\s*"([^"]+)"'
                doc_match = re.search(policy_doc_pattern, policy_block, re.DOTALL | re.IGNORECASE)
                
                if doc_match:
                    policy_json = doc_match.group(1) or doc_match.group(2) or doc_match.group(3)
                    # Clean up the JSON
                    policy_json = policy_json.strip().strip('"').strip("'")
                    # Handle heredoc format
                    if '<<-EOF' in policy_block:
                        policy_json = policy_json.replace('\\n', '\n').replace('\\"', '"')
                    
                    try:
                        policy_obj = json.loads(policy_json)
                        policies.append({
                            'name': policy_name,
                            'type': 'managed_policy',
                            'policy': policy_obj,
                            'source': file_path,
                            'format': 'terraform'
                        })
                    except json.JSONDecodeError as e:
                        errors.append(f"Failed to parse policy JSON for {policy_name}: {str(e)}")
            
            # Pattern 2: aws_iam_role with inline policy
            role_pattern = r'resource\s+"aws_iam_role"\s+"([^"]+)"\s*\{([^}]+)\}'
            role_matches = re.finditer(role_pattern, content, re.DOTALL | re.IGNORECASE)
            
            for match in role_matches:
                role_name = match.group(1)
                role_block = match.group(2)
                
                # Check for inline policy
                inline_policy_pattern = r'inline_policy\s*\{[^}]*name\s*=\s*"([^"]+)"[^}]*policy\s*=\s*<<-EOF\s*\n(.*?)\nEOF'
                inline_match = re.search(inline_policy_pattern, role_block, re.DOTALL | re.IGNORECASE)
                
                if inline_match:
                    policy_name = inline_match.group(1)
                    policy_json = inline_match.group(2).strip()
                    
                    try:
                        policy_obj = json.loads(policy_json)
                        policies.append({
                            'name': f"{role_name}-{policy_name}",
                            'type': 'inline_policy',
                            'policy': policy_obj,
                            'source': file_path,
                            'format': 'terraform',
                            'role_name': role_name
                        })
                    except json.JSONDecodeError as e:
                        errors.append(f"Failed to parse inline policy JSON for {role_name}: {str(e)}")
            
            # Pattern 3: aws_iam_role_policy (inline policy attached to role)
            role_policy_pattern = r'resource\s+"aws_iam_role_policy"\s+"([^"]+)"\s*\{([^}]+)\}'
            role_policy_matches = re.finditer(role_policy_pattern, content, re.DOTALL | re.IGNORECASE)
            
            for match in role_policy_matches:
                policy_name = match.group(1)
                policy_block = match.group(2)
                
                # Extract role name
                role_name_match = re.search(r'role\s*=\s*aws_iam_role\.([^\.\s]+)', policy_block, re.IGNORECASE)
                role_name = role_name_match.group(1) if role_name_match else None
                
                # Extract policy document
                policy_doc_pattern = r'policy\s*=\s*<<-EOF\s*\n(.*?)\nEOF|policy\s*=\s*jsonencode\(([^)]+)\)'
                doc_match = re.search(policy_doc_pattern, policy_block, re.DOTALL | re.IGNORECASE)
                
                if doc_match:
                    policy_json = doc_match.group(1) or doc_match.group(2)
                    policy_json = policy_json.strip().strip('"').strip("'")
                    
                    try:
                        policy_obj = json.loads(policy_json)
                        policies.append({
                            'name': policy_name,
                            'type': 'inline_policy',
                            'policy': policy_obj,
                            'source': file_path,
                            'format': 'terraform',
                            'role_name': role_name
                        })
                    except json.JSONDecodeError as e:
                        errors.append(f"Failed to parse role policy JSON for {policy_name}: {str(e)}")
            
            # Pattern 4: aws_iam_role with assume_role_policy (trust policy)
            for match in role_matches:
                role_name = match.group(1)
                role_block = match.group(2)
                
                assume_policy_pattern = r'assume_role_policy\s*=\s*<<-EOF\s*\n(.*?)\nEOF|assume_role_policy\s*=\s*jsonencode\(([^)]+)\)'
                assume_match = re.search(assume_policy_pattern, role_block, re.DOTALL | re.IGNORECASE)
                
                if assume_match:
                    policy_json = assume_match.group(1) or assume_match.group(2)
                    policy_json = policy_json.strip().strip('"').strip("'")
                    
                    try:
                        policy_obj = json.loads(policy_json)
                        policies.append({
                            'name': f"{role_name}-trust-policy",
                            'type': 'trust_policy',
                            'policy': policy_obj,
                            'source': file_path,
                            'format': 'terraform',
                            'role_name': role_name
                        })
                    except json.JSONDecodeError as e:
                        errors.append(f"Failed to parse trust policy JSON for {role_name}: {str(e)}")
        
        except Exception as e:
            errors.append(f"Error extracting Terraform policies: {str(e)}")
            logging.error(f"Terraform extraction error: {e}")
        
        return {
            'success': len(policies) > 0,
            'policies': policies,
            'format': 'terraform',
            'errors': errors
        }
    
    def extract_from_cloudformation(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract IAM policies from CloudFormation YAML/JSON"""
        policies = []
        errors = []
        
        try:
            # Parse YAML or JSON
            if content.strip().startswith('{'):
                cfn_data = json.loads(content)
            else:
                try:
                    import yaml
                    cfn_data = yaml.safe_load(content)
                except ImportError:
                    errors.append("PyYAML not installed. Install with: pip install pyyaml")
                    return {'success': False, 'policies': [], 'format': 'cloudformation', 'errors': errors}
            
            if not isinstance(cfn_data, dict) or 'Resources' not in cfn_data:
                errors.append("Invalid CloudFormation template structure")
                return {'success': False, 'policies': [], 'format': 'cloudformation', 'errors': errors}
            
            resources = cfn_data.get('Resources', {})
            
            for resource_name, resource in resources.items():
                resource_type = resource.get('Type', '')
                properties = resource.get('Properties', {})
                
                # AWS::IAM::Policy
                if resource_type == 'AWS::IAM::Policy':
                    policy_doc = properties.get('PolicyDocument')
                    if policy_doc:
                        policies.append({
                            'name': resource_name,
                            'type': 'managed_policy',
                            'policy': policy_doc,
                            'source': file_path,
                            'format': 'cloudformation'
                        })
                
                # AWS::IAM::Role with Policies
                elif resource_type == 'AWS::IAM::Role':
                    # Inline policies
                    inline_policies = properties.get('Policies', [])
                    for inline_policy in inline_policies:
                        policy_doc = inline_policy.get('PolicyDocument')
                        if policy_doc:
                            policies.append({
                                'name': f"{resource_name}-{inline_policy.get('PolicyName', 'inline')}",
                                'type': 'inline_policy',
                                'policy': policy_doc,
                                'source': file_path,
                                'format': 'cloudformation',
                                'role_name': resource_name
                            })
                    
                    # Trust policy (AssumeRolePolicyDocument)
                    trust_policy = properties.get('AssumeRolePolicyDocument')
                    if trust_policy:
                        policies.append({
                            'name': f"{resource_name}-trust-policy",
                            'type': 'trust_policy',
                            'policy': trust_policy,
                            'source': file_path,
                            'format': 'cloudformation',
                            'role_name': resource_name
                        })
                
                # AWS::IAM::ManagedPolicy
                elif resource_type == 'AWS::IAM::ManagedPolicy':
                    policy_doc = properties.get('PolicyDocument')
                    if policy_doc:
                        policies.append({
                            'name': resource_name,
                            'type': 'managed_policy',
                            'policy': policy_doc,
                            'source': file_path,
                            'format': 'cloudformation'
                        })
        
        except json.JSONDecodeError as e:
            errors.append(f"Failed to parse CloudFormation JSON: {str(e)}")
        except Exception as e:
            errors.append(f"Error extracting CloudFormation policies: {str(e)}")
            logging.error(f"CloudFormation extraction error: {e}")
        
        return {
            'success': len(policies) > 0,
            'policies': policies,
            'format': 'cloudformation',
            'errors': errors
        }
    
    def extract_from_cdk(self, content: str, file_path: str, file_ext: str) -> Dict[str, Any]:
        """Extract IAM policies from AWS CDK code"""
        policies = []
        errors = []
        
        try:
            # CDK is more complex - we'll look for common patterns
            # Pattern: new iam.PolicyDocument({ ... })
            # Pattern: new iam.PolicyStatement({ ... })
            
            # For now, we'll extract JSON-like policy structures
            # This is a simplified version - full CDK parsing would require AST parsing
            
            # Look for policy document patterns
            policy_patterns = [
                r'PolicyDocument\.fromJson\(({[^}]+})\)',
                r'new PolicyDocument\(({[^}]+})\)',
                r'policyDocument:\s*({[^}]+})',
            ]
            
            for pattern in policy_patterns:
                matches = re.finditer(pattern, content, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    try:
                        policy_json = match.group(1)
                        # Clean up JavaScript/TypeScript syntax
                        policy_json = policy_json.replace('\\n', '\n')
                        policy_obj = json.loads(policy_json)
                        policies.append({
                            'name': f"cdk-policy-{len(policies)}",
                            'type': 'managed_policy',
                            'policy': policy_obj,
                            'source': file_path,
                            'format': 'cdk'
                        })
                    except json.JSONDecodeError:
                        continue
            
            # If no policies found, add a note
            if len(policies) == 0:
                errors.append("CDK policy extraction is limited. Full support requires AST parsing.")
        
        except Exception as e:
            errors.append(f"Error extracting CDK policies: {str(e)}")
            logging.error(f"CDK extraction error: {e}")
        
        return {
            'success': len(policies) > 0,
            'policies': policies,
            'format': 'cdk',
            'errors': errors
        }
    
    def extract_from_json(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract IAM policies from raw JSON files"""
        policies = []
        errors = []
        
        try:
            # Strip comments from JSON (many developers add comments even though JSON spec doesn't support them)
            content_clean = self._strip_json_comments(content)
            data = json.loads(content_clean)
            
            # Check if it's a direct policy document
            if isinstance(data, dict) and 'Version' in data and 'Statement' in data:
                policies.append({
                    'name': Path(file_path).stem,
                    'type': 'managed_policy',
                    'policy': data,
                    'source': file_path,
                    'format': 'json'
                })
            # Check if it's a list of policies
            elif isinstance(data, list):
                for idx, item in enumerate(data):
                    if isinstance(item, dict) and 'Version' in item and 'Statement' in item:
                        policies.append({
                            'name': f"{Path(file_path).stem}-{idx}",
                            'type': 'managed_policy',
                            'policy': item,
                            'source': file_path,
                            'format': 'json'
                        })
            # Check if it's wrapped in an object
            elif isinstance(data, dict):
                # Look for common policy keys
                for key in ['PolicyDocument', 'policy', 'Policy', 'policyDocument']:
                    if key in data and isinstance(data[key], dict):
                        if 'Version' in data[key] and 'Statement' in data[key]:
                            policies.append({
                                'name': Path(file_path).stem,
                                'type': 'managed_policy',
                                'policy': data[key],
                                'source': file_path,
                                'format': 'json'
                            })
                            break
        
        except json.JSONDecodeError as e:
            errors.append(f"Failed to parse JSON: {str(e)}")
        except Exception as e:
            errors.append(f"Error extracting JSON policies: {str(e)}")
            logging.error(f"JSON extraction error: {e}")
        
        return {
            'success': len(policies) > 0,
            'policies': policies,
            'format': 'json',
            'errors': errors
        }
    
    def _strip_json_comments(self, content: str) -> str:
        """
        Strip comments from JSON content to support developer-friendly JSON files
        Handles:
        - Single-line comments: // comment
        - Multi-line comments: /* comment */
        - Hash comments: # comment (common in some tools)
        """
        import re
        
        # Remove single-line comments (// ...)
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        
        # Remove multi-line comments (/* ... */)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Remove hash comments (# ...) but be careful with strings
        # Only remove # comments that are not inside quoted strings
        lines = []
        for line in content.split('\n'):
            # Simple heuristic: if # appears before any quotes, it's likely a comment
            hash_pos = line.find('#')
            if hash_pos != -1:
                # Check if # is inside a string
                before_hash = line[:hash_pos]
                quote_count = before_hash.count('"') - before_hash.count('\\"')
                if quote_count % 2 == 0:  # Even number of quotes = not inside string
                    line = line[:hash_pos]
            lines.append(line)
        
        return '\n'.join(lines)
    
    def _auto_detect_and_extract(self, content: str, file_path: str) -> Dict[str, Any]:
        """Auto-detect format and extract"""
        # Try JSON first
        if content.strip().startswith('{') or content.strip().startswith('['):
            result = self.extract_from_json(content, file_path)
            if result['success']:
                return result
        
        # Try CloudFormation
        if 'AWSTemplateFormatVersion' in content or 'Resources:' in content:
            result = self.extract_from_cloudformation(content, file_path)
            if result['success']:
                return result
        
        # Try Terraform
        if 'resource "aws_iam' in content.lower():
            result = self.extract_from_terraform(content, file_path)
            if result['success']:
                return result
        
        return {
            'success': False,
            'policies': [],
            'format': 'unknown',
            'errors': ['Could not auto-detect file format']
        }

