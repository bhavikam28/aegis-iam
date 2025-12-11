# agent/github_client.py
"""
GitHub API Client
Fetches PR files, posts comments, handles both PRs and Push events
"""
import requests
import logging
from typing import List, Dict, Optional

# Import github_app to avoid circular dependency
try:
    from features.cicd.github_app import github_app
except ImportError:
    github_app = None

logging.basicConfig(level=logging.INFO)


class GitHubClient:
    """GitHub API client for fetching files and posting comments"""
    
    def __init__(self, installation_id: Optional[int] = None, token: Optional[str] = None):
        """
        Initialize GitHub client
        
        Args:
            installation_id: GitHub App installation ID
            token: Installation access token (if not provided, will be fetched)
        """
        self.installation_id = installation_id
        self.token = token
        self.base_url = "https://api.github.com"
    
    def _get_token(self) -> Optional[str]:
        """Get installation token"""
        if self.token:
            return self.token
        if self.installation_id and github_app:
            return github_app.get_installation_token(self.installation_id)
        return None
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication"""
        token = self._get_token()
        if not token:
            raise ValueError("No authentication token available")
        
        return {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Aegis-IAM'
        }
    
    def get_pr_files(self, owner: str, repo: str, pr_number: int) -> List[Dict[str, str]]:
        """
        Fetch changed files in a pull request
        
        Returns:
            List of {path: str, content: str, status: str}
        """
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
        
        try:
            response = requests.get(url, headers=self._get_headers())
            response.raise_for_status()
            files_data = response.json()
            
            files = []
            for file_info in files_data:
                # Only process IAM-related files
                path = file_info.get('filename', '')
                if not self._is_iam_file(path):
                    continue
                
                status = file_info.get('status', 'modified')  # added, modified, removed
                if status == 'removed':
                    continue  # Skip deleted files
                
                # Get file content
                content = self.get_file_content(owner, repo, path, file_info.get('sha'))
                if content:
                    files.append({
                        'path': path,
                        'content': content,
                        'status': status
                    })
            
            logging.info(f"✅ Fetched {len(files)} IAM-related files from PR #{pr_number}")
            return files
            
        except Exception as e:
            logging.error(f"❌ Failed to fetch PR files: {e}")
            return []
    
    def get_push_files(self, owner: str, repo: str, commit_sha: str, base_sha: Optional[str] = None) -> List[Dict[str, str]]:
        """
        Fetch changed files in a push/commit
        
        Args:
            owner: Repository owner
            repo: Repository name
            commit_sha: SHA of the commit
            base_sha: Base commit SHA (if None, compares with parent)
        
        Returns:
            List of {path: str, content: str, status: str}
        """
        # Get commit details
        commit_url = f"{self.base_url}/repos/{owner}/{repo}/commits/{commit_sha}"
        
        try:
            response = requests.get(commit_url, headers=self._get_headers())
            response.raise_for_status()
            commit_data = response.json()
            
            files = []
            for file_info in commit_data.get('files', []):
                path = file_info.get('filename', '')
                if not self._is_iam_file(path):
                    continue
                
                status = file_info.get('status', 'modified')
                if status == 'removed':
                    continue
                
                # Get file content from the commit
                content = self.get_file_content(owner, repo, path, file_info.get('sha'))
                if content:
                    files.append({
                        'path': path,
                        'content': content,
                        'status': status
                    })
            
            logging.info(f"✅ Fetched {len(files)} IAM-related files from commit {commit_sha[:7]}")
            return files
            
        except Exception as e:
            logging.error(f"❌ Failed to fetch push files: {e}")
            return []
    
    def get_file_content(self, owner: str, repo: str, path: str, sha: Optional[str] = None) -> Optional[str]:
        """
        Fetch file content from repository
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: File path
            sha: Optional commit SHA (if None, gets from default branch)
        """
        if sha:
            url = f"{self.base_url}/repos/{owner}/{repo}/git/blobs/{sha}"
        else:
            url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        
        try:
            response = requests.get(url, headers=self._get_headers())
            response.raise_for_status()
            data = response.json()
            
            # Handle both blob and content API responses
            if 'content' in data:
                import base64
                content = base64.b64decode(data['content']).decode('utf-8')
            elif 'content' in data and isinstance(data['content'], str):
                content = data['content']
            else:
                return None
            
            return content
            
        except Exception as e:
            logging.error(f"❌ Failed to fetch file content for {path}: {e}")
            return None
    
    def post_pr_comment(self, owner: str, repo: str, pr_number: int, comment: str) -> bool:
        """
        Post comment on a pull request
        Updates existing comment if bot comment exists
        """
        # Check for existing bot comment
        existing_comment_id = self._find_bot_comment(owner, repo, pr_number)
        
        if existing_comment_id:
            # Update existing comment
            url = f"{self.base_url}/repos/{owner}/{repo}/issues/comments/{existing_comment_id}"
            try:
                response = requests.patch(url, headers=self._get_headers(), json={'body': comment})
                response.raise_for_status()
                logging.info(f"✅ Updated PR comment on PR #{pr_number}")
                return True
            except Exception as e:
                logging.error(f"❌ Failed to update PR comment: {e}")
                return False
        else:
            # Create new comment
            url = f"{self.base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
            try:
                response = requests.post(url, headers=self._get_headers(), json={'body': comment})
                response.raise_for_status()
                logging.info(f"✅ Posted PR comment on PR #{pr_number}")
                return True
            except Exception as e:
                logging.error(f"❌ Failed to post PR comment: {e}")
                return False
    
    def post_commit_comment(self, owner: str, repo: str, commit_sha: str, comment: str) -> bool:
        """
        Post comment on a commit (for push events)
        """
        url = f"{self.base_url}/repos/{owner}/{repo}/commits/{commit_sha}/comments"
        
        try:
            response = requests.post(url, headers=self._get_headers(), json={'body': comment})
            response.raise_for_status()
            logging.info(f"✅ Posted commit comment on {commit_sha[:7]}")
            return True
        except Exception as e:
            logging.error(f"❌ Failed to post commit comment: {e}")
            return False
    
    def create_issue_comment(self, owner: str, repo: str, issue_number: int, comment: str) -> bool:
        """
        Create a comment on an issue (fallback for push events if no PR)
        """
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}/comments"
        
        try:
            response = requests.post(url, headers=self._get_headers(), json={'body': comment})
            response.raise_for_status()
            logging.info(f"✅ Posted issue comment on issue #{issue_number}")
            return True
        except Exception as e:
            logging.error(f"❌ Failed to post issue comment: {e}")
            return False
    
    def _find_bot_comment(self, owner: str, repo: str, pr_number: int) -> Optional[int]:
        """Find existing bot comment on PR"""
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        
        try:
            response = requests.get(url, headers=self._get_headers())
            response.raise_for_status()
            comments = response.json()
            
            for comment in comments:
                if (comment.get('user', {}).get('type') == 'Bot' and 
                    'IAM Policy Security Analysis' in comment.get('body', '')):
                    return comment['id']
            return None
        except Exception as e:
            logging.error(f"❌ Failed to find bot comment: {e}")
            return None
    
    def _is_iam_file(self, path: str) -> bool:
        """
        Check if file is IAM-related
        Supports: Terraform, CloudFormation, CDK, raw JSON, and more
        """
        # Comprehensive list of file extensions that might contain IAM policies
        iam_extensions = [
            '.tf', '.tfvars',  # Terraform
            '.yaml', '.yml',  # CloudFormation, Kubernetes
            '.json',  # Raw IAM policies, CloudFormation
            '.ts', '.js',  # AWS CDK TypeScript/JavaScript
            '.py',  # AWS CDK Python, Troposphere
            '.rb',  # AWS CDK Ruby
            '.java',  # AWS CDK Java
            '.cs',  # AWS CDK C#
            '.go',  # AWS CDK Go
            '.hcl',  # HashiCorp Configuration Language
            '.toml',  # Some config formats
        ]
        
        # Keywords that indicate IAM-related content
        iam_keywords = [
            'iam', 'policy', 'role', 'permission', 'permissions',
            'cloudformation', 'cfn', 'cdk',
            'assume', 'trust',
            'aws_iam', 'iam_role', 'iam_policy',
            'security', 'access',
        ]
        
        path_lower = path.lower()
        
        # Check file extension
        if any(path_lower.endswith(ext) for ext in iam_extensions):
            return True
        
        # Check keywords in filename or path
        if any(keyword in path_lower for keyword in iam_keywords):
            return True
        
        # Check for common infrastructure directories
        infra_paths = ['terraform/', 'cloudformation/', 'cdk/', 'iac/', 'infrastructure/', 'policies/']
        if any(infra_path in path_lower for infra_path in infra_paths):
            return True
        
        return False

