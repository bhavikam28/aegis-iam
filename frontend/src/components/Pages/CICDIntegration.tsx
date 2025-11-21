import React, { useState } from 'react';
import { Shield, GitBranch, Github, Gitlab, Settings, CheckCircle, AlertCircle, Info, Copy, ChevronDown, ChevronUp, Lock, Activity, Zap } from 'lucide-react';

interface CICDIntegrationProps {}

const CICDIntegration: React.FC<CICDIntegrationProps> = () => {
  const [activeTab, setActiveTab] = useState<'github' | 'gitlab' | 'advanced'>('github');
  const [githubMethod, setGithubMethod] = useState<'app' | 'actions'>('app'); // 'app' for GitHub App, 'actions' for GitHub Actions
  const [expandedSection, setExpandedSection] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section);
  };


  const githubActionYaml = `name: IAM Policy Security Check

on:
  pull_request:
    paths:
      - '**/*.tf'
      - '**/*.yaml'
      - '**/*.yml'
      - '**/*.json'
      - '**/*.ts'
      - '**/*.py'

jobs:
  check-iam-policies:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Fetch full history for diff

      - name: Get changed files
        id: changed-files
        uses: tj-actions/changed-files@v35
        with:
          files: |
            **/*.tf
            **/*.yaml
            **/*.yml
            **/*.json
            **/*.ts
            **/*.py

      - name: Analyze IAM Policies
        id: analyze
        uses: actions/github-script@v6
        env:
          AEGIS_API_URL: \${{ secrets.AEGIS_API_URL }}
        with:
          script: |
            const fs = require('fs');
            const changedFiles = '\${{ steps.changed-files.outputs.all_changed_files }}'.split(' ').filter(f => f);
            
            const files = [];
            for (const file of changedFiles) {
              if (file && fs.existsSync(file)) {
                try {
                  const content = fs.readFileSync(file, 'utf8');
                  files.push({
                    path: file,
                    content: content,
                    status: 'modified'
                  });
                } catch (e) {
                  console.log(\`Skipping \${file}: \${e.message}\`);
                }
              }
            }
            
            if (files.length === 0) {
              console.log('No IAM policy files changed');
              core.setOutput('analysis', JSON.stringify({ success: false, message: 'No IAM policy files found' }));
              return;
            }
            
            const response = await fetch(process.env.AEGIS_API_URL + '/api/cicd/analyze', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                changed_files: files,
                lookback_days: 90,
                aws_region: 'us-east-1'
              })
            });
            
            const analysis = await response.json();
            core.setOutput('analysis', JSON.stringify(analysis));

      - name: Generate PR Comment
        uses: actions/github-script@v6
        env:
          ANALYSIS: \${{ steps.analyze.outputs.analysis }}
          AEGIS_API_URL: \${{ secrets.AEGIS_API_URL }}
        with:
          github-token: \${{ secrets.GITHUB_TOKEN }}
          script: |
            const analysis = JSON.parse(process.env.ANALYSIS);
            
            if (!analysis.success && analysis.message) {
              console.log('Skipping comment generation:', analysis.message);
              return;
            }
            
            const commentResponse = await fetch(process.env.AEGIS_API_URL + '/api/cicd/generate-comment', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ analysis })
            });
            
            const { comment } = await commentResponse.json();
            
            // Check if comment already exists
            const existingComments = await github.rest.issues.listComments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number
            });
            
            const botComment = existingComments.data.find(c => 
              c.user.type === 'Bot' && c.body.includes('IAM Policy Security Analysis')
            );
            
            if (botComment) {
              // Update existing comment
              await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: botComment.id,
                body: comment
              });
            } else {
              // Create new comment
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: comment
              });
            }
            
            // Check for critical issues and fail if found
            const analysisData = analysis.analysis || {};
            const hasCritical = analysisData.has_critical_issues || false;
            const riskScore = analysisData.risk_score || 0;
            
            if (hasCritical) {
              core.setFailed('🚨 BLOCKING: Critical security issues detected. This PR cannot be merged until issues are resolved.');
            } else if (riskScore >= 70) {
              core.setFailed('⚠️ High-risk issues detected. Please review and address before merging.');
            }`;

  const gitlabCiYaml = `stages:
  - security

iam-policy-check:
  stage: security
  image: node:18
  only:
    - merge_requests
  script:
    - |
      # Get changed files
      CHANGED_FILES=$(git diff --name-only $CI_MERGE_REQUEST_DIFF_BASE_SHA $CI_COMMIT_SHA | grep -E '\\.(tf|yaml|yml|json|ts|py)$' || true)
      
      # Build file list
      FILES_JSON="[]"
      for file in $CHANGED_FILES; do
        if [ -f "$file" ]; then
          CONTENT=$(cat "$file" | jq -Rs .)
          FILES_JSON=$(echo "$FILES_JSON" | jq ". += [{\"path\": \"$file\", \"content\": $CONTENT, \"status\": \"modified\"}]")
        fi
      done
      
      # Analyze policies
      ANALYSIS=$(curl -X POST "$AEGIS_API_URL/api/cicd/analyze" \\
        -H "Content-Type: application/json" \\
        -d "{\"changed_files\": $FILES_JSON, \"lookback_days\": 90}")
      
      # Generate comment
      COMMENT=$(curl -X POST "$AEGIS_API_URL/api/cicd/generate-comment" \\
        -H "Content-Type: application/json" \\
        -d "{\"analysis\": $ANALYSIS}")
      
      # Post comment to MR
      COMMENT_BODY=$(echo "$COMMENT" | jq -r '.comment')
      curl -X POST "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes" \\
        -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \\
        -F "body=$COMMENT_BODY"
  variables:
    AEGIS_API_URL: "https://your-api-url.com"`;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50/30 to-indigo-50/30">
      {/* Background Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-20 w-96 h-96 bg-blue-400/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-20 left-20 w-96 h-96 bg-purple-400/10 rounded-full blur-3xl"></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="mb-12 text-center">
          <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-6 py-2 mb-6">
            <Shield className="w-4 h-4 text-blue-600" />
            <span className="text-blue-700 text-sm font-semibold">CI/CD Integration</span>
          </div>
          
          <h1 className="text-5xl font-extrabold mb-6">
            <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
              Proactive IAM Security
            </span>
            <br />
            <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
              in Your CI/CD Pipeline
            </span>
          </h1>
          
          <p className="text-xl text-slate-600 max-w-3xl mx-auto leading-relaxed font-medium">
            Automatically analyze IAM policies in pull requests before they're merged. 
            Compare requested permissions against actual CloudTrail usage and prevent security issues proactively.
          </p>
        </div>

        {/* Tabs */}
        <div className="flex items-center justify-center gap-2 mb-8 bg-white/80 backdrop-blur-xl border-2 border-white/50 rounded-xl p-1.5 shadow-lg max-w-2xl mx-auto">
          <button
            onClick={() => setActiveTab('github')}
            className={`flex-1 flex items-center justify-center space-x-2 px-6 py-3 rounded-lg font-semibold text-sm transition-all duration-300 ${
              activeTab === 'github'
                ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg scale-105'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Github className="w-5 h-5" />
            <span>GitHub Actions</span>
          </button>
          <button
            onClick={() => setActiveTab('gitlab')}
            className={`flex-1 flex items-center justify-center space-x-2 px-6 py-3 rounded-lg font-semibold text-sm transition-all duration-300 ${
              activeTab === 'gitlab'
                ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg scale-105'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Gitlab className="w-5 h-5" />
            <span>GitLab CI</span>
          </button>
          <button
            onClick={() => setActiveTab('advanced')}
            className={`flex-1 flex items-center justify-center space-x-2 px-6 py-3 rounded-lg font-semibold text-sm transition-all duration-300 ${
              activeTab === 'advanced'
                ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg scale-105'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Settings className="w-5 h-5" />
            <span>Advanced</span>
          </button>
        </div>

        {/* Content */}
        <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-8 shadow-xl">
          {activeTab === 'github' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-3">
                  <Github className="w-8 h-8 text-slate-900" />
                  <h2 className="text-3xl font-bold text-slate-900">GitHub Integration</h2>
                </div>
                
                {/* Method Toggle */}
                <div className="flex items-center space-x-2 bg-white/80 rounded-lg p-1 border-2 border-slate-200">
                  <button
                    onClick={() => setGithubMethod('app')}
                    className={`px-4 py-2 rounded-md text-sm font-semibold transition-all ${
                      githubMethod === 'app'
                        ? 'bg-gradient-to-r from-emerald-600 to-teal-600 text-white shadow-md'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    GitHub App (Recommended)
                  </button>
                  <button
                    onClick={() => setGithubMethod('actions')}
                    className={`px-4 py-2 rounded-md text-sm font-semibold transition-all ${
                      githubMethod === 'actions'
                        ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-md'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    GitHub Actions
                  </button>
                </div>
              </div>

              {/* GitHub App Method */}
              {githubMethod === 'app' && (
                <div className="space-y-6">
                  <div className="bg-gradient-to-br from-emerald-50 to-teal-50 rounded-2xl p-6 border-2 border-emerald-200/50">
                    <div className="flex items-center space-x-2 mb-4">
                      <CheckCircle className="w-5 h-5 text-emerald-600" />
                      <span className="text-emerald-700 font-semibold">One-Click Installation</span>
                    </div>
                    <p className="text-slate-700 mb-6">
                      Install the Aegis IAM GitHub App on your repository. No YAML files, no secrets, no configuration needed!
                      Works automatically on both Pull Requests and direct pushes to main/master branches.
                    </p>
                    
                    <button
                      onClick={async () => {
                        setConnecting(true);
                        try {
                          const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
                          const response = await fetch(`${apiUrl}/api/github/install`);
                          const data = await response.json();
                          if (data.success) {
                            // Show demo message if in demo mode, then open GitHub
                            if (data.demo_mode && data.install_url) {
                              // Demo mode: Show message, then open GitHub page
                              alert(`${data.message}\n\n${data.instructions}`);
                              // Open GitHub Apps settings page for demo
                              window.open(data.install_url, '_blank');
                            } else if (data.install_url) {
                              // Production mode: Open GitHub installation page directly
                              window.open(data.install_url, '_blank');
                            } else {
                              alert(data.message || 'GitHub App installation ready');
                            }
                          } else if (data.error) {
                            // Show error with setup instructions, but still offer to open GitHub
                            const userWantsToProceed = confirm(
                              `${data.error}\n\n${data.message || ''}\n\n` +
                              `Would you like to open GitHub App settings anyway?\n\n` +
                              `(To enable full functionality, add credentials to .env file)`
                            );
                            if (userWantsToProceed) {
                              // Open GitHub Apps page or installation page
                              const githubUrl = data.setup_url || 'https://github.com/settings/apps';
                              window.open(githubUrl, '_blank');
                            }
                          } else {
                            alert('GitHub App not configured. Please check backend configuration.');
                          }
                        } catch (error) {
                          console.error('Failed to connect GitHub:', error);
                          alert('Failed to connect GitHub. Please check if the backend is running and try again.');
                        } finally {
                          setConnecting(false);
                        }
                      }}
                      disabled={connecting}
                      className="w-full bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white font-bold py-4 px-6 rounded-xl shadow-lg transition-all duration-300 flex items-center justify-center space-x-2 disabled:opacity-50"
                    >
                      {connecting ? (
                        <>
                          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                          <span>Connecting...</span>
                        </>
                      ) : (
                        <>
                          <Github className="w-5 h-5" />
                          <span>Install GitHub App</span>
                        </>
                      )}
                    </button>
                  </div>

                  <div className="bg-blue-50 rounded-xl p-6 border-2 border-blue-200/50">
                    <h3 className="text-xl font-bold text-slate-900 mb-4 flex items-center space-x-2">
                      <Info className="w-6 h-6 text-blue-600" />
                      <span>How It Works</span>
                    </h3>
                    <ul className="space-y-3 text-slate-700">
                      <li className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0 mt-0.5">1</div>
                        <div>
                          <p className="font-semibold">Click "Install GitHub App"</p>
                          <p className="text-sm">You'll be redirected to GitHub to authorize the app</p>
                        </div>
                      </li>
                      <li className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0 mt-0.5">2</div>
                        <div>
                          <p className="font-semibold">Select Repository</p>
                          <p className="text-sm">Choose which repositories to install the app on</p>
                        </div>
                      </li>
                      <li className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0 mt-0.5">3</div>
                        <div>
                          <p className="font-semibold">Automatic Analysis</p>
                          <p className="text-sm">Every PR and push automatically triggers IAM policy analysis</p>
                        </div>
                      </li>
                      <li className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0 mt-0.5">4</div>
                        <div>
                          <p className="font-semibold">Get Results</p>
                          <p className="text-sm">Security analysis is posted as comments on PRs or commits</p>
                        </div>
                      </li>
                    </ul>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-white/80 rounded-xl p-6 border-2 border-slate-200/50">
                      <Zap className="w-8 h-8 text-emerald-600 mb-3" />
                      <h4 className="font-bold text-slate-900 mb-2">Zero Config</h4>
                      <p className="text-sm text-slate-600">No YAML files, no secrets, no code changes needed.</p>
                    </div>
                    <div className="bg-white/80 rounded-xl p-6 border-2 border-slate-200/50">
                      <Shield className="w-8 h-8 text-emerald-600 mb-3" />
                      <h4 className="font-bold text-slate-900 mb-2">Secure</h4>
                      <p className="text-sm text-slate-600">OAuth-based authentication with scoped permissions.</p>
                    </div>
                    <div className="bg-white/80 rounded-xl p-6 border-2 border-slate-200/50">
                      <Activity className="w-8 h-8 text-emerald-600 mb-3" />
                      <h4 className="font-bold text-slate-900 mb-2">Automatic</h4>
                      <p className="text-sm text-slate-600">Works on PRs and direct pushes to main/master.</p>
                    </div>
                  </div>
                </div>
              )}

              {/* GitHub Actions Method */}
              {githubMethod === 'actions' && (
                <div className="space-y-6">
                  <div className="flex items-center space-x-3 mb-6">
                    <Github className="w-8 h-8 text-slate-900" />
                    <h2 className="text-3xl font-bold text-slate-900">GitHub Actions Integration</h2>
                  </div>

              <div className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-2xl p-6 border-2 border-blue-200/50 mb-6">
                <div className="flex items-center space-x-2 mb-4">
                  <Info className="w-5 h-5 text-blue-600" />
                  <span className="text-blue-700 font-semibold">How It Works</span>
                </div>
                <ul className="space-y-2 text-slate-700">
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
                    <span>Automatically triggers on pull requests when IAM policy files change</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
                    <span>Extracts IAM policies from Terraform, CloudFormation, CDK, or JSON files</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
                    <span>Compares requested permissions against CloudTrail historical usage</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
                    <span>Posts security analysis as a PR comment with recommendations</span>
                  </li>
                </ul>
              </div>

              <div className="bg-slate-900 rounded-2xl p-6 border-2 border-slate-700 shadow-xl">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <GitBranch className="w-5 h-5 text-slate-300" />
                    <span className="text-slate-300 font-semibold">.github/workflows/iam-policy-check.yml</span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(githubActionYaml, 'github')}
                    className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors duration-300"
                  >
                    {copied === 'github' ? (
                      <>
                        <CheckCircle className="w-4 h-4" />
                        <span>Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-4 h-4" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="text-slate-300 text-xs font-mono overflow-x-auto">
                  {githubActionYaml}
                </pre>
              </div>

              <div className="bg-gradient-to-br from-indigo-50 to-purple-50 rounded-2xl p-6 border-2 border-indigo-200/50">
                <h3 className="text-xl font-bold text-slate-900 mb-4 flex items-center space-x-2">
                  <Zap className="w-6 h-6 text-indigo-600" />
                  <span>Required Secrets</span>
                </h3>
                <div className="space-y-3">
                  <div className="bg-white/80 rounded-xl p-4 border-2 border-indigo-200/50">
                    <code className="text-sm font-mono text-slate-900">AEGIS_API_URL</code>
                    <p className="text-slate-600 text-sm mt-1">Your Aegis IAM API endpoint URL</p>
                  </div>
                </div>
              </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'gitlab' && (
            <div className="space-y-6">
              <div className="flex items-center space-x-3 mb-6">
                <Gitlab className="w-8 h-8 text-slate-900" />
                <h2 className="text-3xl font-bold text-slate-900">GitLab CI Integration</h2>
              </div>

              <div className="bg-gradient-to-br from-orange-50 to-red-50 rounded-2xl p-6 border-2 border-orange-200/50 mb-6">
                <div className="flex items-center space-x-2 mb-4">
                  <Info className="w-5 h-5 text-orange-600" />
                  <span className="text-orange-700 font-semibold">How It Works</span>
                </div>
                <ul className="space-y-2 text-slate-700">
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="w-5 h-5 text-orange-600 mt-0.5 flex-shrink-0" />
                    <span>Runs automatically on merge request creation and updates</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="w-5 h-5 text-orange-600 mt-0.5 flex-shrink-0" />
                    <span>Analyzes changed IAM policy files in the MR</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle className="w-5 h-5 text-orange-600 mt-0.5 flex-shrink-0" />
                    <span>Posts security analysis as an MR comment</span>
                  </li>
                </ul>
              </div>

              <div className="bg-slate-900 rounded-2xl p-6 border-2 border-slate-700 shadow-xl">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <GitBranch className="w-5 h-5 text-slate-300" />
                    <span className="text-slate-300 font-semibold">.gitlab-ci.yml</span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(gitlabCiYaml, 'gitlab')}
                    className="flex items-center space-x-2 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition-colors duration-300"
                  >
                    {copied === 'gitlab' ? (
                      <>
                        <CheckCircle className="w-4 h-4" />
                        <span>Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-4 h-4" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="text-slate-300 text-xs font-mono overflow-x-auto">
                  {gitlabCiYaml}
                </pre>
              </div>

              <div className="bg-gradient-to-br from-orange-50 to-red-50 rounded-2xl p-6 border-2 border-orange-200/50">
                <h3 className="text-xl font-bold text-slate-900 mb-4 flex items-center space-x-2">
                  <Zap className="w-6 h-6 text-orange-600" />
                  <span>Required Variables</span>
                </h3>
                <div className="space-y-3">
                  <div className="bg-white/80 rounded-xl p-4 border-2 border-orange-200/50">
                    <code className="text-sm font-mono text-slate-900">AEGIS_API_URL</code>
                    <p className="text-slate-600 text-sm mt-1">Your Aegis IAM API endpoint URL</p>
                  </div>
                  <div className="bg-white/80 rounded-xl p-4 border-2 border-orange-200/50">
                    <code className="text-sm font-mono text-slate-900">GITLAB_TOKEN</code>
                    <p className="text-slate-600 text-sm mt-1">GitLab personal access token with api scope</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'advanced' && (
            <div className="space-y-6">
              <div className="flex items-center space-x-3 mb-6">
                <Settings className="w-8 h-8 text-slate-900" />
                <h2 className="text-3xl font-bold text-slate-900">Setup Guide</h2>
              </div>

              {/* Step 1 */}
              <div className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-2xl p-6 border-2 border-blue-200/50">
                <button
                  onClick={() => toggleSection('step1')}
                  className="w-full flex items-center justify-between"
                >
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center text-white font-bold shadow-lg">
                      1
                    </div>
                    <h3 className="text-xl font-bold text-slate-900">Configure API Endpoint</h3>
                  </div>
                  {expandedSection === 'step1' ? (
                    <ChevronUp className="w-6 h-6 text-slate-600" />
                  ) : (
                    <ChevronDown className="w-6 h-6 text-slate-600" />
                  )}
                </button>
                {expandedSection === 'step1' && (
                  <div className="mt-4 space-y-3 text-slate-700">
                    <p>Add your Aegis IAM API endpoint as a secret/variable:</p>
                    <div className="bg-white/80 rounded-xl p-4 border-2 border-blue-200/50">
                      <p className="text-sm font-mono text-slate-900">AEGIS_API_URL=https://your-api-url.com</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Step 2 */}
              <div className="bg-gradient-to-br from-purple-50 to-pink-50 rounded-2xl p-6 border-2 border-purple-200/50">
                <button
                  onClick={() => toggleSection('step2')}
                  className="w-full flex items-center justify-between"
                >
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-600 rounded-xl flex items-center justify-center text-white font-bold shadow-lg">
                      2
                    </div>
                    <h3 className="text-xl font-bold text-slate-900">Add Workflow File</h3>
                  </div>
                  {expandedSection === 'step2' ? (
                    <ChevronUp className="w-6 h-6 text-slate-600" />
                  ) : (
                    <ChevronDown className="w-6 h-6 text-slate-600" />
                  )}
                </button>
                {expandedSection === 'step2' && (
                  <div className="mt-4 space-y-3 text-slate-700">
                    <p>Copy the workflow file to your repository:</p>
                    <ul className="list-disc list-inside space-y-2">
                      <li><strong>GitHub:</strong> <code className="bg-purple-100 px-2 py-1 rounded">.github/workflows/iam-policy-check.yml</code></li>
                      <li><strong>GitLab:</strong> Add to your existing <code className="bg-purple-100 px-2 py-1 rounded">.gitlab-ci.yml</code></li>
                    </ul>
                  </div>
                )}
              </div>

              {/* Step 3 */}
              <div className="bg-gradient-to-br from-emerald-50 to-teal-50 rounded-2xl p-6 border-2 border-emerald-200/50">
                <button
                  onClick={() => toggleSection('step3')}
                  className="w-full flex items-center justify-between"
                >
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl flex items-center justify-center text-white font-bold shadow-lg">
                      3
                    </div>
                    <h3 className="text-xl font-bold text-slate-900">Test the Integration</h3>
                  </div>
                  {expandedSection === 'step3' ? (
                    <ChevronUp className="w-6 h-6 text-slate-600" />
                  ) : (
                    <ChevronDown className="w-6 h-6 text-slate-600" />
                  )}
                </button>
                {expandedSection === 'step3' && (
                  <div className="mt-4 space-y-3 text-slate-700">
                    <p>Create a test PR/MR with IAM policy changes to verify the integration works.</p>
                  </div>
                )}
              </div>

              {/* Features */}
              <div className="bg-gradient-to-br from-slate-50 to-blue-50 rounded-2xl p-6 border-2 border-slate-200/50">
                <h3 className="text-xl font-bold text-slate-900 mb-4 flex items-center space-x-2">
                  <Shield className="w-6 h-6 text-blue-600" />
                  <span>What Gets Analyzed</span>
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-white/80 rounded-xl p-4 border-2 border-blue-200/50">
                    <div className="flex items-center space-x-2 mb-2">
                      <Lock className="w-5 h-5 text-blue-600" />
                      <span className="font-semibold text-slate-900">Unused Permissions</span>
                    </div>
                    <p className="text-slate-600 text-sm">Detects permissions granted but never used in CloudTrail</p>
                  </div>
                  <div className="bg-white/80 rounded-xl p-4 border-2 border-blue-200/50">
                    <div className="flex items-center space-x-2 mb-2">
                      <AlertCircle className="w-5 h-5 text-orange-600" />
                      <span className="font-semibold text-slate-900">Wildcard Permissions</span>
                    </div>
                    <p className="text-slate-600 text-sm">Flags overly permissive wildcard actions and resources</p>
                  </div>
                  <div className="bg-white/80 rounded-xl p-4 border-2 border-blue-200/50">
                    <div className="flex items-center space-x-2 mb-2">
                      <Activity className="w-5 h-5 text-purple-600" />
                      <span className="font-semibold text-slate-900">CloudTrail Comparison</span>
                    </div>
                    <p className="text-slate-600 text-sm">Compares requested vs actual usage from last 90 days</p>
                  </div>
                  <div className="bg-white/80 rounded-xl p-4 border-2 border-blue-200/50">
                    <div className="flex items-center space-x-2 mb-2">
                      <CheckCircle className="w-5 h-5 text-emerald-600" />
                      <span className="font-semibold text-slate-900">Security Scoring</span>
                    </div>
                    <p className="text-slate-600 text-sm">Calculates risk score and provides recommendations</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CICDIntegration;

