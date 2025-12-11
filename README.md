# 🛡️ Aegis IAM

### AI-Powered IAM Security Platform for AWS

<div align="center">

[![Live Demo](https://img.shields.io/badge/Live%20Demo-aegis--iam.vercel.app-blue?style=for-the-badge&logo=vercel)](https://aegis-iam.vercel.app)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge&logo=opensourceinitiative)](LICENSE)
[![Powered by Claude](https://img.shields.io/badge/Powered%20by-Claude%203.7-purple?style=for-the-badge&logo=anthropic)](https://www.anthropic.com/claude)
[![AWS](https://img.shields.io/badge/AWS-Bedrock-orange?style=for-the-badge&logo=amazonaws)](https://aws.amazon.com/bedrock/)

**Generate, validate, and audit AWS IAM policies using AI-powered autonomous agents**

[🚀 Live Demo](https://aegis-iam.vercel.app) · [🐛 Report Bug](https://github.com/bhavikam28/aegis-iam/issues) · [✨ Request Feature](https://github.com/bhavikam28/aegis-iam/issues)

</div>

---

## 🚀 What is Aegis IAM?

Aegis IAM is an **AI-powered security platform** that helps you create, validate, and audit AWS IAM policies using **Claude 3.7 Sonnet**. It combines natural language processing with AWS security best practices to make IAM policy management accessible to everyone—from beginners to security experts.

### ✨ Key Features

#### 🤖 **AI Policy Generation**
Transform natural language descriptions into production-ready IAM policies with comprehensive security analysis.
- **Natural language input** → Complete IAM policies (Permissions + Trust)
- **Security scoring** (0-100) with detailed breakdown
- **Compliance validation** (PCI DSS, HIPAA, SOX, GDPR, CIS)
- **Conversational refinement** via AI chatbot
- **Multi-format export** (JSON, Terraform, CloudFormation, YAML)

#### 🔍 **Deep Security Validation**
Analyze existing IAM policies for security vulnerabilities and compliance violations.
- **Risk assessment** with severity-based findings
- **Compliance framework** validation
- **Actionable recommendations** with code snippets
- **Quick wins** for immediate security improvements
- **PDF/Email export** for sharing reports

#### 🔬 **Autonomous Account Audit**
Full AWS account security scan powered by autonomous AI agents.
- **Automatic role discovery** across your entire account
- **CloudTrail analysis** (90-day usage comparison)
- **Unused permission detection**
- **Pattern recognition** for systemic issues
- **Comprehensive reporting** with prioritized risks

#### 🔄 **CI/CD Integration**
Proactive security analysis in your development workflow.
- **GitHub App integration** (zero config)
- **Automatic PR analysis** for IAM policy changes
- **Inline security comments** on pull requests
- **CloudTrail usage comparison** for new permissions
- **Works with Terraform, CloudFormation, CDK**, and raw JSON

---

## 🎯 Why Aegis IAM?

### The Problem
- IAM policies are complex and error-prone
- Security best practices are hard to implement
- Compliance requirements are overwhelming
- Manual audits are time-consuming
- Overprivileged roles create security risks

### The Solution
Aegis IAM uses **AI agents** powered by Claude 3.7 Sonnet to:
- ✅ Generate secure policies from plain English
- ✅ Validate against 5+ compliance frameworks
- ✅ Audit entire AWS accounts autonomously
- ✅ Catch security issues before they're merged
- ✅ Provide actionable, specific recommendations

---

## 🏗️ Architecture

### Tech Stack

**Frontend:**
- React 18 + TypeScript
- Tailwind CSS
- Vite
- Real-time SSE (Server-Sent Events)

**Backend:**
- FastAPI (Python 3.11+)
- AWS Bedrock (Claude 3.7 Sonnet)
- boto3 (AWS SDK)
- Strands Agents SDK
- MCP (Model Context Protocol)

**AWS Services:**
- Amazon Bedrock
- AWS IAM
- AWS CloudTrail
- AWS STS

**CI/CD:**
- GitHub App (OAuth)
- Webhook integration
- Automated analysis

### System Design

```
┌─────────────────┐
│  React Frontend │ ← User enters AWS credentials
│  (Vercel)       │
└────────┬────────┘
         │ HTTPS (credentials in request body)
         ▼
┌─────────────────┐
│  FastAPI Backend│ ← Credentials used for request only
│  (Render)       │ ← NEVER stored or logged
└────────┬────────┘
         │
         ├─► Amazon Bedrock (Claude 3.7)
         ├─► AWS IAM API
         ├─► AWS CloudTrail
         └─► AWS STS
```

**Security Model:**
- User credentials stored **only in React state** (memory)
- Transmitted via **HTTPS** to backend
- Backend uses credentials **only for current request**
- Automatically **cleared after request**
- **Never logged or persisted** anywhere

---

## 🚀 Getting Started

### Prerequisites

**For Users:**
- AWS Account with:
  - IAM access (to manage policies)
  - Bedrock access (Claude 3.7 Sonnet enabled)
- AWS Access Key ID and Secret Access Key

**For Developers:**
- Node.js 18+
- Python 3.11+
- AWS CLI configured

### Using Aegis IAM (Hosted) ⚡

1. **Visit the live app:** [https://aegis-iam.vercel.app](https://aegis-iam.vercel.app)

2. **Click "Get Started"** and configure AWS credentials in the one-time modal:
   - 🔑 **Access Key ID**
   - 🔐 **Secret Access Key**
   - 🌍 **AWS Region**
   
   > **Note:** Credentials are stored *only in memory* for your session. Never persisted.

3. **Choose a feature:**
   - 🤖 **Generate Policy** → Create new IAM policies from plain English
   - 🔍 **Validate Policy** → Analyze existing policies for security issues
   - 🔬 **Audit Account** → Scan your entire AWS account autonomously
   - 🔄 **CI/CD Integration** → Automate IAM policy reviews in PRs

4. **Get AI-powered results** instantly with actionable security insights!

### Running Locally

#### 1. Clone the repository
```bash
git clone https://github.com/bhavikam28/aegis-iam.git
cd aegis-iam
```

#### 2. Backend Setup
```bash
cd agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run backend
uvicorn main:app --reload --port 8000
```

#### 3. Frontend Setup (New Terminal)
```bash
cd frontend

# Install dependencies
npm install

# Create .env file
echo "VITE_API_URL=http://localhost:8000" > .env

# Run frontend
npm run dev
```

#### 4. Access the app
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 💰 AWS Costs

**Important:** Aegis IAM invokes AWS Bedrock on **your AWS account**. You are responsible for AWS charges.

### Pricing Breakdown (as of Dec 2024)
- **Claude 3.7 Sonnet:** ~$3-15 per 1M tokens
- **Typical costs per operation:**
  - Policy generation: $0.01 - $0.05
  - Policy validation: $0.02 - $0.08
  - Full account audit: $0.10 - $0.50
- **IAM/STS/CloudTrail API calls:** Included in AWS Free Tier

**The Aegis IAM application itself is FREE.** All AWS costs are based on your Bedrock usage.

---

## 🔒 Security & Privacy

### We Never Store Your Credentials

Your AWS credentials are:
- ✅ **Never stored** in any database
- ✅ **Never logged** to files or monitoring
- ✅ **Never persisted** to localStorage/sessionStorage
- ✅ **Used only for the current request**
- ✅ **Transmitted over HTTPS** only
- ✅ **Automatically cleared** after each request

### How It Works
1. You enter credentials in the modal → Stored in React state (memory only)
2. Credentials sent to backend with API request → Used immediately
3. Backend calls AWS on your behalf → Using your credentials
4. Request completes → Credentials cleared from backend memory
5. You close browser → Credentials cleared from React state

**Result:** Zero-trust architecture. Your credentials exist only for the duration of your active session.

### Additional Security Measures
- Request-scoped context variables (thread-safe)
- Automatic cleanup in `finally` blocks
- Input validation and sanitization
- CORS protection
- No credential logging anywhere in codebase

---

## 🎨 Features in Detail

### 1️⃣ Generate IAM Policy

**Create production-ready IAM policies from natural language**

**Example:**
```
Input: "Lambda function to read from S3 bucket customer-uploads and write to DynamoDB table transactions"

Output:
✓ Permissions Policy (JSON)
✓ Trust Policy (JSON)
✓ Security Score (0-100)
✓ Compliance Status (PCI DSS, HIPAA, etc.)
✓ Refinement Suggestions
✓ Export (Terraform, CloudFormation, YAML)
```

**Features:**
- Conversational chatbot for policy refinement
- Account ID auto-detection
- Service-specific best practices
- Compliance framework support
- One-click AWS deployment

---

### 2️⃣ Validate IAM Policy

**Deep security analysis of existing policies**

**Input Options:**
- Paste policy JSON
- Provide Role ARN (auto-fetches policy)

**Analysis Includes:**
- Risk score with severity breakdown
- Security findings (Critical/High/Medium/Low)
- Compliance validation (5+ frameworks)
- Quick wins for immediate fixes
- Detailed recommendations with code

**Export Options:**
- PDF report
- Email sharing
- Copy to clipboard

---

### 3️⃣ Autonomous Account Audit

**Full AWS account security scan**

**What It Does:**
1. Discovers all IAM roles automatically
2. Analyzes CloudTrail for actual usage (90 days)
3. Identifies unused permissions
4. Detects security vulnerabilities
5. Checks compliance across frameworks
6. Generates comprehensive report

**Output:**
- Audit summary (roles, findings, risks)
- Top 5 riskiest roles
- Detailed findings with remediation
- Compliance status
- Systemic pattern detection

---

### 4️⃣ CI/CD Integration

**Automated IAM policy analysis in Pull Requests**

**Features:**
- GitHub App (one-click install)
- Automatic PR comments with security analysis
- CloudTrail usage comparison
- Supports Terraform, CloudFormation, CDK
- Works on JSON files with comments
- Dashboard view of recent analyses

**How It Works:**
1. Install GitHub App on your repository
2. Create PR with IAM policy changes
3. Aegis IAM analyzes policies automatically
4. Get security feedback as PR comments
5. View analysis history in dashboard

---

## 🛠️ Tech Stack Details

### AI & Agents
- **Claude 3.7 Sonnet** (Amazon Bedrock)
- **Strands Agents SDK** for autonomous decision-making
- **MCP (Model Context Protocol)** for AWS API integration

### Backend Stack
- **FastAPI** for high-performance async API
- **boto3** for AWS operations
- **Context variables** for secure credential handling
- **SSE** for real-time audit streaming

### Frontend Stack
- **React 18** with functional components
- **TypeScript** for type safety
- **Tailwind CSS** for beautiful UI
- **Lucide icons** for consistent design

### AWS Integration
- **MCP Servers:** aws-iam, aws-cloudtrail, aws-api
- **Graceful fallback** to boto3 if MCP unavailable
- **Multi-region support**

---

## 📖 Documentation

### AWS Credentials Setup

**Required IAM Permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "iam:GetRole",
        "iam:GetPolicy",
        "iam:ListRoles",
        "iam:ListPolicies",
        "sts:GetCallerIdentity",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

**Setup Steps:**
1. Go to AWS Console → IAM → Users → Create User
2. Enable "Programmatic access"
3. Attach policies: `IAMFullAccess`, `AmazonBedrockFullAccess`
4. Download credentials CSV
5. Enter credentials in Aegis IAM modal

**Security Best Practice:** Create a dedicated IAM user for Aegis IAM with minimum required permissions.

---

## 🏃 Development

### Project Structure
```
aegis-iam/
├── frontend/              # React + TypeScript frontend
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── services/      # API client
│   │   ├── utils/         # Utility functions
│   │   └── types/         # TypeScript types
│   └── package.json
│
├── agent/                 # FastAPI backend
│   ├── features/          # Feature modules
│   │   ├── policy_generation/
│   │   ├── validation/
│   │   ├── audit/
│   │   └── cicd/
│   ├── utils/             # Utilities
│   ├── core/              # MCP client
│   └── main.py            # FastAPI app
│
└── README.md
```

### Environment Variables

**Backend (Optional - for CI/CD feature):**
```bash
# GitHub App credentials (only needed for CI/CD integration)
GITHUB_APP_ID=your_app_id
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
GITHUB_WEBHOOK_SECRET=your_webhook_secret
```

**Frontend:**
```bash
VITE_API_URL=http://localhost:8000  # For local dev
# Or: https://your-backend.onrender.com for production
```

### Running Tests
```bash
# Backend tests
cd agent
pytest

# Frontend
cd frontend
npm test
```

---

## 🌟 Use Cases

### For Developers
- **Learn IAM:** Generate policies to understand IAM structure
- **Speed up development:** Stop googling IAM actions
- **Avoid errors:** Validate before deploying

### For Security Teams
- **Audit entire accounts:** Discover unused permissions
- **Enforce compliance:** Check against regulatory frameworks
- **Shift-left security:** Catch issues in CI/CD

### For DevOps Engineers
- **Automate reviews:** GitHub App integration
- **Reduce privilege creep:** CloudTrail usage analysis
- **Generate IaC:** Export to Terraform/CloudFormation

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Anthropic Claude 3.7 Sonnet** for AI capabilities
- **Amazon Bedrock** for serverless AI inference
- **Strands Agents SDK** for agentic workflows
- **MCP Protocol** for AWS integration

---

## ⚠️ Disclaimer

**AWS Charges:** This application invokes AWS Bedrock API on your AWS account. You are responsible for all AWS charges incurred.

**Security:** While Aegis IAM follows security best practices, always review generated policies before deploying to production. This tool is for assistance and should not replace human security review.

**Not Affiliated:** This project is not affiliated with, endorsed by, or sponsored by Amazon Web Services (AWS) or Anthropic.

---

## 📧 Contact

**Bhavika M** - [@bhavikam28](https://github.com/bhavikam28)

**Project Link:** [https://github.com/bhavikam28/aegis-iam](https://github.com/bhavikam28/aegis-iam)

**Live Demo:** [https://aegis-iam.vercel.app](https://aegis-iam.vercel.app)

---

<div align="center">

### ⭐ Star this repo if you find it helpful!

Made with ❤️ and 🤖 AI

</div>
