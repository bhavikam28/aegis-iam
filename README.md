# Aegis IAM

**AI-Powered AWS IAM Security Platform**

Generate, validate, and audit AWS IAM policies using Claude 3.7 Sonnet. Transform natural language into production-ready policies with comprehensive security analysis and compliance validation.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Aegis%20IAM-blue?style=for-the-badge)](https://aegis-iam.vercel.app)
[![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-red?style=for-the-badge)](LICENSE)

---

## ⚠️ Disclaimer

**This software is provided for demonstration and reference purposes only. Use at your own risk.**

This software is provided "AS IS" without any warranty. The authors are not responsible for any damages, losses, security breaches, or other consequences resulting from use of this software. Do not use in production without proper security review, testing, and compliance validation. You are solely responsible for reviewing all generated policies, managing AWS credentials securely, and monitoring AWS costs. This application uses your AWS credentials and makes API calls to your account—you are responsible for all AWS charges. This project is not affiliated with, endorsed by, or sponsored by AWS or Anthropic.

**By using this software, you acknowledge and agree to these terms.**

---

## 🚀 Quick Start

### 🏠 Run Locally (Recommended for Full Functionality)

**For complete access to all features with maximum security, run Aegis IAM on your local machine. Your AWS credentials never leave your computer.**

📖 **[Complete Local Setup Guide →](LOCAL_SETUP.md)**

**Quick setup (5 minutes):**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bhavikam28/aegis-iam.git
   cd aegis-iam
   ```

2. **Configure AWS CLI:**
   ```bash
   aws configure
   # Enter your AWS Access Key ID, Secret Key, and region
   ```

3. **Start backend:**
   ```bash
   cd agent
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   uvicorn main:app --reload --port 8000
   ```

4. **Start frontend (new terminal):**
   ```bash
   cd frontend
   npm install
   echo "VITE_API_URL=http://localhost:8000" > .env
   npm run dev
   ```

5. **Access:** [http://localhost:5173](http://localhost:5173)

✅ **All features available**  
✅ **AWS credentials stay on your machine**  
✅ **Maximum security**  

---

### 🌐 Online Demo (Showcase Only)

Visit **[https://aegis-iam.vercel.app](https://aegis-iam.vercel.app)** to explore the interface and see sample outputs.

⚠️ **Note:** The hosted version is for demonstration purposes. For full functionality, please run locally.

---

## ✨ Features

### 🔧 Policy Generation
- **Natural Language to IAM Policies**: Describe what you need in plain English
- **Dual Policy Generation**: Creates both Permissions and Trust policies
- **Multi-Format Export**: JSON, Terraform, CloudFormation, YAML
- **Conversational Refinement**: Chat with AI to refine policies
- **Compliance-Aware**: Built-in support for PCI DSS, HIPAA, SOX, GDPR, CIS
- **Simple Explanations**: Get non-technical explanations for stakeholders

### ✅ Policy Validation
- **Deep Security Analysis**: Identifies over 20 security risks
- **Compliance Framework Validation**: Checks against major compliance standards
- **Security Scoring**: Get a security score (0-100, higher is better)
- **Actionable Recommendations**: Code snippets and step-by-step fixes
- **Export Reports**: PDF and email export options

### 🔍 Account Audit
- **Autonomous Scanning**: Analyzes entire AWS accounts
- **CloudTrail Integration**: Identifies unused permissions
- **Pattern Recognition**: Finds systemic security issues
- **Prioritized Findings**: Critical, High, Medium, Low severity classification
- **Auto-Remediation**: One-click fixes for common issues

### 🔄 CI/CD Integration
- **GitHub App Integration**: Zero-configuration setup
- **Automatic PR Analysis**: Reviews IAM policy changes in pull requests
- **Multi-Format Support**: Terraform, CloudFormation, CDK, raw JSON
- **CloudTrail Comparison**: Compares new permissions against actual usage
- **PR Comments**: Automatic security feedback on pull requests

---

## 🏗️ Architecture

**Frontend:**
- React 18 + TypeScript
- Tailwind CSS for styling
- Vite for build tooling
- Server-Sent Events (SSE) for real-time updates

**Backend:**
- FastAPI (Python) with async endpoints
- AWS Bedrock (Claude 3.7 Sonnet) for AI capabilities
- MCP (Model Context Protocol) for AWS integration
- Strands Agents SDK for agentic workflows

**AWS Services:**
- Amazon Bedrock (Claude 3.7 Sonnet)
- AWS IAM API
- AWS CloudTrail
- AWS STS

---

## 🔐 AWS Credentials Setup

### For Local Installation (Secure Method)

Aegis IAM uses **AWS CLI-based authentication** when running locally. This is the most secure method - your credentials stay on your machine.

**Setup Steps:**

1. **Install AWS CLI** (if not already installed):
   ```bash
   # macOS/Linux
   brew install awscli
   
   # Windows
   # Download from: https://aws.amazon.com/cli/
   
   # Or via pip
   pip install awscli
   ```

2. **Configure AWS CLI** (one-time setup):
   ```bash
   aws configure
   ```
   
   Enter your:
   - AWS Access Key ID (from IAM Console)
   - AWS Secret Access Key
   - Default region (e.g., `us-east-1`)
   - Default output format (e.g., `json`)

3. **Required IAM Permissions** - Attach this policy to your IAM user:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": [
         "bedrock:InvokeModel",
         "bedrock:InvokeModelWithResponseStream",
         "iam:GetRole",
         "iam:GetPolicy",
         "iam:GetPolicyVersion",
         "iam:ListRoles",
         "iam:ListAttachedRolePolicies",
         "iam:GetRolePolicy",
         "cloudtrail:LookupEvents",
         "sts:GetCallerIdentity"
       ],
       "Resource": "*"
     }]
   }
   ```

4. **Enable Amazon Bedrock**:
   - Go to [AWS Bedrock Console](https://console.aws.amazon.com/bedrock/)
   - Select Model access
   - Enable **Claude 3.7 Sonnet**
   - Request access (usually instant)

5. **Verify Setup**:
   ```bash
   aws sts get-caller-identity  # Should show your account info
   ```

6. **Start using Aegis IAM locally!**

📖 **[Detailed Setup Guide →](LOCAL_SETUP.md)**

**Security Best Practices:**
- ✅ Run locally (credentials never leave your machine)
- ✅ Create a dedicated IAM user with minimum required permissions
- ✅ Never commit AWS credentials to version control
- ✅ Rotate credentials regularly
- ✅ Enable MFA on your AWS account

---

## 💰 AWS Costs

This application invokes AWS Bedrock on your AWS account. You are responsible for all AWS charges.

**Typical costs per operation:**
- Policy generation: $0.01 - $0.05
- Policy validation: $0.02 - $0.08
- Full account audit: $0.10 - $0.50

The Aegis IAM application itself is free. All AWS costs are based on your Bedrock usage. Monitor your AWS billing dashboard to track costs.

---

## 📁 Project Structure

```
aegis-iam/
├── frontend/              # React + TypeScript frontend
│   ├── src/
│   │   ├── components/    # React components
│   │   │   ├── Pages/    # Main feature pages
│   │   │   ├── Modals/   # Modal dialogs
│   │   │   └── Layout/   # Layout components
│   │   ├── services/     # API service layer
│   │   ├── utils/        # Utility functions
│   │   └── types/        # TypeScript type definitions
│   └── package.json
│
├── agent/                # FastAPI backend
│   ├── features/         # Feature modules
│   │   ├── policy_generation/  # Policy generation agent
│   │   ├── validation/         # Validation agent
│   │   ├── audit/              # Audit agent
│   │   └── cicd/               # CI/CD integration
│   ├── utils/           # Utility modules
│   │   ├── iac_exporter.py     # IaC format conversion
│   │   └── iam_deployer.py     # AWS deployment
│   ├── main.py          # FastAPI application
│   └── requirements.txt
│
└── README.md
```

---

## 🔧 Environment Variables

**Backend (Optional - for CI/CD):**
```bash
GITHUB_APP_ID=your_app_id
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
GITHUB_WEBHOOK_SECRET=your_webhook_secret
```

**Frontend:**
```bash
VITE_API_URL=http://localhost:8000  # Local development
# Or: https://your-backend.onrender.com for production
```

---

## 🎯 Use Cases

**Developers:**
- Learn IAM policy structure
- Speed up policy development
- Validate policies before deploying
- Generate IaC templates

**Security Teams:**
- Audit AWS accounts for security issues
- Enforce compliance requirements
- Shift-left security practices
- Generate security reports

**DevOps Engineers:**
- Automate IAM policy reviews
- Reduce privilege creep
- Generate Infrastructure as Code
- Integrate security into CI/CD pipelines

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

All rights reserved. This project is provided for demonstration and reference purposes only.

---

## 🙏 Acknowledgments

- **Anthropic Claude 3.7 Sonnet** for AI capabilities
- **Amazon Bedrock** for serverless AI inference
- **Strands Agents SDK** for agentic workflows
- **MCP Protocol** for AWS integration

---

## 📞 Contact

**Bhavika M** - [@bhavikam28](https://github.com/bhavikam28)

**Project Link:** [https://github.com/bhavikam28/aegis-iam](https://github.com/bhavikam28/aegis-iam)  
**Live Demo:** [https://aegis-iam.vercel.app](https://aegis-iam.vercel.app)

---

## 🛠️ Technology Stack

- **Frontend:** React 18, TypeScript, Tailwind CSS, Vite
- **Backend:** FastAPI, Python 3.11+
- **AI:** Claude 3.7 Sonnet via Amazon Bedrock
- **AWS Integration:** MCP (Model Context Protocol), boto3
- **Agent Framework:** Strands Agents SDK
- **Deployment:** Vercel (Frontend), Render/Railway (Backend)

---

## 📊 Roadmap

- [ ] Support for additional compliance frameworks
- [ ] Enhanced auto-remediation capabilities
- [ ] Multi-account audit support
- [ ] Policy versioning and history
- [ ] Team collaboration features
- [ ] API access for programmatic usage

---

**Made with ❤️ for the AWS security community**
