# Aegis IAM

> AI-powered AWS IAM security platform for policy generation, validation, and autonomous account auditing.

[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://aegis-iam.vercel.app)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## Overview

Aegis IAM is an enterprise-grade security platform that leverages Claude Sonnet 4.5 to generate, validate, and audit AWS IAM policies. Built for developers, security teams, and DevOps engineers who need to manage IAM permissions at scale while maintaining security best practices and compliance requirements.

### Key Capabilities

- **Policy Generation**: Convert natural language requirements into production-ready IAM policies
- **Security Validation**: Deep analysis against 20+ security categories and 8 compliance frameworks  
- **Autonomous Auditing**: Full AWS account scanning with CloudTrail-based unused permission detection
- **Auto-Remediation**: One-click fixes for common security misconfigurations
- **CI/CD Integration**: Automated policy analysis in pull requests via GitHub App

---

## Quick Start

### Prerequisites

- Node.js 18+ and npm
- Python 3.11+
- AWS CLI configured with credentials
- Amazon Bedrock access (Claude Sonnet 4.5 model enabled)

### Local Installation

**1. Clone the repository**
```bash
git clone https://github.com/bhavikam28/aegis-iam.git
cd aegis-iam
```

**2. Configure AWS credentials**
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and region
```

**3. Start the backend**
```bash
cd agent
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**4. Start the frontend (new terminal)**
```bash
cd frontend
npm install
echo "VITE_API_URL=http://localhost:8000" > .env
npm run dev
```

**5. Access the application**
```
http://localhost:5173
```

### Online Demo

Visit [aegis-iam.vercel.app](https://aegis-iam.vercel.app) to explore the interface with demo data. For full functionality including AWS integrations, run locally.

---

## Features

### Policy Generation

Generate production-ready IAM policies from natural language descriptions.

- **Natural Language Processing**: Describe requirements in plain English
- **Dual Policy Creation**: Automatic generation of both permissions and trust policies
- **Compliance Integration**: Built-in support for PCI DSS, HIPAA, SOX, GDPR, CIS
- **Multi-Format Export**: JSON, Terraform, CloudFormation, YAML
- **Interactive Refinement**: Conversational interface for policy iteration

### Security Validation

Comprehensive security analysis of IAM policies against industry standards.

- **Risk Detection**: 20+ security risk categories including wildcards, over-privileged access
- **Compliance Validation**: PCI DSS, HIPAA, SOX, GDPR, CIS, HITRUST, NIST 800-53, ISO 27001
- **Security Scoring**: Granular 0-100 scoring with detailed breakdown
- **Actionable Recommendations**: Step-by-step remediation instructions with code snippets
- **ARN Validation**: Live AWS role analysis via IAM API

### Account Audit

Autonomous scanning and remediation of AWS accounts.

- **Role Discovery**: Automatic identification of user-managed IAM roles
- **CloudTrail Analysis**: 90-day permission usage tracking for unused permission detection
- **Pattern Recognition**: Identification of systemic security issues across roles
- **Auto-Remediation**: One-click fixes for common misconfigurations
- **Compliance Mapping**: Finding classification against compliance requirements
- **Real-time Progress**: Server-sent events for audit status updates

### CI/CD Integration

Automated security analysis integrated into development workflows.

- **GitHub App**: Zero-configuration OAuth-based installation
- **PR Analysis**: Automatic IAM policy review on pull requests
- **Multi-Format Support**: Terraform, CloudFormation, CDK, raw JSON
- **CloudTrail Comparison**: Usage-based validation of new permissions
- **Status Checks**: Pass/fail indicators based on configurable risk thresholds

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend Layer                        │
│                  React 18 + TypeScript + Vite                │
└─────────────────────┬───────────────────────────────────────┘
                      │ REST API + SSE
┌─────────────────────┴───────────────────────────────────────┐
│                        Backend Layer                         │
│                   FastAPI + Python 3.11+                     │
│                                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────┐  │
│  │ Policy     │  │ Validator  │  │ Audit      │  │ CI/CD│  │
│  │ Agent      │  │ Agent      │  │ Agent      │  │Agent │  │
│  └────────────┘  └────────────┘  └────────────┘  └──────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │                      ▲
                      │                      │ GitHub Webhook
                      │              ┌───────┴────────┐
                      │              │ GitHub Actions │
                      │              │   PR Analysis  │
                      │              └────────────────┘
┌─────────────────────┴───────────────────────────────────────┐
│                      AWS Services Layer                      │
│                                                              │
│  Amazon Bedrock (Claude Sonnet 4.5) │ AWS IAM API           │
│  AWS CloudTrail                      │ AWS STS               │
└──────────────────────────────────────────────────────────────┘
```

### Technology Stack

**Frontend**
- React 18 with TypeScript
- Tailwind CSS for styling
- Vite for build tooling
- Server-Sent Events for real-time updates

**Backend**
- FastAPI with async/await
- Strands Agents SDK for AI orchestration
- boto3 for AWS API integration
- MCP (Model Context Protocol) with fallback support

**AI/ML**
- Claude Sonnet 4.5 via Amazon Bedrock
- Autonomous agent architecture
- Context-aware policy generation

---

## Configuration

### Environment Variables

**Backend** (optional - for CI/CD integration)
```bash
GITHUB_APP_ID=your_app_id
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
GITHUB_WEBHOOK_SECRET=your_webhook_secret
```

**Frontend**
```bash
VITE_API_URL=http://localhost:8000  # Development
# Production: https://your-backend-url.com
```

### AWS Credentials

Aegis IAM uses the AWS CLI credential chain for secure, local-first authentication.

**Required IAM Permissions**
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

**Setup Steps**
1. Install AWS CLI: `pip install awscli`
2. Configure credentials: `aws configure`
3. Enable Bedrock access in AWS Console
4. Verify setup: `aws sts get-caller-identity`

---

## Project Structure

```
aegis-iam/
├── frontend/              # React TypeScript application
│   ├── src/
│   │   ├── components/    # React components
│   │   │   ├── Pages/     # Feature pages
│   │   │   ├── Modals/    # Modal dialogs
│   │   │   └── Layout/    # Layout components
│   │   ├── services/      # API service layer
│   │   ├── utils/         # Utility functions
│   │   └── types/         # TypeScript definitions
│   └── package.json
│
├── agent/                 # FastAPI backend
│   ├── features/          # Feature modules
│   │   ├── policy_generation/  # Policy generation agent
│   │   ├── validation/         # Validation agent
│   │   ├── audit/              # Audit agent
│   │   └── cicd/               # CI/CD integration
│   ├── utils/             # Utility modules
│   ├── main.py            # FastAPI application
│   └── requirements.txt
│
├── README.md
├── LICENSE
└── LOCAL_SETUP.md         # Detailed setup instructions
```

---

## Security

### Credential Management

- AWS credentials never transmitted over network
- No credential storage in databases or logs
- Local-first architecture with AWS CLI credential chain
- Support for IAM roles and instance profiles

### Privacy

- No user authentication or tracking
- No telemetry or analytics collection
- All operations performed locally
- Open source and auditable

### Best Practices

- Run locally for maximum security
- Use dedicated IAM user with minimum required permissions
- Enable MFA on AWS accounts
- Rotate credentials regularly
- Review generated policies before deployment

---

## Use Cases

**Developers**
- Accelerate IAM policy creation from hours to minutes
- Learn IAM policy structure through AI-generated examples
- Validate policies before deployment
- Generate Infrastructure as Code templates

**Security Teams**
- Audit AWS accounts for security misconfigurations
- Enforce compliance requirements
- Identify and remediate unused permissions
- Generate security reports for stakeholders

**DevOps Engineers**
- Integrate security analysis into CI/CD pipelines
- Automate IAM policy reviews in pull requests
- Reduce privilege creep through regular audits
- Maintain least-privilege access across environments

---

## Cost Considerations

Aegis IAM invokes Amazon Bedrock APIs using your AWS credentials. You are responsible for all AWS charges incurred.

**Typical Costs per Operation**
- Policy generation: $0.01 - $0.05
- Policy validation: $0.02 - $0.08
- Account audit: $0.10 - $0.50

Costs are based on Claude Sonnet 4.5 pricing. Monitor your AWS billing dashboard to track usage.

---

## Documentation

- [Local Setup Guide](LOCAL_SETUP.md) - Detailed installation and configuration
- [Deployment Guide](DEPLOYMENT.md) - Production deployment instructions
- [API Documentation](docs/API.md) - Backend API reference (coming soon)
- [Contributing Guide](CONTRIBUTING.md) - How to contribute (coming soon)

---

## Roadmap

**Planned Features**
- Multi-account audit support via AWS Organizations
- Policy versioning and history tracking
- Team collaboration features
- Scheduled automated audits
- Additional CI/CD platform integrations (GitLab, Bitbucket)
- Enhanced auto-remediation capabilities

**Community Requests**
- API access for programmatic usage
- Slack/Teams integration for notifications
- Custom compliance framework definitions
- Policy template library

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows the existing style and includes appropriate tests.

---

## Disclaimer

This software is provided "AS IS" without warranty of any kind. Users are solely responsible for:

- Reviewing all generated policies before deployment
- Managing AWS credentials securely
- Monitoring AWS costs and usage
- Ensuring compliance with organizational security policies
- Validating auto-remediation changes before applying

This project is not affiliated with, endorsed by, or sponsored by AWS or Anthropic.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built with:
- [Claude Sonnet 4.5](https://www.anthropic.com/claude) by Anthropic
- [Amazon Bedrock](https://aws.amazon.com/bedrock/) for AI inference
- [Strands Agents SDK](https://github.com/strands-ai/strands) for agent orchestration
- [FastAPI](https://fastapi.tiangolo.com/) for backend framework
- [React](https://react.dev/) for frontend interface

---

## Contact

**Author**: Bhavika M  
**GitHub**: [@bhavikam28](https://github.com/bhavikam28)  
**Project**: [github.com/bhavikam28/aegis-iam](https://github.com/bhavikam28/aegis-iam)  
**Live Demo**: [aegis-iam.vercel.app](https://aegis-iam.vercel.app)

For questions, issues, or feature requests, please use [GitHub Issues](https://github.com/bhavikam28/aegis-iam/issues).

---

<p align="center">
  <sub>Built for the AWS security community</sub>
</p>
