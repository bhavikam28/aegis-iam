# Aegis IAM - AI-Powered IAM Policy Generator

Aegis IAM is an intelligent conversational agent that generates secure, least-privilege AWS IAM policies using natural language processing. Built on Amazon Bedrock with Claude 3.7 Sonnet, the system enables users to create compliant IAM policies through iterative dialogue while maintaining adherence to AWS Foundational Security Best Practices.

---

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Security Validation](#security-validation)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [API Documentation](#api-documentation)
- [Security Standards](#security-standards)
- [Development](#development)
- [Extensibility](#extensibility)
- [Troubleshooting](#troubleshooting)
- [Future Roadmap](#future-roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Capabilities
* **Conversational Policy Generation**: Generate IAM policies using natural language descriptions rather than manual JSON crafting.
* **Iterative Refinement**: Refine policies through follow-up conversations with contextual awareness.
* **Real-time Security Scoring**: Validate policies against AWS Foundational Security Best Practices with a dynamic score (0-100).
* **Least Privilege by Default**: Automatically generates restrictive policies following the principle of least privilege.
* **Multi-standard Compliance**: Validation against CIS AWS Foundations Benchmark, NIST 800-53, and PCI DSS requirements.
* **Chat History**: Full conversation context is maintained for transparency and auditability.

### User Experience
* **Intelligent Suggestions**: AI-powered refinement suggestions are provided after initial policy generation.
* **Visual Policy Display**: Syntax-highlighted JSON with copy/download functionality.
* **Detailed Explanations**: Human-readable explanations of policy permissions and restrictions.
* **Security Insights**: Real-time feedback on policy security posture with actionable recommendations.

---

## Architecture

### System Design

┌─────────────────────────────────────────────────────────────┐
│                     Frontend Layer                           │
│            React + TypeScript + Tailwind CSS                 │
└──────────────────────┬──────────────────────────────────────┘
│ HTTP REST API
↓
┌─────────────────────────────────────────────────────────────┐
│                   Backend Layer (FastAPI)                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │          Conversation Management                     │   │
│  │          Security Validation Module                  │   │
│  └─────────────────────┬───────────────────────────────┘   │
└────────────────────────┼───────────────────────────────────┘
│
↓
┌─────────────────────────────────────────────────────────────┐
│              AI Agent Layer (Strands Framework)              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Policy Agent: Plan → Act → Reflect                 │   │
│  │  System Prompt: IAM Security Expert                 │   │
│  └─────────────────────┬───────────────────────────────┘   │
└────────────────────────┼───────────────────────────────────┘
│ Tool Invocation
↓
┌─────────────────────────────────────────────────────────────┐
│           Amazon Bedrock (Claude 3.7 Sonnet)                │
│          Model: us.anthropic.claude-3-7-sonnet              │
└─────────────────────────────────────────────────────────────┘


### Component Interaction Flow
1.  **User Input**: User describes IAM requirements in natural language.
2.  **API Layer**: FastAPI receives the request and manages the conversation state.
3.  **Agent Processing**: The Strands agent analyzes the request with contextual awareness.
4.  **LLM Generation**: Claude 3.7 Sonnet generates an IAM policy following security prompts.
5.  **Security Validation**: The policy is validated against AWS security controls.
6.  **Response Delivery**: A formatted policy, explanation, and security score are returned to the user.
7.  **Iterative Refinement**: The user can send follow-up messages to modify the policy.

---

## Security Validation

### Validation Framework
Aegis IAM implements a pluggable security validation architecture based on AWS Foundational Security Best Practices. The system validates policies against documented AWS Security Hub IAM controls.

### Implemented Controls
| Control ID      | Severity | Description                                           | Impact      |
| --------------- | -------- | ----------------------------------------------------- | ----------- |
| **IAM.1** | HIGH     | No full `*:` administrative privileges                | -35 points  |
| **IAM.21** | LOW      | No wildcard service actions (e.g., `ec2:*`)           | -10 points  |
| **Resource Wildcard** | MEDIUM   | No wildcard resources (`Resource: "*"`)             | -20 points  |
| **Condition Check** | MEDIUM   | Policies should include conditions (IP, VPC, MFA) | -10 points  |

### Scoring Algorithm
The final score is calculated based on a starting score of 100, with penalties applied for each failed control.
`Final Score = max(0, 100 - Σ(severity_penalties))`

| Score Range | Grade | Meaning              |
| ----------- | ----- | -------------------- |
| 90-100      | A     | Excellent            |
| 80-89       | B     | Good                 |
| 70-79       | C     | Acceptable           |
| 60-69       | D     | Needs Improvement    |
| 0-59        | F     | Critical Issues      |

### Control Selection Rationale
Out of 28 AWS Security Hub IAM controls, only **IAM.1** and **IAM.21** directly validate IAM policy JSON content. The remaining controls (IAM.2-IAM.28) address user/role management, account-level policies, and root user security, which are outside the scope of Aegis IAM's policy generation capabilities.

---

## Technology Stack
* **Backend**
    * **Python 3.13**: Core backend language
    * **FastAPI**: Modern async web framework for REST API
    * **Strands Agents SDK**: Agentic AI framework with tool calling
    * **Boto3**: AWS SDK for Bedrock integration
    * **Uvicorn**: ASGI server for production deployment
    * **Pydantic**: Data validation and settings management
* **Frontend**
    * **React 18**: UI component framework
    * **TypeScript**: Type-safe JavaScript
    * **Vite**: Fast build tool and dev server
    * **Tailwind CSS**: Utility-first CSS framework
    * **Lucide React**: Icon library
* **AI/ML**
    * **Amazon Bedrock**: Managed service for foundation models
    * **Claude 3.7 Sonnet**: Anthropic's latest language model
    * **Model ID**: `us.anthropic.claude-3-7-sonnet-20250219-v1:0`

---

## Prerequisites

### System Requirements
* **Operating System**: Windows 10/11, macOS 11+, or Linux
* **Python**: 3.10 or higher
* **Node.js**: 18.0 or higher
* **npm**: 9.0 or higher

### AWS Requirements
* **AWS Account**: Free tier eligible
* **AWS CLI**: Configured with credentials
* **Bedrock Access**: Claude 3.7 Sonnet model access in the `us-east-1` region
* **IAM Permissions**: `bedrock:InvokeModel` permission

---

## Installation

### Backend Setup
```bash
# Navigate to agent directory
cd agent

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
Frontend Setup
Bash

# Navigate to frontend directory
cd frontend

# Install dependencies
npm install
Configuration
AWS Credentials
Configure your AWS credentials using one of the following methods:

Method 1: AWS CLI Configuration

Bash

aws configure
# Enter Access Key ID, Secret Access Key, and Region (us-east-1)
Method 2: Environment Variables

Bash

export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
Method 3: IAM Roles (for EC2/Lambda deployment)
Attach an IAM role with the bedrock:InvokeModel permission to your compute resource.

Bedrock Model Access
Navigate to the AWS Bedrock console.

Go to "Model access" in the sidebar.

Request access to Anthropic Claude 3.7 Sonnet.

Wait for approval (typically instant for supported regions).

Usage
Starting the Application
Terminal 1 - Backend:

Bash

cd agent
# On Windows: venv\Scripts\activate
# On macOS/Linux: source venv/bin/activate
uvicorn main:app --reload
# Server runs on http://localhost:8000
Terminal 2 - Frontend:

Bash

cd frontend
npm run dev
# Application runs on http://localhost:5173
Basic Workflow
Initial Request: Enter permission requirements in natural language.

Example: "IAM policy for read-only access to S3 bucket named 'company-documents'"

Review Generated Policy: Examine the JSON policy, explanation, and security score.

Refine Policy: Use suggested refinements or ask custom follow-up questions.

Example: "Restrict to red-team/* prefix only"

Example: "Add organization ID condition for o-abc123xyz"

Iterate: Continue refining until the policy meets your requirements.

Export: Copy or download the final JSON policy.

Example Interaction
User: "IAM policy for read-only access to S3 bucket named 'company-documents'"
Agent: [Generates policy with s3:GetObject and s3:ListBucket]
Security Score: 100/100

User: "Restrict to marketing/* prefix and add IP condition for 10.0.0.0/16"
Agent: [Updates policy with prefix restriction and IP condition]
Security Score: 100/100

Project Structure
aegis-iam/
├── agent/                          # Backend directory
│   ├── main.py                     # FastAPI server & API endpoints
│   ├── policy_agent.py             # Strands AI agent configuration
│   ├── bedrock_tool.py             # Amazon Bedrock integration tool
│   ├── security_validator.py       # Security validation module
│   ├── requirements.txt            # Python dependencies
│   └── venv/                       # Python virtual environment
│
├── frontend/                       # Frontend directory
│   ├── src/
│   │   ├── components/
│   │   │   ├── Pages/
│   │   │   │   ├── GeneratePolicy.tsx  # Main policy generation UI
│   │   │   │   ├── ValidatePolicy.tsx  # Policy validation UI
│   │   │   │   └── AnalyzeHistory.tsx  # Usage analysis UI
│   │   │   ├── UI/
│   │   │   │   ├── LoadingSpinner.tsx
│   │   │   │   ├── SecurityScore.tsx
│   │   │   │   └── CodeBlock.tsx
│   │   │   └── Layout/
│   │   │       └── Dashboard.tsx
│   │   ├── services/
│   │   │   ├── api.ts              # Backend API integration
│   │   │   └── mockData.ts         # Mock data for development
│   │   ├── types/
│   │   │   └── index.ts            # TypeScript type definitions
│   │   ├── App.tsx                 # Root component
│   │   └── main.tsx                # Application entry point
│   ├── package.json
│   └── vite.config.ts
│
└── README.md                       # This file
API Documentation
Endpoints
GET /

Health check endpoint.

Response:

JSON

{
  "status": "healthy",
  "message": "Aegis IAM Agent is running"
}
POST /generate

Generate or refine an IAM policy.

Request:

JSON

{
  "description": "IAM policy for read-only S3 access",
  "service": "S3",
  "conversation_id": "uuid-string",  // Optional for follow-ups
  "is_followup": false
}
Response:

JSON

{
  "final_answer": "Full agent response with policy and explanation",
  "conversation_id": "uuid-string",
  "message_count": 2,
  "security_score": 85,
  "security_notes": ["List of security issues"],
  "refinement_suggestions": ["Suggested improvements"],
  "conversation_history": [
    {
      "role": "user",
      "content": "User message",
      "timestamp": "uuid"
    },
    {
      "role": "assistant",
      "content": "Agent response",
      "timestamp": "uuid"
    }
  ]
}
GET /conversation/{conversation_id}

Retrieve conversation history.

Response:

JSON

{
  "conversation_id": "uuid-string",
  "messages": [...],
  "message_count": 5
}
DELETE /conversation/{conversation_id}

Clear conversation history.

Security Standards
Compliance Frameworks
Aegis IAM validates policies against multiple security frameworks:

AWS Foundational Security Best Practices: Primary validation standard.

CIS AWS Foundations Benchmark: Industry security benchmarks.

NIST 800-53: Federal information security standards.

PCI DSS: Payment card industry requirements.

Documentation References
AWS Security Hub IAM Controls

IAM Best Practices

Least Privilege Principle

Development
Running Tests
Bash

# Backend tests (when implemented)
cd agent
pytest

# Frontend tests
cd frontend
npm test
Code Style
Python:

Follow PEP 8 style guide.

Use type hints where applicable.

Document functions with docstrings.

TypeScript:

Follow the Airbnb style guide.

Use strict type checking.

Prefer functional components.

Adding New Features
Create a feature branch: git checkout -b feature/your-feature

Implement changes with tests.

Update documentation.

Submit a pull request.

Extensibility
Security Validation Architecture
The security validation system is designed for easy extension.

Current Implementation:

SecurityValidator class in security_validator.py.

Local validation using hardcoded AWS controls.

No external API dependencies.

Future Integration:
To integrate the AWS Security Hub API, you would implement a SecurityHubValidator class with the same interface, add AWS Security Hub API calls using boto3, and update the security_validator.py file to use the new validator.

Python

# In security_validator.py

# Change from:
validator = SecurityValidator()

# To:
validator = SecurityHubValidator()
Adding New Scenarios
Scenario 2: Policy Validation (Planned)

Analyze existing policies for security issues.

Compare against organizational policies.

Generate remediation recommendations.

Scenario 3: Historical Usage Analysis (Planned)

Analyze CloudTrail logs for actual permission usage.

Generate right-sized policies based on usage.

Identify unused permissions.

Troubleshooting
Common Issues
Issue: Backend fails to start.

Solution: Ensure Python 3.10+ is installed and the virtual environment is activated.

Issue: Bedrock access denied.

Solution: 1. Verify AWS credentials are configured. 2. Check IAM permissions include bedrock:InvokeModel. 3. Confirm Claude 3.7 Sonnet access is enabled in the Bedrock console.

Issue: Frontend shows CORS errors.

Solution: Ensure the backend is running on port 8000 and CORS is enabled in main.py.

Issue: The security score always shows 85.

Solution: Check that security_validator.py is created and imported correctly in main.py.

Debug Mode
Enable debug logging in main.py:

Python

# In main.py
import logging
logging.basicConfig(level=logging.DEBUG)
Future Roadmap
Phase 1: Core Enhancement (Current)

✅ Conversational policy generation

✅ Security validation framework

✅ Chat history visualization

🔄 AWS Security Hub integration preparation

Phase 2: Advanced Features (Q2 2025)

Policy validation against existing policies

CloudTrail integration for usage analysis

Policy comparison and diff tools

Bulk policy generation

Phase 3: Enterprise Features (Q3 2025)

Multi-account support

Policy approval workflows

Audit trail and compliance reporting

Role-based access control

Phase 4: Production Deployment (Q4 2025)

AgentCore Runtime integration

Database persistence

API rate limiting

Production monitoring

Contributing
Contributions are welcome! Please follow these guidelines:

Fork the repository.

Create a feature branch.

Commit changes with clear messages.

Add tests for new functionality.

Update documentation.

Submit a pull request.

License
This project is developed as an educational tool for AWS IAM policy management. It is not intended for production use without proper security review and testing.

Acknowledgments
Amazon Web Services: For Bedrock and Security Hub documentation.

Anthropic: For the Claude AI models.

Strands AI: For the agent framework.

Open Source Community: For React, FastAPI, and supporting libraries.

Developed by: Bhavika Mantri
Project: Aegis IAM - AI Security Shield for AWS
Last Updated: September 30, 2025

For questions or support, please open an issue in the repository.