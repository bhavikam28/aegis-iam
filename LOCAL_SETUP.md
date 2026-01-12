# Local Setup Guide - Full Functionality

Run Aegis IAM locally for complete functionality with maximum security. Your AWS credentials never leave your machine.

---

## Why Run Locally?

✅ **Maximum Security** - AWS credentials stay on your machine  
✅ **Full Functionality** - All features work (Generate, Validate, Audit, Deploy)  
✅ **No Trust Required** - Your credentials never sent to remote servers  
✅ **Free** - No costs except your own AWS Bedrock usage  
✅ **Private** - All processing happens locally  

---

## Prerequisites

Before you begin, ensure you have:

- **Node.js 18+** - [Download](https://nodejs.org/)
- **Python 3.11+** - [Download](https://www.python.org/)
- **AWS Account** - [Sign up](https://aws.amazon.com/)
- **AWS CLI** - [Install Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **Git** - [Download](https://git-scm.com/)

---

## Quick Start (5 Minutes)

### Step 1: Clone the Repository

```bash
git clone https://github.com/bhavikam28/aegis-iam.git
cd aegis-iam
```

### Step 2: Configure AWS CLI

```bash
# Configure your AWS credentials
aws configure

# You'll be prompted for:
# AWS Access Key ID: [Enter your key]
# AWS Secret Access Key: [Enter your secret]
# Default region: us-east-1 (or your preferred region)
# Default output format: json
```

**Get your credentials:**
1. Go to [AWS IAM Console](https://console.aws.amazon.com/iam/)
2. Users → Your username → Security credentials
3. Create access key → Copy Access Key ID and Secret

### Step 3: Attach Required IAM Policy

Your AWS user needs permissions. In AWS IAM Console:

1. Go to Users → Your username → Permissions
2. Add permissions → Create inline policy
3. JSON tab → Paste this policy:

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

4. Review policy → Name it: `AegisIAMPolicy`
5. Create policy

### Step 4: Enable Amazon Bedrock

1. Go to [Amazon Bedrock Console](https://console.aws.amazon.com/bedrock/)
2. Select your region (us-east-1, us-west-2, or eu-west-1 recommended)
3. **Model access** (left sidebar)
4. **Enable** → Select **Claude 3.7 Sonnet**
5. Request access (usually instant approval)

### Step 5: Start the Backend

```bash
cd aegis-iam/agent

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend
uvicorn main:app --reload --port 8000
```

**Backend should now be running at:** http://localhost:8000

### Step 6: Start the Frontend

Open a **new terminal window** (keep backend running):

```bash
cd aegis-iam/frontend

# Install dependencies
npm install

# Create .env file
echo "VITE_API_URL=http://localhost:8000" > .env

# Start frontend
npm run dev
```

**Frontend should now be running at:** http://localhost:5173

### Step 7: Open the App

1. Open your browser
2. Visit: **http://localhost:5173**
3. Click "Add AWS" or "Configure AWS"
4. The wizard should detect your AWS CLI credentials ✅
5. Start using all features!

---

## Verify Installation

### Test 1: Check AWS CLI
```bash
aws sts get-caller-identity
```

**Expected output:**
```json
{
    "UserId": "AIDA...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-username"
}
```

### Test 2: Check Bedrock Access
```bash
aws bedrock list-foundation-models --region us-east-1
```

**Expected:** List of available models

### Test 3: Check Backend
Visit: http://localhost:8000/docs

**Expected:** FastAPI documentation page

### Test 4: Check Frontend
Visit: http://localhost:5173

**Expected:** Aegis IAM landing page

---

## Using the App

Once everything is running:

### 1. Generate IAM Policy
- Type: "Create an IAM policy for a Lambda function that reads from S3"
- Click Generate
- Get a complete IAM policy in seconds

### 2. Validate Policy
- Paste any IAM policy
- Get security analysis and recommendations
- Check compliance (PCI DSS, HIPAA, GDPR, etc.)

### 3. Audit AWS Account
- Click "Audit Account"
- Select compliance frameworks
- Get comprehensive security report
- Identify risks and unused permissions

### 4. Deploy to AWS
- Generate a policy
- Click "Deploy to AWS"
- Enter role name
- Deploy directly to your account

### 5. Export to IaC
- Generate a policy
- Export as CloudFormation, Terraform, or YAML
- Use in your infrastructure code

---

## Troubleshooting

### Problem: "No Credentials Found"

**Solution:**
```bash
# Verify AWS CLI is configured
aws configure list

# Reconfigure if needed
aws configure
```

### Problem: "Bedrock not available"

**Solutions:**
1. **Wrong region:** Use us-east-1, us-west-2, or eu-west-1
2. **Not enabled:** Enable Bedrock in AWS Console
3. **No access:** Request model access in Bedrock Console

### Problem: Backend won't start

**Solutions:**
```bash
# Make sure you're in the agent directory
cd aegis-iam/agent

# Activate venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux

# Install dependencies again
pip install -r requirements.txt

# Try starting
uvicorn main:app --reload --port 8000
```

### Problem: Frontend won't start

**Solutions:**
```bash
# Make sure you're in the frontend directory
cd aegis-iam/frontend

# Install dependencies
npm install

# Create .env file
echo "VITE_API_URL=http://localhost:8000" > .env

# Start
npm run dev
```

### Problem: Port already in use

**Backend (port 8000):**
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID [PID] /F

# Mac/Linux
lsof -ti:8000 | xargs kill -9
```

**Frontend (port 5173):**
```bash
# Windows
netstat -ano | findstr :5173
taskkill /PID [PID] /F

# Mac/Linux
lsof -ti:5173 | xargs kill -9
```

---

## Project Structure

```
aegis-iam/
├── agent/              # Backend (FastAPI)
│   ├── features/       # Feature modules
│   ├── utils/          # Utilities
│   ├── main.py         # FastAPI app
│   └── requirements.txt
│
├── frontend/           # Frontend (React)
│   ├── src/
│   │   ├── components/ # React components
│   │   ├── services/   # API layer
│   │   └── utils/      # Utilities
│   └── package.json
│
└── README.md
```

---

## Updating the App

To get the latest features:

```bash
# Pull latest code
git pull origin main

# Update backend dependencies
cd agent
pip install -r requirements.txt

# Update frontend dependencies
cd ../frontend
npm install

# Restart both backend and frontend
```

---

## Security Best Practices

✅ **Never commit credentials** to Git  
✅ **Use IAM roles** for EC2/ECS deployments  
✅ **Rotate credentials** regularly  
✅ **Use least privilege** IAM policies  
✅ **Enable MFA** on your AWS account  
✅ **Monitor CloudTrail** for unusual activity  

---

## AWS Costs

Running locally, you only pay for:

- **Amazon Bedrock** (Claude 3.7 Sonnet)
  - ~$0.01-$0.05 per policy generation
  - ~$0.02-$0.08 per validation
  - ~$0.10-$0.50 per full account audit

**The app itself is free!** You only pay for AWS services you use.

Monitor costs: [AWS Billing Dashboard](https://console.aws.amazon.com/billing/)

---

## Support

### GitHub Issues
Report bugs: https://github.com/bhavikam28/aegis-iam/issues

### Documentation
- [README.md](README.md) - Project overview
- [TEST_SCENARIOS.md](TEST_SCENARIOS.md) - Test all features
- [DEPLOYMENT.md](DEPLOYMENT.md) - Deploy to Render/Railway

---

## Next Steps

1. ✅ Complete local setup
2. ✅ Test all features
3. 📚 Read [TEST_SCENARIOS.md](TEST_SCENARIOS.md) for comprehensive testing
4. 🚀 Start securing your AWS IAM policies!

---

**You're all set! Your AWS credentials stay secure on your machine while you enjoy all features.**

