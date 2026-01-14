# Testing Guide - Connect Your AWS Account

This guide will help you test Aegis IAM with your AWS account before delivering.

---

## 📋 Prerequisites Checklist

Before starting, make sure you have:

- [ ] AWS Account (with access to IAM and Bedrock)
- [ ] AWS Access Key ID and Secret Access Key
- [ ] Python 3.11+ installed
- [ ] Node.js 18+ installed
- [ ] AWS CLI installed (or install it below)

---

## Step 1: Install AWS CLI (If Not Already Installed)

### Windows (PowerShell as Administrator):
```powershell
# Download AWS CLI MSI installer
# Visit: https://awscli.amazonaws.com/AWSCLIV2.msi
# Or use winget:
winget install Amazon.AWSCLI
```

### macOS:
```bash
brew install awscli
```

### Linux:
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

**Verify Installation:**
```bash
aws --version
# Should show: aws-cli/2.x.x
```

---

## Step 2: Configure AWS CLI Credentials

**IMPORTANT:** This step stores your AWS credentials locally on your machine (in `~/.aws/credentials` on Linux/Mac, or `%USERPROFILE%\.aws\credentials` on Windows).

### Run AWS Configure:
```bash
aws configure
```

**You'll be prompted for 4 things:**

1. **AWS Access Key ID:** 
   - Get this from: AWS Console → IAM → Users → Your User → Security Credentials → Create Access Key
   - Example: `AKIAIOSFODNN7EXAMPLE`

2. **AWS Secret Access Key:**
   - Get this from the same place (only shown once!)
   - Example: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

3. **Default region name:**
   - Use: `us-east-1` (or your preferred region)
   - Common options: `us-east-1`, `us-west-2`, `eu-west-1`

4. **Default output format:**
   - Press Enter (defaults to `json`)

**Example Session:**
```bash
$ aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-east-1
Default output format [None]: json
```

### Verify AWS CLI is Working:
```bash
aws sts get-caller-identity
```

**Expected Output:**
```json
{
    "UserId": "AIDAXXXXXXXXXXXXXXXXX",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-username"
}
```

**If you see an error:**
- Check your Access Key ID and Secret Access Key
- Make sure you have IAM permissions (at minimum: `sts:GetCallerIdentity`)

---

## Step 3: Enable Bedrock Access (Required for AI Features)

The application uses **Amazon Bedrock** (Claude Sonnet 4.5) for AI features. You need to enable it:

1. **Go to AWS Console:** https://console.aws.amazon.com/bedrock/
2. **Click "Model access"** (left sidebar)
3. **Click "Edit"** (top right)
4. **Find "Claude Sonnet 4.5"** and **Enable** it
5. **Click "Save changes"**

**Note:** This is free to enable. You only pay per API call (~$0.01-0.10 per policy generation).

---

## Step 4: Create IAM Policy (Minimum Required Permissions)

Create an IAM user or attach this policy to your existing user:

**IAM Policy JSON:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
    }
  ]
}
```

**How to attach:**
1. Go to: AWS Console → IAM → Users → Your User → Permissions
2. Click "Add permissions" → "Attach policies directly"
3. Click "Create policy" → JSON tab → Paste the policy above
4. Name it: `AegisIAMMinimumPolicy`
5. Click "Create policy"
6. Go back to your user → Add permissions → Attach the policy you just created

---

## Step 5: Start Backend Server

**Open Terminal/PowerShell in the project root:**

```bash
# Navigate to agent directory
cd agent

# Create virtual environment (if not already created)
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Windows (CMD):
venv\Scripts\activate.bat
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend server
uvicorn main:app --reload --port 8000
```

**You should see:**
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

**✅ Backend is running!** Keep this terminal open.

---

## Step 6: Start Frontend Server

**Open a NEW Terminal/PowerShell window in the project root:**

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies (first time only)
npm install

# Create .env file (if not exists)
echo VITE_API_URL=http://localhost:8000 > .env

# On Windows PowerShell, use:
# "VITE_API_URL=http://localhost:8000" | Out-File -FilePath .env -Encoding utf8

# Start frontend server
npm run dev
```

**You should see:**
```
VITE v5.x.x  ready in xxx ms

➜  Local:   http://localhost:5173/
➜  Network: use --host to expose
```

**✅ Frontend is running!** Keep this terminal open.

---

## Step 7: Test the Connection

### 7.1 Open the Application

1. **Open your browser:** http://localhost:5173
2. **Click "Get Started"** (not "Explore Demo")
3. **You should see the Dashboard with 4 tabs:**
   - Generate Policy
   - Validate Policy
   - Audit Account
   - CI/CD Integration

### 7.2 Test AWS Credentials Detection

**The app should automatically detect your AWS CLI credentials!**

**Check the top right corner:**
- If you see **"AWS ✓"** button → ✅ Credentials detected!
- If you see **"Add AWS"** button → Click it to open the setup wizard

### 7.3 Test Policy Generation (Quick Test)

1. **Click "Generate Policy" tab**
2. **Fill in the form:**
   - Description: `Lambda function to read from S3 bucket my-test-bucket`
   - Check "Maximum Security"
   - Compliance: "General"
3. **Click "Generate Policy"**
4. **Wait 10-30 seconds** (Bedrock API call)
5. **You should see:**
   - Generated Permissions Policy (JSON)
   - Generated Trust Policy (JSON)
   - Security Scores
   - Compliance Status
   - Explanation

**✅ If you see policies generated → AWS connection is working!**

### 7.4 Test Policy Validation

1. **Click "Validate Policy" tab**
2. **Select "Policy JSON"**
3. **Paste a sample policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    }
  ]
}
```
4. **Click "Validate Policy"**
5. **You should see:**
   - Security Score
   - Findings (security issues)
   - Recommendations

**✅ If you see validation results → AWS connection is working!**

---

## 🔍 Troubleshooting

### Issue: "No Credentials Found" Error

**Solution:**
1. Verify AWS CLI is configured: `aws sts get-caller-identity`
2. If that works, restart the backend server
3. Make sure you're running locally (not on Vercel)

### Issue: "Bedrock Access Denied"

**Solution:**
1. Enable Bedrock model access (Step 3)
2. Wait 5-10 minutes after enabling (AWS propagation delay)
3. Check your IAM permissions include `bedrock:InvokeModel`

### Issue: Backend won't start

**Solution:**
```bash
# Make sure you're in the agent directory
cd agent

# Activate virtual environment
.\venv\Scripts\Activate.ps1  # Windows
# or
source venv/bin/activate  # Mac/Linux

# Check Python version
python --version  # Should be 3.11+

# Reinstall dependencies
pip install -r requirements.txt --upgrade
```

### Issue: Frontend won't start

**Solution:**
```bash
# Make sure you're in the frontend directory
cd frontend

# Check Node version
node --version  # Should be 18+

# Delete node_modules and reinstall
rm -rf node_modules package-lock.json  # Mac/Linux
# or
Remove-Item -Recurse -Force node_modules, package-lock.json  # Windows
npm install
```

### Issue: CORS Errors

**Solution:**
- Make sure backend is running on port 8000
- Make sure frontend .env file has: `VITE_API_URL=http://localhost:8000`
- Restart both servers

---

## ✅ Success Checklist

Before delivering, verify:

- [ ] AWS CLI configured: `aws sts get-caller-identity` works
- [ ] Backend running: http://localhost:8000
- [ ] Frontend running: http://localhost:5173
- [ ] Can generate a policy successfully
- [ ] Can validate a policy successfully
- [ ] "AWS ✓" button shows in navbar (credentials detected)
- [ ] No errors in browser console (F12 → Console tab)
- [ ] No errors in backend terminal

---

## 🎉 You're Ready!

If all tests pass, your AWS account is connected and the application is working correctly!

**Next Steps:**
- Test all features: Generate, Validate, Audit, CI/CD
- Try different compliance frameworks
- Test the "Explain Simply" feature
- Test "Deploy to AWS" feature (creates IAM roles)

**Remember:**
- AWS charges apply for Bedrock usage (~$0.01-0.10 per operation)
- All charges appear on **your AWS bill**
- Credentials stay on your machine (secure)

