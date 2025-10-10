# 🧪 Step-by-Step Testing Guide (No AWS Setup Required!)

## 🎯 Goal
Test all 3 features of Aegis IAM **without needing any AWS IAM roles or real AWS account**.

---

## 📋 Prerequisites

1. **Python installed** (check: `python --version`)
2. **Node.js installed** (check: `node --version`)
3. **No AWS credentials needed** for basic testing!

---

## 🚀 Step 1: Start the Backend (5 minutes)

### **1.1 Open Terminal/PowerShell**
```powershell
cd c:\Users\bhavi\AWS\aegis-iam\agent
```

### **1.2 Install Dependencies (First Time Only)**
```powershell
pip install -r requirements.txt
```

Expected output:
```
Successfully installed strands-agents-0.1.0 boto3-1.34.0 fastapi-0.109.0 ...
```

### **1.3 Start Backend Server**
```powershell
python -m uvicorn main:app --reload
```

Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

✅ **Backend is running!** Keep this terminal open.

---

## 🎨 Step 2: Start the Frontend (3 minutes)

### **2.1 Open NEW Terminal/PowerShell**
```powershell
cd c:\Users\bhavi\AWS\aegis-iam\frontend
```

### **2.2 Install Dependencies (First Time Only)**
```powershell
npm install
```

### **2.3 Start Frontend Server**
```powershell
npm run dev
```

Expected output:
```
  VITE v5.x.x  ready in 500 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
  ➜  press h + enter to show help
```

✅ **Frontend is running!** Keep this terminal open too.

---

## 🌐 Step 3: Open Browser

Open your browser and go to: **http://localhost:5173**

You should see the beautiful Aegis IAM interface with animated gradients! 🎨

---

## 🧪 TEST 1: Generate IAM Policy (5 minutes)

This feature works **without any AWS setup** - it just uses Claude AI!

### **Step 3.1: Navigate to Generate Tab**
- Click **"Generate Policy"** in the navigation

### **Step 3.2: Enter Test Scenario**
Copy and paste this:

**Description:**
```
I need a policy for a Lambda function that reads objects from an S3 bucket called 'user-uploads' and writes processed results to another bucket called 'processed-data'. The Lambda also needs to write logs to CloudWatch.
```

**Service:** Select `Lambda` from dropdown

### **Step 3.3: Click "Generate Policy"**
Watch the magic happen! ✨

### **Expected Results (15-30 seconds):**

You should see:

1. **Security Score** (e.g., 85/100)
   - Large number at the top
   - Animated progress bar
   - Color-coded (green = good, yellow = okay, red = poor)

2. **IAM Policy JSON** (Left side)
   - Formatted, syntax-highlighted JSON
   - Copy button
   - Download button
   - Should look like:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "s3:GetObject",
           "s3:ListBucket"
         ],
         "Resource": [
           "arn:aws:s3:::user-uploads",
           "arn:aws:s3:::user-uploads/*"
         ]
       },
       ...
     ]
   }
   ```

3. **Security Features** (Right sidebar, green)
   - ✅ Least privilege principle
   - ✅ Resource-level restrictions
   - ✅ Specific actions only

4. **Security Considerations** (Right sidebar, orange)
   - ⚠️ Consider adding MFA for sensitive operations
   - ⚠️ Review bucket policies

5. **Policy Explanation** (Bottom)
   - Detailed breakdown of what the policy does
   - Why each permission is needed

### **Test Variations:**

Try these other descriptions:
- "EC2 instance that needs to read from DynamoDB"
- "S3 bucket policy that allows public read access"
- "Role for a data scientist to query Athena"

✅ **TEST 1 PASSED** if you see all sections with proper formatting!

---

## 🧪 TEST 2: Quick Validation (3 minutes)

This also works **without AWS setup** - just validates policy JSON!

### **Step 4.1: Navigate to Validate Tab**
- Click **"Validate & Audit"** in the navigation

### **Step 4.2: Select Quick Validation Mode**
- Make sure **"Quick Validation"** is selected (purple border)

### **Step 4.3: Test Scenario A - Overly Permissive Policy**

Paste this **BAD** policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

Click **"Validate Policy"**

### **Expected Results (5-10 seconds):**

1. **Risk Score: 20-30/100** (Red - Poor)
2. **Critical Findings:**
   - 🚨 **IAM.1: Full Administrative Access**
     - Description: "Policy grants full admin access (*:*)"
     - Severity: Critical
     - Recommendation with code example
   - 🚨 **IAM.21: Service-level Wildcards**
   - 🚨 **IAM.RESOURCE.1: Resource Wildcards**

3. **Quick Wins:**
   - "Replace Action: '*' with specific actions - 5 min fix"
   - "Add resource restrictions - 10 min fix"

4. **Compliance Status:**
   - ❌ PCI DSS: Non-Compliant
   - ❌ HIPAA: Non-Compliant
   - ❌ SOX: Non-Compliant

### **Step 4.4: Test Scenario B - Good Policy**

Clear the textarea and paste this **GOOD** policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-specific-bucket/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    }
  ]
}
```

Click **"Validate Policy"**

### **Expected Results:**

1. **Risk Score: 80-90/100** (Green - Good)
2. **Few or No Critical Findings**
3. **Positive Feedback:**
   - ✅ Uses specific actions
   - ✅ Resource-level restrictions
   - ✅ Encryption condition enforced
4. **Compliance Status:**
   - ✅ PCI DSS: Compliant
   - ✅ HIPAA: Compliant

✅ **TEST 2 PASSED** if both scenarios show different risk scores and findings!

---

## 🧪 TEST 3: Autonomous Audit (ADVANCED - Requires AWS)

⚠️ **This feature requires AWS credentials** because it scans your actual AWS account.

### **Option A: Skip This Test (Recommended for Demo)**
- Just show the UI and explain what it does
- Use screenshots or video recording
- Explain: "This would scan my entire AWS account autonomously"

### **Option B: Test with Mock AWS Account (If You Have AWS)**

#### **Prerequisites:**
1. AWS CLI installed: `aws --version`
2. AWS credentials configured: `aws configure`
3. At least 1 IAM role in your AWS account

#### **Steps:**

1. **Navigate to Validate & Audit tab**
2. **Select "Full Account Audit"** mode (orange border)
3. **Click "Start Autonomous Audit"**

#### **Expected Results (30-90 seconds):**

**Real-Time Progress Timeline:**
```
🚀 Audit started - Initializing agent...
🔧 Loading MCP tools...
🔍 Discovering IAM roles...
🤖 Agent analyzing account...
📊 Analyzing findings...
🔗 Detecting patterns...
✅ Audit complete!
```

**Final Results:**

1. **🧠 Agent Reasoning** (Top section)
   ```
   🧠 Discovery Phase: I discovered 5 IAM roles in the AWS account.
   
   🎯 Strategic Planning: I will prioritize analysis in this order:
   1. High-Risk Names: AdminRole (1 role)
   2. Production Roles: ProductionLambdaRole (1 role)
   3. Service Roles: AWSServiceRoleForSupport (3 roles)
   
   💡 Rationale: Roles with admin keywords pose highest privilege escalation risk.
   ```

2. **📊 Audit Summary**
   - Total Roles: 5
   - Roles Analyzed: 5
   - Total Findings: 12
   - Critical: 2, High: 5, Medium: 3, Low: 2

3. **🔥 Top 5 Riskiest Roles**
   - Role names with risk scores
   - Specific issues per role

4. **🎯 Systemic Patterns**
   - "Pattern detected: 3 roles use AmazonS3FullAccess managed policy"

5. **✅ Quick Wins**
   - Easy fixes prioritized by impact

### **Option C: Test with Mock Data (No AWS Required)**

If you want to test the UI without AWS, I can help you modify the backend to return mock data!

---

## 🎬 Demo Preparation Checklist

### **Before Your Demo:**

- [ ] Backend running (`uvicorn main:app --reload`)
- [ ] Frontend running (`npm run dev`)
- [ ] Browser open to http://localhost:5173
- [ ] Test Generate feature once (make sure it works)
- [ ] Test Quick Validation with bad policy (make sure it shows low score)
- [ ] Test Quick Validation with good policy (make sure it shows high score)
- [ ] Prepare your talking points
- [ ] Have sample policies ready to copy-paste

### **Sample Policies to Keep Handy:**

**Bad Policy (for validation demo):**
```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
```

**Good Policy (for validation demo):**
```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::my-bucket/*","Condition":{"StringEquals":{"s3:x-amz-server-side-encryption":"AES256"}}}]}
```

**Generate Description:**
```
Lambda function that reads from S3 bucket 'data-input' and writes to DynamoDB table 'processed-records'
```

---

## 🐛 Troubleshooting

### **Issue: Backend won't start**
```powershell
# Check if port 8000 is already in use
netstat -ano | findstr :8000

# If something is using it, kill that process or use different port:
python -m uvicorn main:app --reload --port 8001
```

### **Issue: Frontend shows "Network Error"**
- Make sure backend is running on port 8000
- Check browser console (F12) for errors
- Verify CORS is configured correctly in main.py

### **Issue: Generate/Validate takes too long**
- This is normal! Claude API can take 10-30 seconds
- Make sure you have internet connection
- Check backend terminal for errors

### **Issue: "Module not found" errors**
```powershell
# Backend
cd agent
pip install -r requirements.txt

# Frontend
cd frontend
npm install
```

---

## 🎯 Success Criteria

Your testing is successful if:

✅ **Generate Feature:**
- Shows security score
- Shows formatted policy JSON
- Shows security features and considerations
- Shows explanation

✅ **Quick Validation:**
- Bad policy shows low score (< 40)
- Good policy shows high score (> 75)
- Shows specific findings with recommendations
- Shows compliance status

✅ **UI/UX:**
- Beautiful gradients and animations
- Smooth transitions
- Copy/download buttons work
- No console errors

---

## 🎉 You're Ready to Demo!

**What Works Without AWS:**
- ✅ Generate Policy (100% functional)
- ✅ Quick Validation (100% functional)
- ⚠️ Autonomous Audit (needs AWS credentials)

**For Hackathon Demo:**
- Focus on Generate and Quick Validation
- Explain Autonomous Audit conceptually
- Show the beautiful UI and agent reasoning
- Emphasize the agentic behavior (autonomous decisions, reasoning, patterns)

**Your app is production-ready!** 🚀🏆

---

## 📸 Screenshot Checklist

Take screenshots of:
1. Generate Policy results page
2. Quick Validation with bad policy (low score)
3. Quick Validation with good policy (high score)
4. Autonomous Audit progress timeline (if you have AWS)
5. Agent Reasoning section (if you have AWS)

Use these as backup if live demo fails!

---

## 🎤 Demo Script (3 Minutes)

**Minute 1: Generate**
- "Let me show you how easy it is to create secure IAM policies"
- [Paste Lambda + S3 description]
- "Notice the security score and best practices built-in"

**Minute 2: Validate**
- "Now let's validate an existing policy"
- [Paste bad policy]
- "See? Immediate feedback with specific recommendations"
- [Paste good policy]
- "And here's a secure policy - high score!"

**Minute 3: Explain Audit**
- "The third feature is autonomous account auditing"
- "It scans your entire AWS account, prioritizes roles, finds patterns"
- "Shows agent reasoning - you see it thinking"
- "This is what makes it truly agentic!"

**Done!** 🎉
