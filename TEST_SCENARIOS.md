# Complete Test Scenarios for Aegis IAM

Use these test scenarios to verify all features work correctly on your Vercel deployment.

---

## Prerequisites

1. **AWS CLI Configured Locally**
   ```bash
   aws configure
   # Enter your Access Key ID
   # Enter your Secret Access Key
   # Enter default region (e.g., us-east-1)
   # Enter output format (json)
   ```

2. **Required IAM Permissions**
   - Your AWS user needs the policy from the setup wizard
   - Bedrock access enabled in your region

3. **Test on Vercel**: Visit [https://aegis-iam.vercel.app](https://aegis-iam.vercel.app)

---

## Feature 1: Policy Generation

### Test Scenario 1.1: Simple Lambda Function

**Input:**
```
Create an IAM policy for a Lambda function that needs to:
- Read from S3 bucket named "my-data-bucket"
- Write logs to CloudWatch
- Invoke another Lambda function named "process-data"
```

**Expected Results:**
- ✅ Policy generated with S3, CloudWatch, and Lambda permissions
- ✅ Trust policy for Lambda service
- ✅ Security score displayed
- ✅ Compliance framework adherence shown
- ✅ Explanation section populated

**What to Check:**
- [ ] Permissions policy is valid JSON
- [ ] Trust policy allows `lambda.amazonaws.com`
- [ ] No wildcard permissions (`*`) on resources
- [ ] Security score is reasonable (40-80)
- [ ] Can export as JSON, CloudFormation, Terraform, YAML

---

### Test Scenario 1.2: EC2 Instance with S3 Access

**Input:**
```
I need an IAM role for an EC2 instance that:
- Can read and write to S3 bucket "app-storage"
- Can send emails via SES
- Can access DynamoDB table "user-data"
```

**Expected Results:**
- ✅ Policy includes S3, SES, and DynamoDB permissions
- ✅ Trust policy for EC2 service
- ✅ Specific resource ARNs (not wildcards)
- ✅ Security recommendations provided

**What to Check:**
- [ ] Trust policy has `ec2.amazonaws.com`
- [ ] S3 permissions are bucket-specific
- [ ] DynamoDB permissions are table-specific
- [ ] Can download policy as JSON
- [ ] Can view in CloudFormation format

---

### Test Scenario 1.3: Conversational Refinement

**Input (Initial):**
```
Create a policy for a Lambda that reads from S3
```

**Then in chat:**
```
Actually, make it more restrictive - only allow read access to objects with prefix "public/"
```

**Expected Results:**
- ✅ Initial policy generated
- ✅ Chat interface appears
- ✅ Refinement request processed
- ✅ Updated policy with more restrictive permissions
- ✅ Conversation history maintained

**What to Check:**
- [ ] Chat messages appear in conversation
- [ ] Policy updates after refinement
- [ ] S3 permissions now include condition for prefix
- [ ] Can continue conversation with more changes

---

## Feature 2: Policy Validation

### Test Scenario 2.1: Validate a Good Policy

**Input Policy (JSON):**
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
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

**Expected Results:**
- ✅ Security score: 60-80 (Good)
- ✅ Few or no critical findings
- ✅ Compliance frameworks checked
- ✅ Recommendations provided

**What to Check:**
- [ ] Security score displayed (higher is better)
- [ ] Grade shown (A, B, C, or F)
- [ ] Findings list is reasonable
- [ ] Can export report as PDF
- [ ] Compliance status shown

---

### Test Scenario 2.2: Validate a Bad Policy (Wildcards)

**Input Policy (JSON):**
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

**Expected Results:**
- ✅ Security score: 0-20 (Poor)
- ✅ Multiple critical findings
- ✅ Warning about wildcard permissions
- ✅ Specific recommendations to fix

**What to Check:**
- [ ] Security score is low
- [ ] Grade is F or D
- [ ] Critical findings highlighted
- [ ] Recommendations include removing wildcards
- [ ] Code snippets provided for fixes

---

### Test Scenario 2.3: Validate with Compliance Framework

**Input Policy:**
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
      "Resource": "*"
    }
  ]
}
```

**Select Compliance:** PCI DSS

**Expected Results:**
- ✅ PCI DSS specific checks performed
- ✅ Findings related to PCI DSS requirements
- ✅ Compliance score for PCI DSS
- ✅ Links to PCI DSS documentation

**What to Check:**
- [ ] Compliance framework selected
- [ ] PCI DSS specific findings shown
- [ ] Compliance links work
- [ ] Recommendations mention PCI DSS requirements

---

## Feature 3: Account Audit

### Test Scenario 3.1: Full Account Audit

**Steps:**
1. Click "Audit Account"
2. Select compliance frameworks (or leave default)
3. Click "Start Audit"
4. Wait for completion (may take 2-5 minutes)

**Expected Results:**
- ✅ Progress updates via Server-Sent Events
- ✅ Audit completes successfully
- ✅ Summary dashboard shows:
  - Total roles analyzed
  - Total findings
  - Breakdown by severity (Critical, High, Medium, Low)
  - Security score
- ✅ Findings list with details
- ✅ CloudTrail analysis results

**What to Check:**
- [ ] Progress bar updates in real-time
- [ ] No errors during audit
- [ ] Findings are categorized correctly
- [ ] Can expand findings to see details
- [ ] Can remediate critical issues
- [ ] Export options work

---

### Test Scenario 3.2: Remediate Critical Issues

**Steps:**
1. Run an audit (from Scenario 3.1)
2. Wait for completion
3. Click "Remediate Critical Issues" button
4. Review remediation results

**Expected Results:**
- ✅ Critical findings identified
- ✅ Remediation attempted for each
- ✅ Success/failure status for each fix
- ✅ Updated policies shown
- ✅ Logs of what was changed

**What to Check:**
- [ ] Remediation button appears when critical issues found
- [ ] Each remediation shows status
- [ ] Successfully fixed issues are marked
- [ ] Failed remediations show error messages
- [ ] Can view before/after policy changes

---

## Feature 4: CI/CD Integration

### Test Scenario 4.1: View CI/CD Status

**Steps:**
1. Navigate to "CI/CD Integration" page
2. Check GitHub App status

**Expected Results:**
- ✅ GitHub App configuration status shown
- ✅ Installation URL provided (if not installed)
- ✅ Recent analysis results displayed (if any)
- ✅ Setup instructions clear

**What to Check:**
- [ ] Page loads without errors
- [ ] Status information is accurate
- [ ] Links to GitHub work
- [ ] Analysis results section visible

---

## Feature 5: IaC Export

### Test Scenario 5.1: Export as CloudFormation

**Steps:**
1. Generate a policy (use Scenario 1.1)
2. Click "Export as" dropdown
3. Select "CloudFormation"
4. View the CloudFormation template

**Expected Results:**
- ✅ CloudFormation YAML/JSON generated
- ✅ Includes IAM Role resource
- ✅ Includes IAM Policy resource
- ✅ Valid CloudFormation syntax
- ✅ Can copy to clipboard

**What to Check:**
- [ ] CloudFormation format is correct
- [ ] Resources are properly defined
- [ ] Can copy the code
- [ ] Can download as file

---

### Test Scenario 5.2: Export as Terraform

**Steps:**
1. Generate a policy
2. Click "Export as" → "Terraform"
3. View the Terraform HCL

**Expected Results:**
- ✅ Terraform HCL generated
- ✅ Uses `aws_iam_role` resource
- ✅ Uses `aws_iam_role_policy` or `aws_iam_policy`
- ✅ Valid Terraform syntax
- ✅ Can copy/download

**What to Check:**
- [ ] Terraform syntax is valid
- [ ] Resources use correct provider
- [ ] Variables are properly formatted
- [ ] Can use in Terraform projects

---

## Feature 6: Deploy to AWS

### Test Scenario 6.1: Deploy IAM Role

**Steps:**
1. Generate a policy (use Scenario 1.1)
2. Click "Deploy to AWS" button
3. Fill in:
   - Role Name: `test-lambda-role-12345` (use unique name)
   - Region: `us-east-1`
   - Description: "Test deployment"
4. Click "Deploy"

**Expected Results:**
- ✅ Deployment starts
- ✅ Progress indicator shown
- ✅ Success message with role ARN
- ✅ Role created in AWS account
- ✅ Policy attached to role

**What to Check:**
- [ ] Deployment completes successfully
- [ ] Role appears in AWS Console
- [ ] Policy is attached correctly
- [ ] Can verify in AWS IAM console
- [ ] Error handling works if deployment fails

---

## Feature 7: Explain Simply

### Test Scenario 7.1: Get Simple Explanation

**Steps:**
1. Generate a policy (use Scenario 1.1)
2. Click "Explain Simply" button
3. Wait for explanation

**Expected Results:**
- ✅ Modal opens with explanation
- ✅ Plain language (no technical jargon)
- ✅ Explains what the policy does
- ✅ Explains security implications
- ✅ Suitable for non-technical stakeholders

**What to Check:**
- [ ] Explanation is clear and simple
- [ ] No AWS-specific jargon
- [ ] Explains business purpose
- [ ] Mentions security aspects
- [ ] Can copy explanation

---

## Feature 8: AWS Setup Wizard

### Test Scenario 8.1: Complete Setup Flow

**Steps:**
1. Click "Add AWS" or "Configure AWS"
2. Go through all 3 steps:
   - Step 1: Verify credentials
   - Step 2: Review IAM policy
   - Step 3: Complete setup

**Expected Results:**
- ✅ Credentials detected (if AWS CLI configured)
- ✅ Account ID shown (masked)
- ✅ Bedrock access confirmed
- ✅ Can proceed through all steps
- ✅ Setup completes successfully

**What to Check:**
- [ ] Wizard opens correctly
- [ ] Credentials are detected
- [ ] Region dropdown shows all regions
- [ ] Can navigate between steps
- [ ] Completion works

---

## Feature 9: Format Preview Tabs

### Test Scenario 9.1: Switch Between Formats

**Steps:**
1. Generate a policy
2. Click format tabs: JSON, CloudFormation, Terraform, YAML
3. Verify each format displays correctly

**Expected Results:**
- ✅ All format tabs work
- ✅ Content updates when switching tabs
- ✅ Code is properly formatted
- ✅ Syntax highlighting (if implemented)
- ✅ Can copy from any format

**What to Check:**
- [ ] JSON tab shows valid JSON
- [ ] CloudFormation tab shows valid YAML
- [ ] Terraform tab shows valid HCL
- [ ] YAML tab shows valid YAML
- [ ] Switching is smooth

---

## Feature 10: Trust Policy Features

### Test Scenario 10.1: Trust Policy Export and Deploy

**Steps:**
1. Generate a policy with trust policy
2. Go to Trust Policy section
3. Test export options
4. Test "Deploy to AWS" for trust policy

**Expected Results:**
- ✅ Trust policy shown separately
- ✅ Can export trust policy in all formats
- ✅ Can deploy role with trust policy
- ✅ Trust policy explanation shown

**What to Check:**
- [ ] Trust policy section is visible
- [ ] Export works for trust policy
- [ ] Deploy includes trust policy
- [ ] Explanation is clear

---

## Common Issues to Watch For

### ❌ API Connection Errors
- **Symptom**: "Failed to connect" or CORS errors
- **Check**: Verify `VITE_API_URL` is set in Vercel
- **Fix**: Set environment variable and redeploy

### ❌ Backend Timeout
- **Symptom**: Requests timeout after 30+ seconds
- **Check**: Render service might be sleeping (free tier)
- **Fix**: Wait for cold start, or upgrade Render plan

### ❌ AWS Credentials Not Found
- **Symptom**: "No credentials found" in wizard
- **Check**: AWS CLI configured locally
- **Fix**: Run `aws configure` on your machine

### ❌ Bedrock Access Denied
- **Symptom**: "Bedrock not available" error
- **Check**: Bedrock enabled in your AWS region
- **Fix**: Enable Bedrock in AWS Console

---

## Success Criteria

All features should:
- ✅ Load without errors
- ✅ Connect to Render backend (not localhost)
- ✅ Process requests successfully
- ✅ Display results correctly
- ✅ Handle errors gracefully
- ✅ Work on first try (after cold start)

---

## Quick Test Checklist

Run through these quickly:

- [ ] Homepage loads
- [ ] AWS Setup Wizard opens
- [ ] Generate Policy works
- [ ] Validate Policy works
- [ ] Account Audit starts
- [ ] Export options work
- [ ] Deploy to AWS works
- [ ] Explain Simply works
- [ ] CI/CD page loads
- [ ] No console errors
- [ ] All API calls go to Render URL

---

**Test each feature thoroughly and report any issues!**

