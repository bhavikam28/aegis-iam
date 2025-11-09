# 🧪 Generate Policy Feature - Production Testing Guide

**Date:** 2025-01-27  
**Purpose:** Complete end-to-end testing before production submission  
**Status:** ✅ **PRODUCTION READY** - Use these scenarios to validate

---

## ✅ PRE-TESTING CHECKLIST

Before starting, verify:
- [ ] Backend server is running (`cd agent && python -m uvicorn main:app --reload`)
- [ ] Frontend is running (`cd frontend && npm run dev`)
- [ ] AWS credentials are configured (for Bedrock API)
- [ ] Browser console is open (F12) to check for errors
- [ ] Network tab is open to monitor API calls

---

## 🎯 CRITICAL PRODUCTION SCENARIOS

### **Scenario 1: Basic Lambda + S3 Policy Generation** ✅ MUST TEST

**Purpose:** Validate core functionality works end-to-end

**Steps:**
1. Navigate to "Generate Policy" page
2. Enter description: `"Lambda function that needs to read files from an S3 bucket named customer-uploads"`
3. Select "Maximum Security" mode
4. Select "General Security" compliance
5. Click "Generate Secure Policy"
6. Wait for generation to complete

**Expected Results:**
- ✅ Loading spinner shows "Aegis AI Analyzing"
- ✅ Both Permissions Policy and Trust Policy are generated
- ✅ Permissions Policy includes: `s3:ListBucket`, `s3:GetObject`
- ✅ Trust Policy uses: `lambda.amazonaws.com` principal
- ✅ Security scores displayed (Permissions, Trust, Overall)
- ✅ Scores are between 0-100
- ✅ "Policies Generated Successfully" header appears
- ✅ Explanations section shows policy breakdown
- ✅ No errors in console

**What to Check:**
- [ ] Service detection works (should detect 'lambda')
- [ ] Both policies are valid JSON (no syntax errors)
- [ ] Trust policy has correct service principal
- [ ] Permissions policy has specific actions (not wildcards)
- [ ] Resources are scoped (not `*`)
- [ ] Scores make sense (higher = better security)
- [ ] UI is responsive and premium-looking

**Screenshots to Capture:**
- Initial form submission
- Loading state
- Results page (scores, policies, explanations)

---

### **Scenario 2: Compliance Validation (NEW FEATURE)** ✅ MUST TEST

**Purpose:** Validate compliance validation works correctly

**Steps:**
1. Navigate to "Generate Policy" page
2. Enter description: `"Lambda function that needs to read files from an S3 bucket named customer-uploads"`
3. Select "Maximum Security" mode
4. **Select "CIS Benchmarks" compliance** (or PCI DSS, HIPAA, SOX, GDPR)
5. Click "Generate Secure Policy"
6. Wait for generation to complete
7. Scroll to "Compliance Status" section

**Expected Results:**
- ✅ Policy is generated successfully
- ✅ "Compliance Status" subsection appears in results
- ✅ Compliance summary banner shows (Compliant or Non-Compliant)
- ✅ Framework card displays with status
- ✅ If non-compliant: Shows violations/gaps with "How to Fix"
- ✅ If compliant: Shows "All requirements met"
- ✅ Compliance rate percentage displayed

**What to Check:**
- [ ] Compliance section appears (not missing)
- [ ] Correct framework name displayed
- [ ] Status is accurate (Compliant/Non-Compliant)
- [ ] Violations are clearly listed
- [ ] "How to Fix" guidance is actionable
- [ ] UI matches Validate Policy design

**Screenshots to Capture:**
- Compliance dropdown selection
- Compliance Status section
- Violations/gaps display (if any)

---

### **Scenario 3: Service Detection (Multiple Services)** ✅ MUST TEST

**Purpose:** Validate service auto-detection works for different AWS services

**Test Cases:**

#### **3A: ECS Service Detection**
- **Description:** `"ECS task that needs to read and write to a DynamoDB table called user-sessions"`
- **Expected:** Service detected as 'ecs', Trust Policy uses `ecs-tasks.amazonaws.com`

#### **3B: EC2 Service Detection**
- **Description:** `"EC2 instance that needs to send logs to CloudWatch Logs"`
- **Expected:** Service detected as 'ec2', Trust Policy uses `ec2.amazonaws.com`

#### **3C: S3 Service Detection**
- **Description:** `"S3 bucket that needs to allow cross-account access"`
- **Expected:** Service detected as 's3', Trust Policy uses `s3.amazonaws.com`

**What to Check:**
- [ ] Correct service is detected (check backend logs)
- [ ] Trust policy uses correct service principal
- [ ] No fallback to 'lambda' for non-Lambda services

**Backend Logs to Check:**
```
🔍 Service detection: 'ecs' (confidence: X)
✅ Service principal: ecs → ecs-tasks.amazonaws.com
```

---

### **Scenario 4: Chatbot - Policy Modification** ✅ MUST TEST

**Purpose:** Validate chatbot always returns both policies in JSON format

**Steps:**
1. Generate a policy using Scenario 1
2. Click chatbot icon (bottom right)
3. In chatbot, type: `"Add MFA requirement to the permissions policy"`
4. Click Send
5. Wait for response

**Expected Results:**
- ✅ Chatbot returns BOTH policies in JSON format
- ✅ Permissions Policy includes Condition block with `aws:MultiFactorAuthPresent: true`
- ✅ Trust Policy is included (even if unchanged)
- ✅ Both policies wrapped in ```json code blocks
- ✅ Response is helpful and clear

**What to Check:**
- [ ] Both policies are returned (not just one)
- [ ] JSON format is valid (no syntax errors)
- [ ] MFA condition is added correctly
- [ ] Trust policy is included
- [ ] No errors in console

**Screenshots to Capture:**
- Chatbot input
- Chatbot response (showing both policies)

---

### **Scenario 5: Chatbot - Explanation Request** ✅ MUST TEST

**Purpose:** Validate chatbot handles explanation requests correctly

**Steps:**
1. Generate a policy using Scenario 1
2. Open chatbot
3. Type: `"Explain what the permissions policy does"`
4. Click Send

**Expected Results:**
- ✅ Chatbot provides clear explanation in plain text
- ✅ **ALSO returns BOTH policies in JSON format**
- ✅ Explanation is accurate and helpful
- ✅ Both policies are included for reference

**What to Check:**
- [ ] Explanation is clear and accurate
- [ ] Both policies are returned in JSON
- [ ] Format is correct (```json blocks)

---

### **Scenario 6: Chatbot - Policy Retrieval** ✅ MUST TEST

**Purpose:** Validate chatbot returns policies when requested

**Steps:**
1. Generate a policy using Scenario 1
2. Open chatbot
3. Type: `"Show me both policies"`
4. Click Send

**Expected Results:**
- ✅ Chatbot returns BOTH policies in JSON format
- ✅ Both policies are complete and valid
- ✅ Format is correct (```json blocks)

**What to Check:**
- [ ] Both policies returned
- [ ] JSON is valid
- [ ] No errors

---

### **Scenario 7: Complex Multi-Service Policy** ✅ MUST TEST

**Purpose:** Validate policy generation for complex requirements

**Steps:**
1. Enter description: `"Lambda function that reads from S3, writes to DynamoDB, and publishes to SNS"`
2. Select "Maximum Security"
3. Select "General Security"
4. Generate policy

**Expected Results:**
- ✅ Permissions Policy includes S3, DynamoDB, and SNS permissions
- ✅ Trust Policy uses `lambda.amazonaws.com`
- ✅ Statements are separated by service
- ✅ Explanations cover all services
- ✅ Scores reflect complexity

**What to Check:**
- [ ] All three services have permissions
- [ ] Statements are well-organized
- [ ] Explanations are comprehensive
- [ ] No missing permissions

---

### **Scenario 8: Edge Case - Unknown Service** ✅ MUST TEST

**Purpose:** Validate intelligent fallback for unknown services

**Steps:**
1. Enter description: `"New AWS service called myservice that needs basic permissions"`
2. Generate policy

**Expected Results:**
- ✅ Policy is generated successfully
- ✅ Trust Policy uses intelligent fallback (`myservice.amazonaws.com` or `lambda.amazonaws.com`)
- ✅ No errors or crashes
- ✅ User experience is smooth

**What to Check:**
- [ ] No errors occur
- [ ] Trust policy is generated
- [ ] Fallback works correctly

---

### **Scenario 9: Compliance - Multiple Frameworks** ✅ MUST TEST

**Purpose:** Validate compliance works for different frameworks

**Test Cases:**

#### **9A: PCI DSS Compliance**
- Select "PCI DSS"
- Generate policy
- Check compliance section for PCI DSS violations

#### **9B: HIPAA Compliance**
- Select "HIPAA"
- Generate policy
- Check compliance section for HIPAA violations

#### **9C: GDPR Compliance**
- Select "GDPR"
- Generate policy
- Check compliance section for GDPR violations

**What to Check:**
- [ ] Correct framework is validated
- [ ] Compliance section shows correct framework name
- [ ] Violations are framework-specific
- [ ] "How to Fix" guidance is relevant

---

### **Scenario 10: Error Handling** ✅ MUST TEST

**Purpose:** Validate graceful error handling

**Test Cases:**

#### **10A: Empty Description**
- Leave description empty
- Try to generate
- **Expected:** Validation error, cannot submit

#### **10B: Invalid JSON (if manually edited)**
- Generate policy normally
- If user edits JSON and makes it invalid, system should handle gracefully

#### **10C: Network Error (simulate)**
- Disconnect network
- Try to generate
- **Expected:** Error message displayed, user can retry

**What to Check:**
- [ ] Errors are user-friendly
- [ ] No crashes or blank screens
- [ ] User can recover from errors

---

## 📋 COMPREHENSIVE CHECKLIST

### **Functionality Checklist:**
- [ ] ✅ Policy generation works for all major services
- [ ] ✅ Service detection works correctly
- [ ] ✅ Both policies are always generated
- [ ] ✅ Security scores are calculated correctly
- [ ] ✅ Compliance validation works
- [ ] ✅ Chatbot always returns both policies
- [ ] ✅ Explanations are clear and accurate
- [ ] ✅ Error handling is graceful

### **UI/UX Checklist:**
- [ ] ✅ Premium design matches Audit Account
- [ ] ✅ All sections are visible and well-formatted
- [ ] ✅ Scores are displayed correctly
- [ ] ✅ Compliance section appears when framework selected
- [ ] ✅ Chatbot is responsive and helpful
- [ ] ✅ No layout issues on mobile/tablet
- [ ] ✅ Loading states are smooth
- [ ] ✅ No console errors

### **Data Quality Checklist:**
- [ ] ✅ Policies are valid JSON
- [ ] ✅ Service principals are correct
- [ ] ✅ Actions are specific (not wildcards)
- [ ] ✅ Resources are scoped (not `*`)
- [ ] ✅ Scores are accurate (0-100)
- [ ] ✅ Compliance violations are correct
- [ ] ✅ Explanations match policies

---

## 🚨 COMMON ISSUES TO WATCH FOR

### **Issue 1: Missing Policies**
- **Symptom:** Only one policy shown
- **Fix:** Check chatbot system prompt - should always return both

### **Issue 2: Invalid JSON**
- **Symptom:** JSON syntax errors in policies
- **Fix:** Check policy extraction regex patterns

### **Issue 3: Wrong Service Principal**
- **Symptom:** Trust policy uses wrong principal
- **Fix:** Check service detection logic

### **Issue 4: Missing Compliance Section**
- **Symptom:** Compliance section not appearing
- **Fix:** Check backend returns `compliance_status` in response

### **Issue 5: Scores Not Displayed**
- **Symptom:** Scores are blank or 0
- **Fix:** Check score extraction/calculation logic

### **Issue 6: Chatbot Not Returning Policies**
- **Symptom:** Chatbot only returns text
- **Fix:** Check chatbot system prompt - must return JSON

---

## 📸 SCREENSHOTS TO CAPTURE

For each scenario, capture:

1. **Initial Form:**
   - Description input
   - Security mode selection
   - Compliance framework selection

2. **Loading State:**
   - Spinner animation
   - Progress badges

3. **Results Display:**
   - "Policies Generated Successfully" header
   - Security Scores section
   - Permissions Policy JSON
   - Trust Policy JSON
   - Explanations section
   - **Compliance Status section** (if framework selected)
   - Refinement suggestions

4. **Chatbot Interactions:**
   - Chatbot greeting
   - User message
   - Chatbot response (showing both policies)
   - JSON formatting

5. **Error States:**
   - Validation errors
   - Network errors
   - API errors

---

## 🎯 PRIORITY TESTING ORDER

**Test in this order:**

1. **Scenario 1** - Basic functionality (MUST PASS)
2. **Scenario 2** - Compliance validation (NEW FEATURE - MUST PASS)
3. **Scenario 4** - Chatbot modification (CRITICAL - MUST PASS)
4. **Scenario 3** - Service detection (MUST PASS)
5. **Scenario 5** - Chatbot explanation (SHOULD PASS)
6. **Scenario 7** - Complex policies (SHOULD PASS)
7. **Scenario 9** - Multiple compliance frameworks (SHOULD PASS)
8. **Scenario 8** - Edge cases (NICE TO PASS)
9. **Scenario 10** - Error handling (NICE TO PASS)

---

## ✅ PRODUCTION READINESS CRITERIA

**Before submitting to production, ensure:**

- [ ] ✅ All "MUST PASS" scenarios pass
- [ ] ✅ No critical bugs found
- [ ] ✅ Compliance section works correctly
- [ ] ✅ Chatbot always returns both policies
- [ ] ✅ Service detection works for major services
- [ ] ✅ Scores are accurate
- [ ] ✅ UI is responsive and premium
- [ ] ✅ No console errors
- [ ] ✅ Error handling is graceful

---

## 📝 TESTING NOTES

1. **Test systematically:** Follow the order above
2. **Check backend logs:** Monitor service detection and compliance validation
3. **Verify data:** Check that policies match descriptions
4. **Test edge cases:** Don't skip Scenario 8 and 10
5. **Document issues:** Note any bugs found during testing

---

## 🚀 READY FOR PRODUCTION

Once all scenarios pass:
- ✅ Feature is production-ready
- ✅ All critical bugs fixed
- ✅ Compliance validation working
- ✅ Chatbot working correctly
- ✅ Service detection working
- ✅ Ready to submit!

---

**Last Updated:** 2025-01-27  
**Status:** Production Testing Guide - Ready for End-to-End Validation
