# GitHub App Setup - Quick Guide

## Step 1: Register GitHub App

1. Go to: https://github.com/settings/apps/new

2. Fill in these exact values:
   - **GitHub App name**: `Aegis IAM`
   - **Description**: `AI-powered IAM policy security analyzer. Automatically reviews AWS IAM policies in pull requests and provides security recommendations.`
   - **Homepage URL**: `https://aegis-iam.vercel.app/`
   - **User authorization callback URL**: `https://aegis-iam-backend.onrender.com/api/github/oauth/callback`
   - **Webhook URL**: `https://aegis-iam-backend.onrender.com/api/github/webhook`
   - **Webhook secret**: `f15a6b1f020ed357340a945ade30e7806fc5a2b5`

3. Permissions:
   - Contents: Read-only
   - Pull requests: Read & write
   - Issues: Write
   - Metadata: Read-only

4. Events: Pull requests, Push

5. Installation: "Only on this account" (or "Any account" if sharing)

6. Click "Create GitHub App"

## Step 2: Get Credentials

- Copy **App ID** (number)
- Click "Generate a private key" → Download `.pem` file
- Copy the entire private key content

## Step 3: Update Render Environment Variables

In your Render dashboard (https://dashboard.render.com):

1. Go to your service: `aegis-iam-backend`
2. Click **"Environment"** tab
3. Click **"Add Environment Variable"**
4. Add these 3 variables:

**Variable 1:**
- **Key**: `GITHUB_APP_ID`
- **Value**: `2330898`

**Variable 2:**
- **Key**: `GITHUB_PRIVATE_KEY`
- **Value**: `-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n(paste your entire private key here with \n for newlines)\n...\n-----END RSA PRIVATE KEY-----`
  - **Important**: Keep the quotes and use `\n` for newlines, OR paste it as multi-line (Render supports both)

**Variable 3:**
- **Key**: `GITHUB_WEBHOOK_SECRET`
- **Value**: `f15a6b1f020ed357340a945ade30e7806fc5a2b5`

5. Click **"Save Changes"**
6. Render will automatically redeploy your service

## Step 4: Test

1. Go to: https://aegis-iam.vercel.app/cicd-integration
2. Click "Install GitHub App"
3. Install on a test repository
4. Create a PR or push code → automatic analysis!

---

## Your URLs:
- **Backend**: https://aegis-iam-backend.onrender.com
- **Frontend**: https://aegis-iam.vercel.app/
