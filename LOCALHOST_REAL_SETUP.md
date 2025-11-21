# Make GitHub App Work on Localhost (Real Flow)

## Quick Setup (2 minutes)

You already have:
- ✅ GitHub App created (App ID: 2330898)
- ✅ Backend on Render
- ✅ Frontend on Vercel

Now let's make it work on localhost!

## Step 1: Get Your GitHub App Credentials

1. Go to: https://github.com/settings/apps
2. Click on your "Aegis IAM" app
3. You'll see:
   - **App ID**: `2330898` (you have this)
   - **Generate a private key** button → Click it → Download `.pem` file
   - **Webhook secret**: The one you set (`f15a6b1f020ed357340a945ade30e7806fc5a2b5`)

## Step 2: Add to Local .env File

Open `agent/.env` file and add:

```env
GITHUB_APP_ID=2330898
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
(paste your entire private key here - all lines)
...
-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=f15a6b1f020ed357340a945ade30e7806fc5a2b5
```

**Important**: 
- Paste the ENTIRE private key (including BEGIN and END lines)
- Keep it as multi-line (don't use \n)
- Or use single line with \n if you prefer

## Step 3: Get Your App Installation URL

1. Go to: https://github.com/settings/apps
2. Click on "Aegis IAM"
3. Look for "Install App" button or URL
4. The URL format is usually: `https://github.com/apps/aegis-iam/installations/new`
   - Or check your app settings for the exact URL

## Step 4: Update Backend Code

I'll update the code to use your actual app installation URL!

## Step 5: Restart Backend

```powershell
cd agent
python -m uvicorn main:app --reload
```

## Step 6: Test!

1. Open: http://localhost:5173/cicd-integration
2. Click "Install GitHub App"
3. It will open the REAL GitHub App installation page!
4. You can actually install it on a test repo!

---

## What Works on Localhost:

✅ **OAuth Flow** - Users can install the app
✅ **Installation** - App gets installed on repositories
✅ **UI/UX** - Everything works
❌ **Webhooks** - GitHub can't reach localhost (expected)
   - But you can test webhooks on Render backend!

---

## For Your Mentor Demo:

You can say:
- "This is the real GitHub App integration"
- "Users click here and install on their repositories"
- "Once installed, it automatically analyzes IAM policies"
- "Webhooks work in production (on Render), but for localhost demo, we show the installation flow"

