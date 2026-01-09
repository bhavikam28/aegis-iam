# Complete Vercel Setup Guide

Follow these steps to configure your Vercel deployment so it connects to your Render backend.

---

## Step 1: Get Your Render Backend URL

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Find your backend service (should be named something like `aegis-iam-backend`)
3. Click on the service
4. Copy the **Service URL** (it will look like: `https://aegis-iam-backend-xxxxx.onrender.com`)
5. **Save this URL** - you'll need it in the next step

---

## Step 2: Configure Vercel Environment Variable

### 2.1 Go to Vercel Dashboard

1. Open [Vercel Dashboard](https://vercel.com/dashboard)
2. Sign in if needed
3. You should see your projects listed

### 2.2 Select Your Project

1. Find and click on your `aegis-iam` project
2. This will open the project dashboard

### 2.3 Navigate to Environment Variables

1. Click on **Settings** in the top navigation bar
2. In the left sidebar, click on **Environment Variables**
3. You'll see a list of existing environment variables (if any)

### 2.4 Add the API URL Variable

1. Click the **Add New** button (or **Add** button)
2. Fill in the form:
   - **Key**: `VITE_API_URL`
   - **Value**: Paste your Render backend URL (from Step 1)
     - Example: `https://aegis-iam-backend-xxxxx.onrender.com`
   - **Environment**: Select all three:
     - ✅ Production
     - ✅ Preview  
     - ✅ Development
3. Click **Save**

### 2.5 Verify the Variable

- You should now see `VITE_API_URL` in the list
- Make sure it shows for all environments (Production, Preview, Development)

---

## Step 3: Redeploy Your Frontend

After adding the environment variable, you need to redeploy so the changes take effect:

### 3.1 Go to Deployments

1. In your Vercel project, click on **Deployments** tab (top navigation)
2. You'll see a list of all deployments

### 3.2 Redeploy Latest

1. Find the **latest deployment** (should be at the top)
2. Click the **three dots (⋯)** menu on the right side of that deployment
3. Click **Redeploy**
4. Confirm if prompted
5. Wait for the deployment to complete (usually 1-2 minutes)

### 3.3 Verify Deployment

- The deployment status should show "Ready" when complete
- Click on the deployment to see the build logs if needed

---

## Step 4: Test the Connection

### 4.1 Open Your Live Site

1. Visit [https://aegis-iam.vercel.app](https://aegis-iam.vercel.app)
2. Or use the deployment URL shown in Vercel

### 4.2 Check Browser Console

1. Open **Developer Tools** (Press `F12` or right-click → Inspect)
2. Go to the **Console** tab
3. Look for any errors
4. Check Network tab to see if API calls are going to your Render URL (not localhost)

### 4.3 Test AWS Setup Wizard

1. Click "Add AWS" or "Configure AWS" button
2. The wizard should open
3. It should try to connect to your Render backend
4. If you see "Verifying credentials..." it means it's connecting!

---

## Troubleshooting

### Problem: Still seeing "localhost:8000" in console

**Solution:**
- Make sure you redeployed after adding the environment variable
- Check that `VITE_API_URL` is set for Production environment
- Clear browser cache and hard refresh (Ctrl+Shift+R)

### Problem: CORS errors in console

**Solution:**
- Your Render backend needs to allow Vercel origin
- The code has been updated, but Render needs to redeploy
- Check Render dashboard to ensure latest code is deployed

### Problem: Backend not responding

**Solution:**
- Check Render dashboard - service might be sleeping (free tier)
- First request after sleep takes ~30 seconds (cold start)
- Check Render logs for errors

---

## Quick Checklist

- [ ] Got Render backend URL
- [ ] Added `VITE_API_URL` in Vercel Settings → Environment Variables
- [ ] Selected all environments (Production, Preview, Development)
- [ ] Redeployed frontend in Vercel
- [ ] Tested the live site
- [ ] Verified API calls go to Render (not localhost)

---

## Official Vercel Links

- **Dashboard**: https://vercel.com/dashboard
- **Documentation**: https://vercel.com/docs
- **Environment Variables Guide**: https://vercel.com/docs/concepts/projects/environment-variables
- **Deployments**: https://vercel.com/docs/concepts/deployments

---

**Once you complete these steps, your Vercel frontend will connect to your Render backend!**

