# Deployment Guide

This guide explains how to deploy Aegis IAM for production use.

## Architecture Overview

- **Frontend**: Deployed on Vercel
- **Backend**: Already deployed on Render ✅
- **Authentication**: Users configure AWS CLI on their local machines, credentials are passed to backend via API

---

## Quick Setup (Backend Already on Render)

Since your backend is already deployed on Render, you just need to configure Vercel to connect to it:

### Step 1: Get Your Render Backend URL

1. Go to your Render dashboard: [https://dashboard.render.com](https://dashboard.render.com)
2. Find your backend service (e.g., `aegis-iam-backend`)
3. Copy the public URL (e.g., `https://aegis-iam-backend.onrender.com`)

### Step 2: Configure Vercel Environment Variable

1. Go to Vercel Dashboard: [https://vercel.com/dashboard](https://vercel.com/dashboard)
2. Select your `aegis-iam` project
3. Go to **Settings** → **Environment Variables**
4. Click **Add New**
5. Enter:
   - **Key**: `VITE_API_URL`
   - **Value**: `https://your-render-backend-url.onrender.com` (replace with your actual URL)
   - **Environments**: Select all (Production, Preview, Development)
6. Click **Save**

### Step 3: Update CORS in Backend (if needed)

If your frontend can't connect, ensure your Render backend allows requests from Vercel:

1. Check `agent/main.py` - CORS should include:
   ```python
   allow_origins=[
       "http://localhost:5173",
       "https://aegis-iam.vercel.app",
       # Add any custom domains here
   ]
   ```

2. If you need to update CORS:
   - Go to Render dashboard
   - Find your backend service
   - Go to **Environment** tab
   - Or update the code and redeploy

### Step 4: Redeploy Frontend

After setting the environment variable:

1. Go to Vercel Dashboard → **Deployments**
2. Click the three dots (⋯) on the latest deployment
3. Click **Redeploy**
4. This ensures the new `VITE_API_URL` is picked up

### Step 5: Verify Connection

1. Visit [https://aegis-iam.vercel.app](https://aegis-iam.vercel.app)
2. Open browser DevTools (F12) → **Console** tab
3. Check for any API connection errors
4. The app should now connect to your Render backend

---

## Deploy Backend to Render (If Not Already Done)

### Why Render?
- Free tier available
- Easy Python/FastAPI deployment
- Automatic HTTPS
- Environment variable management

### Setup Instructions:

1. **Create Render Account**
   - Go to [https://render.com](https://render.com)
   - Sign up with GitHub

2. **Create New Web Service**
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Select the `aegis-iam` repository

3. **Configure Service**
   ```
   Name: aegis-iam-backend
   Environment: Python 3
   Build Command: cd agent && pip install -r requirements.txt
   Start Command: cd agent && uvicorn main:app --host 0.0.0.0 --port $PORT
   ```

4. **Set Environment Variables** (if needed for CI/CD):
   ```
   GITHUB_APP_ID=your_app_id (optional)
   GITHUB_PRIVATE_KEY=your_private_key (optional)
   GITHUB_WEBHOOK_SECRET=your_webhook_secret (optional)
   ```

5. **Deploy**
   - Click "Create Web Service"
   - Wait for deployment to complete
   - Copy your service URL (e.g., `https://aegis-iam-backend.onrender.com`)

---

## Step 2: Configure Vercel Environment Variables

Now that your backend is deployed, tell Vercel where to find it:

1. **Go to Vercel Dashboard**
   - Visit [https://vercel.com/dashboard](https://vercel.com/dashboard)
   - Select your `aegis-iam` project

2. **Go to Settings → Environment Variables**

3. **Add New Environment Variable**
   ```
   Name: VITE_API_URL
   Value: https://your-backend-url.onrender.com
   ```
   Replace `your-backend-url.onrender.com` with your actual Render service URL

4. **Apply to Production**
   - Select "Production", "Preview", and "Development" environments
   - Click "Save"

5. **Redeploy**
   - Go to "Deployments" tab
   - Click the three dots (⋯) on the latest deployment
   - Click "Redeploy"
   - This ensures the new environment variable is picked up

---

## Step 3: Verify Deployment

1. **Check Backend Health**
   - Visit `https://your-backend-url.onrender.com/docs`
   - You should see the FastAPI documentation page

2. **Check Frontend Connection**
   - Visit [https://aegis-iam.vercel.app](https://aegis-iam.vercel.app)
   - Open browser DevTools (F12) → Console
   - Check for any API connection errors

3. **Test AWS Authentication**
   - Click "Add AWS" or "Configure AWS"
   - Configure AWS CLI on your local machine (see below)
   - The wizard should detect your credentials

---

## Alternative: Deploy Backend to Railway

### Setup Instructions:

1. **Create Railway Account**
   - Go to [https://railway.app](https://railway.app)
   - Sign up with GitHub

2. **Create New Project**
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your `aegis-iam` repository

3. **Configure Service**
   - Railway auto-detects Python projects
   - Set root directory to `agent`
   - Add start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

4. **Get Public URL**
   - Railway provides a public URL automatically
   - Copy this URL

5. **Configure Vercel**
   - Follow Step 2 above, but use your Railway URL instead of Render URL

---

## Alternative: Deploy Backend to AWS (EC2/ECS/Lambda)

For AWS-native deployment, see the AWS deployment guide in the repository.

---

## Important Notes

### AWS Credentials in Production

**Critical Understanding:**
- Users configure AWS CLI **on their local machines**
- When they use the app, their browser sends AWS credentials to the backend
- The backend uses those credentials to make AWS API calls
- **The backend itself doesn't have AWS credentials** - it uses credentials provided by users

**Security:**
- Credentials are transmitted via HTTPS
- Credentials are stored only in React state (browser memory)
- Credentials are not persisted on the backend
- Each API request includes credentials in the request body

### CORS Configuration

The backend automatically allows requests from:
- `http://localhost:5173` (local development)
- `https://aegis-iam.vercel.app` (production)
- Any Vercel preview deployment URLs

If you deploy to a custom domain, update CORS in `agent/main.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://aegis-iam.vercel.app",
        "https://your-custom-domain.com"  # Add your domain here
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## Troubleshooting

### Backend Not Responding
- Check Render/Railway logs for errors
- Verify the start command is correct
- Ensure port is set to `$PORT` (not hardcoded)

### Frontend Can't Connect to Backend
- Verify `VITE_API_URL` is set in Vercel
- Check browser console for CORS errors
- Verify backend URL is accessible (visit `/docs` endpoint)

### AWS Credentials Not Working
- Users must configure AWS CLI locally first
- Backend receives credentials from frontend - check Network tab in DevTools
- Verify credentials are being sent in API requests

### Build Errors
- Check `requirements.txt` is up to date
- Verify Python version matches (3.11+)
- Check build logs for missing dependencies

---

## Quick Reference

**Backend URL Examples:**
- Render: `https://aegis-iam-backend.onrender.com`
- Railway: `https://aegis-iam-production.up.railway.app`
- Custom: `https://api.yourdomain.com`

**Vercel Environment Variable:**
```
VITE_API_URL=https://your-backend-url.com
```

**Backend Start Command:**
```bash
cd agent && uvicorn main:app --host 0.0.0.0 --port $PORT
```

---

## Next Steps

After deployment:
1. Test all features (Generate, Validate, Audit)
2. Monitor backend logs for errors
3. Set up monitoring/alerting (optional)
4. Configure custom domain (optional)

