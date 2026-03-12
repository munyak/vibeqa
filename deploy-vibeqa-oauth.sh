#!/bin/bash
# VibeQA OAuth Deployment Script
# Run this to deploy Google OAuth fix to production
# Usage: bash deploy-vibeqa-oauth.sh

set -e

echo "🚀 VibeQA OAuth Deployment Starting..."

# Step 1: Verify .env.production exists
if [ ! -f ".env.production" ]; then
    echo "❌ Error: .env.production not found in $(pwd)"
    exit 1
fi

echo "✅ .env.production found"

# Step 2: Verify Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "⚠️  Railway CLI not found. Install with: npm install -g @railway/cli"
    echo "   Then run: railway link"
    exit 1
fi

echo "✅ Railway CLI found"

# Step 3: Deploy environment variables to Railway
echo "📤 Deploying environment variables to Railway..."
railway service add VIBEQA_ENV < .env.production || echo "⚠️  Manual var entry may be needed"

# Step 4: Git commit and push frontend changes
echo "📝 Committing frontend changes to git..."
git add index.html
git commit -m "fix: Update API_URL to vibeqa.io for Google OAuth" || echo "⚠️  No changes to commit"

echo "🚀 Pushing to Netlify (git-based deploy)..."
git push origin main

echo ""
echo "✅ DEPLOYMENT COMPLETE!"
echo ""
echo "Next steps:"
echo "1. Go to Railway Dashboard → Verify environment variables are set"
echo "2. Go to Netlify Dashboard → Check deploy log"
echo "3. Visit https://vibeqa.io and test 'Continue with Google'"
echo ""
echo "Expected result: Google login redirects back to vibeqa.io and logs you in"
