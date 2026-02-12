# VibeQA Environment Variables

## Required for Production

### Supabase (Database)
```
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your-service-key
```

### App Configuration
```
APP_URL=https://vibeqa.app (or your Railway URL)
PASSWORD_SALT=your-random-salt-string
ADMIN_SECRET=your-admin-secret-for-plan-upgrades
CRON_SECRET=your-cron-secret-for-scheduled-scans
```

## Optional Features

### Stripe (Payments)
```
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRO_MONTHLY_PRICE_ID=price_...
STRIPE_TEAM_MONTHLY_PRICE_ID=price_...
```

Without Stripe configured, the checkout will work in "demo mode" (instant upgrade without payment).

### OpenAI (AI Analysis for Pro/Team plans)
```
OPENAI_API_KEY=sk-...
```

Enables AI-powered UX analysis of screenshots.

### GitHub Integration (Pro tier)
```
GITHUB_CLIENT_ID=your-github-oauth-app-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-app-client-secret
```

To set up:
1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create new OAuth App
3. Set callback URL to: `{APP_URL}/api/auth/integrations/github/callback`
4. Copy Client ID and Client Secret

### Slack Integration (Pro tier)
```
SLACK_CLIENT_ID=your-slack-app-client-id
SLACK_CLIENT_SECRET=your-slack-app-client-secret
```

To set up:
1. Go to https://api.slack.com/apps
2. Create new app
3. Add OAuth scopes: `incoming-webhook`, `chat:write`
4. Set redirect URL to: `{APP_URL}/api/auth/integrations/slack/callback`
5. Copy Client ID and Client Secret

Users can also manually add a Slack Incoming Webhook URL without OAuth.

## Railway Deployment

On Railway, set these variables in your project's Variables tab.

### Minimum viable production:
- `SUPABASE_URL`
- `SUPABASE_SERVICE_KEY`
- `APP_URL` (your Railway app URL, e.g., `https://vibeqa-production.up.railway.app`)
- `PASSWORD_SALT` (any random string)

### For scheduled scans:
Set up a Railway cron job to call:
```
POST {APP_URL}/api/cron/run-scheduled-scans
Header: x-cron-secret: {CRON_SECRET}
```

Run every hour or as needed.

## Database Setup

Run the SQL in `supabase/schema.sql` in your Supabase SQL Editor to create all tables.

## Quick Test

After deployment:
1. Create account at `/`
2. Run a scan
3. Check `/api/health` endpoint
4. Check server logs for "Supabase: connected" message
