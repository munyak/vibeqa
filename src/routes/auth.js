const express = require('express');
const { User, Session, ApiKey } = require('../models/user');
// Node 18+ has built-in fetch
const fetch = globalThis.fetch;

const router = express.Router();

// Register
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    const user = await User.create({ email, password, name });
    const token = await Session.create(user.id);
    
    res.json({ user, token });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    const user = await User.verifyPassword(email, password);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const token = await Session.create(user.id);
    res.json({ user, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Logout
router.post('/logout', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    await Session.destroy(token);
  }
  res.json({ success: true });
});

// Get current user with full details
router.get('/me', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  res.json({
    id: req.user.id,
    email: req.user.email,
    name: req.user.name,
    plan: req.user.plan,
    usage: req.user.usage,
    settings: req.user.settings,
    integrations: req.user.integrations,
    createdAt: req.user.createdAt,
  });
});

// Get usage stats with upgrade nudges
router.get('/usage', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const stats = await User.getUsageStats(req.user.id);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update profile
router.put('/profile', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { name, timezone } = req.body;
  
  try {
    await User.updateProfile(req.user.id, { name, timezone });
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Update notification settings
router.put('/notifications', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    await User.updateNotificationSettings(req.user.id, req.body);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Change password
router.put('/password', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }
  
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  
  try {
    const verified = await User.verifyPassword(req.user.email, currentPassword);
    if (!verified) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    await User.updatePassword(req.user.id, newPassword);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// === API Keys ===

// List API keys
router.get('/api-keys', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  // Check plan allows API access
  if (req.user.plan === 'free') {
    return res.status(403).json({ 
      error: 'API access requires Pro or higher',
      upgrade: true,
      suggestedPlan: 'pro'
    });
  }
  
  try {
    const keys = await ApiKey.list(req.user.id);
    res.json(keys);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create API key
router.post('/api-keys', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  if (req.user.plan === 'free') {
    return res.status(403).json({ 
      error: 'API access requires Pro or higher',
      upgrade: true,
      suggestedPlan: 'pro'
    });
  }
  
  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'API key name is required' });
  }
  
  try {
    const key = await ApiKey.create(req.user.id, name);
    res.json(key);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Revoke API key
router.delete('/api-keys/:keyPrefix', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const success = await ApiKey.revoke(req.user.id, req.params.keyPrefix);
    if (success) {
      res.json({ success: true });
    } else {
      res.status(404).json({ error: 'API key not found' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === Sessions ===

// List active sessions
router.get('/sessions', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const sessions = await Session.listForUser(req.user.id);
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// === Integrations ===

const APP_URL = process.env.APP_URL || 'http://localhost:3847';

// GitHub OAuth configuration
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;

// Slack OAuth configuration
const SLACK_CLIENT_ID = process.env.SLACK_CLIENT_ID;
const SLACK_CLIENT_SECRET = process.env.SLACK_CLIENT_SECRET;

// Start GitHub OAuth flow
router.get('/integrations/github/connect', async (req, res) => {
  if (!req.user) {
    return res.redirect('/?login=1&redirect=settings');
  }
  
  if (req.user.plan === 'free') {
    return res.redirect('/settings.html?error=upgrade_required&integration=github');
  }
  
  if (!GITHUB_CLIENT_ID) {
    return res.redirect('/settings.html?error=github_not_configured');
  }
  
  // Store user ID in state for callback
  const state = Buffer.from(JSON.stringify({ userId: req.user.id })).toString('base64');
  
  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: `${APP_URL}/api/auth/integrations/github/callback`,
    scope: 'repo read:user',
    state
  });
  
  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

// GitHub OAuth callback
router.get('/integrations/github/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code || !state) {
    return res.redirect('/settings.html?error=github_auth_failed');
  }
  
  try {
    // Decode state to get user ID
    const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
    const userId = stateData.userId;
    
    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${APP_URL}/api/auth/integrations/github/callback`
      })
    });
    
    const tokenData = await tokenResponse.json();
    
    if (tokenData.error) {
      console.error('GitHub OAuth error:', tokenData);
      return res.redirect('/settings.html?error=github_auth_failed');
    }
    
    // Get user info
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Accept': 'application/json'
      }
    });
    
    const githubUser = await userResponse.json();
    
    // Save integration
    await User.connectIntegration(userId, 'github', {
      accessToken: tokenData.access_token,
      username: githubUser.login,
      avatarUrl: githubUser.avatar_url,
      profileUrl: githubUser.html_url
    });
    
    res.redirect('/settings.html?success=github_connected');
  } catch (err) {
    console.error('GitHub callback error:', err);
    res.redirect('/settings.html?error=github_auth_failed');
  }
});

// Start Slack OAuth flow
router.get('/integrations/slack/connect', async (req, res) => {
  if (!req.user) {
    return res.redirect('/?login=1&redirect=settings');
  }
  
  if (req.user.plan === 'free') {
    return res.redirect('/settings.html?error=upgrade_required&integration=slack');
  }
  
  if (!SLACK_CLIENT_ID) {
    return res.redirect('/settings.html?error=slack_not_configured');
  }
  
  // Store user ID in state for callback
  const state = Buffer.from(JSON.stringify({ userId: req.user.id })).toString('base64');
  
  const params = new URLSearchParams({
    client_id: SLACK_CLIENT_ID,
    redirect_uri: `${APP_URL}/api/auth/integrations/slack/callback`,
    scope: 'incoming-webhook,chat:write',
    state
  });
  
  res.redirect(`https://slack.com/oauth/v2/authorize?${params}`);
});

// Slack OAuth callback
router.get('/integrations/slack/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code || !state) {
    return res.redirect('/settings.html?error=slack_auth_failed');
  }
  
  try {
    // Decode state to get user ID
    const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
    const userId = stateData.userId;
    
    // Exchange code for access token
    const tokenResponse = await fetch('https://slack.com/api/oauth.v2.access', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: SLACK_CLIENT_ID,
        client_secret: SLACK_CLIENT_SECRET,
        code,
        redirect_uri: `${APP_URL}/api/auth/integrations/slack/callback`
      })
    });
    
    const tokenData = await tokenResponse.json();
    
    if (!tokenData.ok) {
      console.error('Slack OAuth error:', tokenData);
      return res.redirect('/settings.html?error=slack_auth_failed');
    }
    
    // Save integration with webhook URL
    await User.connectIntegration(userId, 'slack', {
      accessToken: tokenData.access_token,
      teamId: tokenData.team?.id,
      teamName: tokenData.team?.name,
      channelId: tokenData.incoming_webhook?.channel_id,
      channelName: tokenData.incoming_webhook?.channel,
      webhookUrl: tokenData.incoming_webhook?.url
    });
    
    res.redirect('/settings.html?success=slack_connected');
  } catch (err) {
    console.error('Slack callback error:', err);
    res.redirect('/settings.html?error=slack_auth_failed');
  }
});

// Manual Slack webhook URL setup (for users who prefer incoming webhooks)
router.post('/integrations/slack/webhook', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  if (req.user.plan === 'free') {
    return res.status(403).json({ 
      error: 'Slack integration requires Pro or higher',
      upgrade: true 
    });
  }
  
  const { webhookUrl } = req.body;
  
  if (!webhookUrl || !webhookUrl.startsWith('https://hooks.slack.com/')) {
    return res.status(400).json({ error: 'Invalid Slack webhook URL' });
  }
  
  try {
    // Test the webhook
    const testResponse = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: '✅ VibeQA connected successfully!' })
    });
    
    if (!testResponse.ok) {
      return res.status(400).json({ error: 'Webhook URL validation failed' });
    }
    
    await User.connectIntegration(req.user.id, 'slack', {
      webhookUrl,
      manualSetup: true
    });
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Connect integration (generic handler for future integrations)
router.post('/integrations/:integration', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { integration } = req.params;
  const validIntegrations = ['github', 'slack', 'vercel', 'linear', 'discord'];
  
  if (!validIntegrations.includes(integration)) {
    return res.status(400).json({ error: 'Invalid integration' });
  }
  
  // Check plan allows this integration
  const proIntegrations = ['github', 'slack'];
  const teamIntegrations = ['vercel', 'linear', 'discord'];
  
  if (proIntegrations.includes(integration) && req.user.plan === 'free') {
    return res.status(403).json({ 
      error: `${integration} integration requires Pro or higher`,
      upgrade: true,
      suggestedPlan: 'pro'
    });
  }
  
  if (teamIntegrations.includes(integration) && !['team', 'enterprise'].includes(req.user.plan)) {
    return res.status(403).json({ 
      error: `${integration} integration requires Team or higher`,
      upgrade: true,
      suggestedPlan: 'team'
    });
  }
  
  try {
    // In production, this would handle OAuth callback data
    await User.connectIntegration(req.user.id, integration, req.body);
    res.json({ success: true, integration });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Disconnect integration
router.delete('/integrations/:integration', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    await User.disconnectIntegration(req.user.id, req.params.integration);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete account
router.delete('/account', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    await User.delete(req.user.id);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ============================================
// GITHUB WEBHOOK RECEIVER
// ============================================

const crypto = require('crypto');

// Verify GitHub webhook signature
function verifyGitHubSignature(payload, signature, secret) {
  if (!signature || !secret) return false;
  const hmac = crypto.createHmac('sha256', secret);
  const digest = 'sha256=' + hmac.update(payload).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

// GitHub webhook endpoint - receives push/PR events
router.post('/webhooks/github', express.raw({ type: 'application/json' }), async (req, res) => {
  const event = req.headers['x-github-event'];
  const signature = req.headers['x-hub-signature-256'];
  const deliveryId = req.headers['x-github-delivery'];
  
  console.log(`[GitHub Webhook] Event: ${event}, Delivery: ${deliveryId}`);
  
  try {
    const payload = JSON.parse(req.body.toString());
    
    // Find user by repository owner or installation
    // For now, we'll match by the repository owner's GitHub username
    const repoOwner = payload.repository?.owner?.login;
    const repoName = payload.repository?.name;
    const repoUrl = payload.repository?.html_url;
    
    if (!repoOwner) {
      return res.status(400).json({ error: 'Missing repository information' });
    }
    
    // Find user with this GitHub integration
    // This would need a proper lookup in production
    // For now, we'll trust the webhook and look up by username
    let userId = null;
    let deployUrl = null;
    
    // Handle different event types
    switch (event) {
      case 'push':
        // Could trigger scan of a preview deployment URL if configured
        console.log(`[GitHub] Push to ${repoOwner}/${repoName}`);
        // For push events, we'd need the user to configure a preview URL pattern
        break;
        
      case 'pull_request':
        const action = payload.action;
        const prNumber = payload.number;
        const prUrl = payload.pull_request?.html_url;
        
        if (['opened', 'synchronize', 'reopened'].includes(action)) {
          console.log(`[GitHub] PR #${prNumber} ${action} on ${repoOwner}/${repoName}`);
          
          // Look for deployment status or check if there's a preview URL pattern
          // Many platforms create preview URLs like: pr-{number}.{domain} or {branch}.{domain}
          
          // For Vercel-like preview URLs:
          const branchName = payload.pull_request?.head?.ref?.replace(/[^a-z0-9]/gi, '-');
          
          // Store PR info for when deployment completes
          // In production, you'd want a PR -> deployment URL mapping
        }
        break;
        
      case 'deployment_status':
        // This is the ideal event - when a deployment completes
        const state = payload.deployment_status?.state;
        const environmentUrl = payload.deployment_status?.environment_url;
        
        if (state === 'success' && environmentUrl) {
          console.log(`[GitHub] Deployment success: ${environmentUrl}`);
          deployUrl = environmentUrl;
        }
        break;
        
      case 'check_run':
        // Some CI systems report via check runs
        break;
        
      default:
        console.log(`[GitHub] Unhandled event type: ${event}`);
    }
    
    // If we have a URL to scan, find the user and trigger scan
    if (deployUrl && userId) {
      // Import the scan function (or use API call)
      // This would trigger: runScan(scanId, deployUrl, 'pro', userId)
      console.log(`[GitHub] Would scan: ${deployUrl}`);
    }
    
    res.json({ received: true, event });
  } catch (err) {
    console.error('[GitHub Webhook Error]', err);
    res.status(500).json({ error: err.message });
  }
});

// Configure GitHub App webhook URL for a user
router.post('/integrations/github/configure-webhook', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  if (req.user.plan === 'free') {
    return res.status(403).json({ 
      error: 'GitHub integration requires Pro or higher',
      upgrade: true 
    });
  }
  
  const { previewUrlPattern } = req.body;
  
  // previewUrlPattern could be like: "https://pr-{pr_number}.myapp.vercel.app"
  // or "https://{branch}.preview.mysite.com"
  
  try {
    await User.connectIntegration(req.user.id, 'github', {
      ...req.user.integrations?.github,
      previewUrlPattern
    });
    
    res.json({ 
      success: true,
      webhookUrl: `${APP_URL}/api/auth/webhooks/github`,
      message: 'Add this URL as a webhook in your GitHub repository settings'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
