const express = require('express');
const db = require('../db/supabase');
const { PLAN_LIMITS } = require('../models/user');
const fetch = globalThis.fetch;
const crypto = require('crypto');

const router = express.Router();

// Special accounts that get upgraded plans automatically
const SPECIAL_ACCOUNTS = {
  'mkanaventi@gmail.com': 'team',
};

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
    
    // Check if email already exists
    const existing = await db.getUserByEmail(email);
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const user = await db.createUser({ email, password, name });
    
    // Auto-upgrade special accounts
    const specialPlan = SPECIAL_ACCOUNTS[email.toLowerCase()];
    if (specialPlan && user.plan !== specialPlan) {
      await db.updateUser(user.id, { plan: specialPlan });
      user.plan = specialPlan;
    }
    
    const session = await db.createSession(user.id);
    
    res.json({ user, token: session.token });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(400).json({ error: err.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log('[AUTH] Login attempt:', { email, passwordLength: password?.length, bodyKeys: Object.keys(req.body) });
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    const userId = await db.verifyPassword(email, password);
    console.log('[AUTH] verifyPassword result:', userId ? 'success' : 'failed');
    
    if (!userId) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const user = await db.getUserById(userId);
    const session = await db.createSession(userId);
    
    res.json({ user, token: session.token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Logout
router.post('/logout', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    await db.deleteSession(token);
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
    settings: req.user.settings,
    integrations: req.user.integrations,
    createdAt: req.user.created_at,
  });
});

// Get usage stats with upgrade nudges
router.get('/usage', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const usage = await db.getUserUsage(req.user.id);
    const limits = PLAN_LIMITS[req.user.plan] || PLAN_LIMITS.free;
    
    const stats = {
      plan: req.user.plan,
      limits,
      current: {
        scansToday: usage?.scans_today || 0,
        scansThisMonth: usage?.scans_this_month || 0,
        scansAllTime: usage?.scans_all_time || 0,
        apiRequestsThisMonth: usage?.api_requests_this_month || 0,
      },
      percentages: {
        dailyScans: limits.scansPerDay === Infinity ? 0 : ((usage?.scans_today || 0) / limits.scansPerDay) * 100,
        monthlyScans: limits.scansPerMonth === Infinity ? 0 : ((usage?.scans_this_month || 0) / limits.scansPerMonth) * 100,
        apiRequests: limits.apiRequests === Infinity ? 0 : ((usage?.api_requests_this_month || 0) / limits.apiRequests) * 100,
      },
      upgradeNudges: [],
    };
    
    // Add upgrade nudges based on usage
    if (stats.percentages.dailyScans >= 80 && req.user.plan === 'free') {
      stats.upgradeNudges.push({
        type: 'daily_limit',
        message: 'You\'re close to your daily scan limit. Upgrade to Pro for 10 scans/day.',
        cta: 'Upgrade to Pro',
        plan: 'pro',
      });
    }
    
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
    const updates = {};
    if (name !== undefined) updates.name = name;
    if (timezone !== undefined) {
      updates.settings = { ...req.user.settings, timezone };
    }
    
    await db.updateUser(req.user.id, updates);
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
    const newSettings = {
      ...req.user.settings,
      notifications: { ...req.user.settings?.notifications, ...req.body }
    };
    await db.updateUser(req.user.id, { settings: newSettings });
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
    const verified = await db.verifyPassword(req.user.email, currentPassword);
    if (!verified) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    const newHash = db.hashPassword(newPassword);
    await db.updateUser(req.user.id, { password_hash: newHash });
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
  
  if (req.user.plan === 'free') {
    return res.status(403).json({ 
      error: 'API access requires Pro or higher',
      upgrade: true,
      suggestedPlan: 'pro'
    });
  }
  
  try {
    const keys = await db.getApiKeysByUserId(req.user.id);
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
    const key = await db.createApiKey(req.user.id, name);
    res.json(key);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Revoke API key
router.delete('/api-keys/:id', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    await db.deleteApiKey(req.params.id, req.user.id);
    res.json({ success: true });
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
    const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
    const userId = stateData.userId;
    
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
    
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Accept': 'application/json'
      }
    });
    
    const githubUser = await userResponse.json();
    
    await db.saveGitHubIntegration(userId, {
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
    const stateData = JSON.parse(Buffer.from(state, 'base64').toString());
    const userId = stateData.userId;
    
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
    
    await db.saveSlackIntegration(userId, {
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

// Manual Slack webhook URL setup
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
    const testResponse = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: '✅ VibeQA connected successfully!' })
    });
    
    if (!testResponse.ok) {
      return res.status(400).json({ error: 'Webhook URL validation failed' });
    }
    
    await db.saveSlackIntegration(req.user.id, {
      webhookUrl,
      manualSetup: true
    });
    
    res.json({ success: true });
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
    const integrations = await db.getUserIntegrations(req.user.id);
    delete integrations[req.params.integration];
    await db.updateUser(req.user.id, { integrations });
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
    // Delete all user sessions first
    await db.deleteUserSessions(req.user.id);
    // Note: In production, also delete user from Supabase
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// GitHub webhook endpoint
router.post('/webhooks/github', express.raw({ type: 'application/json' }), async (req, res) => {
  const event = req.headers['x-github-event'];
  const deliveryId = req.headers['x-github-delivery'];
  
  console.log(`[GitHub Webhook] Event: ${event}, Delivery: ${deliveryId}`);
  
  try {
    const payload = JSON.parse(req.body.toString());
    const repoOwner = payload.repository?.owner?.login;
    
    if (!repoOwner) {
      return res.status(400).json({ error: 'Missing repository information' });
    }
    
    // Log the event for now
    console.log(`[GitHub] ${event} on ${repoOwner}/${payload.repository?.name}`);
    
    res.json({ received: true, event });
  } catch (err) {
    console.error('[GitHub Webhook Error]', err);
    res.status(500).json({ error: err.message });
  }
});

// Forgot password - request reset
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const result = await db.createPasswordReset(email);
    
    // Always return success to prevent email enumeration
    // In production, this would send an email
    const response = { 
      success: true, 
      message: 'If an account with that email exists, a password reset link has been sent.' 
    };
    
    // In demo mode, include the reset link for testing
    if (result && !process.env.SENDGRID_API_KEY) {
      const resetUrl = `${process.env.APP_URL || 'https://intuitive-insight-production-bb40.up.railway.app'}/reset-password.html?token=${result.token}`;
      response.demo = {
        note: 'Email not configured. Use this link to reset password:',
        resetUrl,
        token: result.token
      };
    }
    
    res.json(response);
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Reset password - verify token and set new password
router.post('/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    
    if (!token || !password) {
      return res.status(400).json({ error: 'Token and password are required' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    const success = await db.completePasswordReset(token, password);
    
    if (!success) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    res.json({ success: true, message: 'Password has been reset. Please log in with your new password.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Verify reset token (check if valid before showing form)
router.get('/verify-reset-token', async (req, res) => {
  try {
    const { token } = req.query;
    
    if (!token) {
      return res.status(400).json({ valid: false, error: 'Token is required' });
    }
    
    const result = await db.verifyPasswordResetToken(token);
    
    if (!result) {
      return res.json({ valid: false, error: 'Invalid or expired token' });
    }
    
    res.json({ valid: true, email: result.user.email });
  } catch (err) {
    console.error('Verify reset token error:', err);
    res.status(500).json({ valid: false, error: 'Failed to verify token' });
  }
});

module.exports = router;

// ============================================
// SSO - Google OAuth
// ============================================

const GOOGLE_SSO_CONFIG = {
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: `${process.env.APP_URL || 'https://intuitive-insight-production-bb40.up.railway.app'}/api/auth/google/callback`
};

// Start Google SSO flow
router.get('/google', (req, res) => {
  if (!GOOGLE_SSO_CONFIG.clientId) {
    return res.status(500).json({ error: 'Google SSO not configured' });
  }
  
  const params = new URLSearchParams({
    client_id: GOOGLE_SSO_CONFIG.clientId,
    redirect_uri: GOOGLE_SSO_CONFIG.redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'select_account'
  });
  
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// Google SSO callback
router.get('/google/callback', async (req, res) => {
  const { code, error } = req.query;
  
  if (error || !code) {
    return res.redirect('/?error=google_auth_failed');
  }
  
  try {
    // Exchange code for tokens
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: GOOGLE_SSO_CONFIG.clientId,
        client_secret: GOOGLE_SSO_CONFIG.clientSecret,
        code,
        grant_type: 'authorization_code',
        redirect_uri: GOOGLE_SSO_CONFIG.redirectUri
      })
    });
    
    const tokenData = await tokenResponse.json();
    
    if (tokenData.error) {
      console.error('Google OAuth error:', tokenData);
      return res.redirect('/?error=google_token_failed');
    }
    
    // Get user info
    const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    
    const googleUser = await userResponse.json();
    
    if (!googleUser.email) {
      return res.redirect('/?error=google_no_email');
    }
    
    // Find or create user
    let user = await db.getUserByEmail(googleUser.email);
    
    if (!user) {
      // Create new user
      user = await db.createUser({
        email: googleUser.email,
        name: googleUser.name || googleUser.email.split('@')[0],
        password: crypto.randomBytes(32).toString('hex'), // Random password for SSO users
        ssoProvider: 'google',
        ssoId: googleUser.id
      });
    }
    
    // Create session
    const session = await db.createSession(user.id);
    
    // Redirect with token
    res.redirect(`/?sso_token=${session.token}`);
    
  } catch (err) {
    console.error('Google SSO error:', err);
    res.redirect('/?error=google_auth_error');
  }
});

// ============================================
// SSO - GitHub OAuth
// ============================================

const GITHUB_SSO_CONFIG = {
  clientId: process.env.GITHUB_SSO_CLIENT_ID || process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_SSO_CLIENT_SECRET || process.env.GITHUB_CLIENT_SECRET,
  redirectUri: `${process.env.APP_URL || 'https://intuitive-insight-production-bb40.up.railway.app'}/api/auth/github/callback`
};

// Start GitHub SSO flow
router.get('/github', (req, res) => {
  if (!GITHUB_SSO_CONFIG.clientId) {
    return res.status(500).json({ error: 'GitHub SSO not configured' });
  }
  
  const params = new URLSearchParams({
    client_id: GITHUB_SSO_CONFIG.clientId,
    redirect_uri: GITHUB_SSO_CONFIG.redirectUri,
    scope: 'user:email read:user',
    allow_signup: 'true'
  });
  
  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

// GitHub SSO callback
router.get('/github/callback', async (req, res) => {
  const { code, error } = req.query;
  
  if (error || !code) {
    return res.redirect('/?error=github_auth_failed');
  }
  
  try {
    // Exchange code for token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_SSO_CONFIG.clientId,
        client_secret: GITHUB_SSO_CONFIG.clientSecret,
        code,
        redirect_uri: GITHUB_SSO_CONFIG.redirectUri
      })
    });
    
    const tokenData = await tokenResponse.json();
    
    if (tokenData.error) {
      console.error('GitHub OAuth error:', tokenData);
      return res.redirect('/?error=github_token_failed');
    }
    
    // Get user info
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        'User-Agent': 'VibeQA'
      }
    });
    
    const githubUser = await userResponse.json();
    
    // Get primary email (might be private)
    let email = githubUser.email;
    if (!email) {
      const emailsResponse = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          'User-Agent': 'VibeQA'
        }
      });
      const emails = await emailsResponse.json();
      const primaryEmail = emails.find(e => e.primary) || emails[0];
      email = primaryEmail?.email;
    }
    
    if (!email) {
      return res.redirect('/?error=github_no_email');
    }
    
    // Find or create user
    let user = await db.getUserByEmail(email);
    
    if (!user) {
      // Create new user
      user = await db.createUser({
        email,
        name: githubUser.name || githubUser.login,
        password: crypto.randomBytes(32).toString('hex'), // Random password for SSO users
        ssoProvider: 'github',
        ssoId: String(githubUser.id)
      });
    }
    
    // Create session
    const session = await db.createSession(user.id);
    
    // Redirect with token
    res.redirect(`/?sso_token=${session.token}`);
    
  } catch (err) {
    console.error('GitHub SSO error:', err);
    res.redirect('/?error=github_auth_error');
  }
});

// Check SSO availability
router.get('/sso/providers', (req, res) => {
  res.json({
    google: !!GOOGLE_SSO_CONFIG.clientId,
    github: !!GITHUB_SSO_CONFIG.clientId
  });
});
