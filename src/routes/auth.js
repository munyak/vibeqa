const express = require('express');
const { User, Session, ApiKey } = require('../models/user');

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

// Connect integration (placeholder - actual OAuth would go here)
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

module.exports = router;
