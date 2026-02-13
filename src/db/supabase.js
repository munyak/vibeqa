/**
 * Supabase Database Client for VibeQA
 * 
 * This module provides all database operations using Supabase
 */

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  console.warn('⚠️ Supabase credentials not configured - falling back to in-memory storage');
}

const supabase = supabaseUrl && supabaseServiceKey 
  ? createClient(supabaseUrl, supabaseServiceKey)
  : null;

// ============================================
// USER OPERATIONS
// ============================================

async function createUser({ email, password, name = null }) {
  if (!supabase) return fallbackCreateUser({ email, password, name });
  
  const passwordHash = hashPassword(password);
  
  const { data, error } = await supabase
    .from('users')
    .insert({
      email: email.toLowerCase(),
      password_hash: passwordHash,
      name,
      plan: 'free'
    })
    .select()
    .single();
  
  if (error) throw error;
  
  // Create usage record
  await supabase.from('user_usage').insert({ user_id: data.id });
  
  return sanitizeUser(data);
}

async function getUserByEmail(email) {
  if (!supabase) return fallbackGetUserByEmail(email);
  
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email.toLowerCase())
    .single();
  
  if (error && error.code !== 'PGRST116') throw error;
  return data ? sanitizeUser(data) : null;
}

async function getUserById(id) {
  if (!supabase) return fallbackGetUserById(id);
  
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('id', id)
    .single();
  
  if (error) throw error;
  return sanitizeUser(data);
}

async function updateUser(id, updates) {
  if (!supabase) return fallbackUpdateUser(id, updates);
  
  const { data, error } = await supabase
    .from('users')
    .update(updates)
    .eq('id', id)
    .select()
    .single();
  
  if (error) throw error;
  return sanitizeUser(data);
}

async function verifyPassword(email, password) {
  if (!supabase) return fallbackVerifyPassword(email, password);
  
  const { data, error } = await supabase
    .from('users')
    .select('id, password_hash, login_count')
    .eq('email', email.toLowerCase())
    .single();
  
  if (error || !data) {
    console.log('[DB] verifyPassword: user not found for', email);
    return null;
  }
  
  const passwordHash = hashPassword(password);
  console.log('[DB] verifyPassword hash comparison:', { 
    stored: data.password_hash?.substring(0, 16) + '...', 
    computed: passwordHash?.substring(0, 16) + '...',
    match: data.password_hash === passwordHash 
  });
  if (data.password_hash !== passwordHash) return null;
  
  // Update login stats (increment login_count manually)
  await supabase
    .from('users')
    .update({ 
      last_login_at: new Date().toISOString(),
      login_count: (data.login_count || 0) + 1
    })
    .eq('id', data.id);
  
  return data.id;
}

// ============================================
// SESSION OPERATIONS
// ============================================

async function createSession(userId) {
  if (!supabase) return fallbackCreateSession(userId);
  
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  
  const { data, error } = await supabase
    .from('sessions')
    .insert({
      user_id: userId,
      token,
      expires_at: expiresAt.toISOString()
    })
    .select()
    .single();
  
  if (error) throw error;
  return { token, expiresAt };
}

async function getSessionByToken(token) {
  if (!supabase) return fallbackGetSessionByToken(token);
  
  const { data, error } = await supabase
    .from('sessions')
    .select('*, users(*)')
    .eq('token', token)
    .gte('expires_at', new Date().toISOString())
    .single();
  
  if (error && error.code !== 'PGRST116') throw error;
  if (!data) return null;
  
  return {
    ...data,
    user: sanitizeUser(data.users)
  };
}

async function deleteSession(token) {
  if (!supabase) return fallbackDeleteSession(token);
  
  await supabase
    .from('sessions')
    .delete()
    .eq('token', token);
}

async function deleteUserSessions(userId) {
  if (!supabase) return;
  
  await supabase
    .from('sessions')
    .delete()
    .eq('user_id', userId);
}

// ============================================
// SCAN OPERATIONS
// ============================================

async function createScan({ userId, projectId = null, url }) {
  if (!supabase) return fallbackCreateScan({ userId, url });
  
  const { data, error } = await supabase
    .from('scans')
    .insert({
      user_id: userId,
      project_id: projectId,
      url,
      status: 'pending'
    })
    .select()
    .single();
  
  if (error) throw error;
  
  // Increment usage
  if (userId) {
    await incrementScanUsage(userId);
  }
  
  return data;
}

async function getScanById(id) {
  if (!supabase) return fallbackGetScanById(id);
  
  const { data, error } = await supabase
    .from('scans')
    .select('*')
    .eq('id', id)
    .single();
  
  if (error) throw error;
  return data;
}

async function updateScan(id, updates) {
  if (!supabase) return fallbackUpdateScan(id, updates);
  
  const { data, error } = await supabase
    .from('scans')
    .update(updates)
    .eq('id', id)
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

async function getUserScans(userId, { limit = 50, offset = 0, status = null } = {}) {
  if (!supabase) return fallbackGetUserScans(userId);
  
  let query = supabase
    .from('scans')
    .select('*', { count: 'exact' })
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);
  
  if (status) {
    query = query.eq('status', status);
  }
  
  const { data, error, count } = await query;
  
  if (error) throw error;
  return { scans: data, total: count };
}

// ============================================
// USAGE TRACKING
// ============================================

async function getUserUsage(userId) {
  if (!supabase) return fallbackGetUserUsage(userId);
  
  const { data, error } = await supabase
    .from('user_usage')
    .select('*')
    .eq('user_id', userId)
    .single();
  
  if (error && error.code === 'PGRST116') {
    // Create usage record if it doesn't exist
    const { data: newData } = await supabase
      .from('user_usage')
      .insert({ user_id: userId })
      .select()
      .single();
    return newData;
  }
  
  if (error) throw error;
  return data;
}

async function incrementScanUsage(userId) {
  if (!supabase) return;
  
  const today = new Date().toISOString().split('T')[0];
  const monthStart = new Date().toISOString().slice(0, 7) + '-01';
  
  // Get current usage
  const usage = await getUserUsage(userId);
  
  // Check if we need to reset daily or monthly counters
  const updates = {
    scans_all_time: usage.scans_all_time + 1
  };
  
  if (usage.last_scan_date !== today) {
    updates.scans_today = 1;
    updates.last_scan_date = today;
  } else {
    updates.scans_today = usage.scans_today + 1;
  }
  
  if (usage.month_start_date !== monthStart) {
    updates.scans_this_month = 1;
    updates.month_start_date = monthStart;
  } else {
    updates.scans_this_month = usage.scans_this_month + 1;
  }
  
  await supabase
    .from('user_usage')
    .update(updates)
    .eq('user_id', userId);
}

// Plan limits
const PLAN_LIMITS = {
  free: { scansPerDay: 1, scansPerMonth: 30 },
  pro: { scansPerDay: 10, scansPerMonth: 100 },
  team: { scansPerDay: Infinity, scansPerMonth: Infinity },
  enterprise: { scansPerDay: Infinity, scansPerMonth: Infinity },
};

async function canScan(userId) {
  if (!supabase) return fallbackCanScan(userId);
  
  // Get user's plan
  const user = await getUserById(userId);
  if (!user) return false;
  
  const limits = PLAN_LIMITS[user.plan] || PLAN_LIMITS.free;
  
  // Unlimited plans
  if (limits.scansPerDay === Infinity) return true;
  
  // Get usage
  const usage = await getUserUsage(userId);
  if (!usage) return true; // No usage record = first scan
  
  const today = new Date().toISOString().split('T')[0];
  const currentMonth = new Date().toISOString().slice(0, 7) + '-01';
  
  // Reset counters if new day/month
  let scansToday = usage.scans_today || 0;
  let scansThisMonth = usage.scans_this_month || 0;
  
  if (usage.last_scan_date !== today) {
    scansToday = 0;
  }
  if (usage.month_start_date !== currentMonth) {
    scansThisMonth = 0;
  }
  
  return scansToday < limits.scansPerDay && scansThisMonth < limits.scansPerMonth;
}

function fallbackCanScan(userId) {
  // In-memory fallback - allow scans
  return true;
}

// ============================================
// API KEY OPERATIONS
// ============================================

async function createApiKey(userId, name) {
  if (!supabase) return fallbackCreateApiKey(userId, name);
  
  const key = `vibeqa_${crypto.randomBytes(24).toString('hex')}`;
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  const keyPrefix = key.substring(0, 15);
  
  const { data, error } = await supabase
    .from('api_keys')
    .insert({
      user_id: userId,
      name,
      key_hash: keyHash,
      key_prefix: keyPrefix
    })
    .select()
    .single();
  
  if (error) throw error;
  
  // Return the full key only this once
  return { ...data, key };
}

async function getApiKeysByUserId(userId) {
  if (!supabase) return fallbackGetApiKeysByUserId(userId);
  
  const { data, error } = await supabase
    .from('api_keys')
    .select('id, name, key_prefix, last_used_at, usage_count, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false });
  
  if (error) throw error;
  return data;
}

async function validateApiKey(key) {
  if (!supabase) return fallbackValidateApiKey(key);
  
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  
  const { data, error } = await supabase
    .from('api_keys')
    .select('*, users(*)')
    .eq('key_hash', keyHash)
    .single();
  
  if (error || !data) return null;
  
  // Update usage stats
  await supabase
    .from('api_keys')
    .update({ 
      last_used_at: new Date().toISOString(),
      usage_count: data.usage_count + 1
    })
    .eq('id', data.id);
  
  return sanitizeUser(data.users);
}

async function deleteApiKey(id, userId) {
  if (!supabase) return fallbackDeleteApiKey(id, userId);
  
  const { error } = await supabase
    .from('api_keys')
    .delete()
    .eq('id', id)
    .eq('user_id', userId);
  
  if (error) throw error;
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + (process.env.PASSWORD_SALT || 'vibeqa-salt')).digest('hex');
}

function sanitizeUser(user) {
  if (!user) return null;
  const { password_hash, ...safe } = user;
  return safe;
}

// ============================================
// FALLBACK IN-MEMORY STORAGE
// (Used when Supabase is not configured)
// ============================================

const inMemoryStore = {
  users: new Map(),
  sessions: new Map(),
  scans: new Map(),
  apiKeys: new Map(),
  usage: new Map()
};

function fallbackCreateUser({ email, password, name }) {
  const id = crypto.randomUUID();
  const user = {
    id,
    email: email.toLowerCase(),
    password_hash: hashPassword(password),
    name,
    plan: 'free',
    settings: { notifications: { emailOnScanComplete: true } },
    integrations: {},
    created_at: new Date().toISOString()
  };
  
  // Auto-upgrade for special emails
  if (email.toLowerCase() === 'mkanaventi@gmail.com') {
    user.plan = 'team';
  }
  
  inMemoryStore.users.set(id, user);
  inMemoryStore.usage.set(id, { scans_today: 0, scans_this_month: 0, scans_all_time: 0 });
  return sanitizeUser(user);
}

function fallbackGetUserByEmail(email) {
  for (const user of inMemoryStore.users.values()) {
    if (user.email === email.toLowerCase()) {
      return sanitizeUser(user);
    }
  }
  return null;
}

function fallbackGetUserById(id) {
  const user = inMemoryStore.users.get(id);
  return user ? sanitizeUser(user) : null;
}

function fallbackUpdateUser(id, updates) {
  const user = inMemoryStore.users.get(id);
  if (!user) throw new Error('User not found');
  const updated = { ...user, ...updates };
  inMemoryStore.users.set(id, updated);
  return sanitizeUser(updated);
}

function fallbackVerifyPassword(email, password) {
  for (const user of inMemoryStore.users.values()) {
    if (user.email === email.toLowerCase() && user.password_hash === hashPassword(password)) {
      return user.id;
    }
  }
  return null;
}

function fallbackCreateSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  inMemoryStore.sessions.set(token, { user_id: userId, token, expires_at: expiresAt });
  return { token, expiresAt };
}

function fallbackGetSessionByToken(token) {
  const session = inMemoryStore.sessions.get(token);
  if (!session || new Date(session.expires_at) < new Date()) return null;
  const user = inMemoryStore.users.get(session.user_id);
  return { ...session, user: sanitizeUser(user) };
}

function fallbackDeleteSession(token) {
  inMemoryStore.sessions.delete(token);
}

function fallbackCreateScan({ userId, url }) {
  const id = crypto.randomUUID();
  const scan = {
    id,
    user_id: userId,
    url,
    status: 'pending',
    issues: [],
    screenshots: [],
    created_at: new Date().toISOString()
  };
  inMemoryStore.scans.set(id, scan);
  
  if (userId) {
    const usage = inMemoryStore.usage.get(userId) || { scans_today: 0, scans_this_month: 0, scans_all_time: 0 };
    usage.scans_today++;
    usage.scans_this_month++;
    usage.scans_all_time++;
    inMemoryStore.usage.set(userId, usage);
  }
  
  return scan;
}

function fallbackGetScanById(id) {
  return inMemoryStore.scans.get(id);
}

function fallbackUpdateScan(id, updates) {
  const scan = inMemoryStore.scans.get(id);
  if (!scan) throw new Error('Scan not found');
  const updated = { ...scan, ...updates };
  inMemoryStore.scans.set(id, updated);
  return updated;
}

function fallbackGetUserScans(userId) {
  const scans = [];
  for (const scan of inMemoryStore.scans.values()) {
    if (scan.user_id === userId) scans.push(scan);
  }
  return { scans: scans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)), total: scans.length };
}

function fallbackGetUserUsage(userId) {
  return inMemoryStore.usage.get(userId) || { scans_today: 0, scans_this_month: 0, scans_all_time: 0 };
}

function fallbackCreateApiKey(userId, name) {
  const key = `vibeqa_${crypto.randomBytes(24).toString('hex')}`;
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  const apiKey = {
    id: crypto.randomUUID(),
    user_id: userId,
    name,
    key_hash: keyHash,
    key_prefix: key.substring(0, 15),
    usage_count: 0,
    created_at: new Date().toISOString()
  };
  inMemoryStore.apiKeys.set(apiKey.id, apiKey);
  return { ...apiKey, key };
}

function fallbackGetApiKeysByUserId(userId) {
  const keys = [];
  for (const key of inMemoryStore.apiKeys.values()) {
    if (key.user_id === userId) {
      const { key_hash, ...safe } = key;
      keys.push(safe);
    }
  }
  return keys;
}

function fallbackValidateApiKey(key) {
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  for (const apiKey of inMemoryStore.apiKeys.values()) {
    if (apiKey.key_hash === keyHash) {
      return fallbackGetUserById(apiKey.user_id);
    }
  }
  return null;
}

function fallbackDeleteApiKey(id, userId) {
  const key = inMemoryStore.apiKeys.get(id);
  if (key && key.user_id === userId) {
    inMemoryStore.apiKeys.delete(id);
  }
}

// ============================================
// WEBHOOKS OPERATIONS
// ============================================

async function createWebhook(userId, { url, events = ['scan.complete'], secret = null }) {
  if (!supabase) return fallbackCreateWebhook(userId, { url, events, secret });
  
  const { data, error } = await supabase
    .from('webhooks')
    .insert({
      user_id: userId,
      url,
      events,
      secret: secret || crypto.randomBytes(16).toString('hex'),
      is_active: true
    })
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

async function getWebhooksByUserId(userId) {
  if (!supabase) return fallbackGetWebhooksByUserId(userId);
  
  const { data, error } = await supabase
    .from('webhooks')
    .select('*')
    .eq('user_id', userId)
    .order('created_at', { ascending: false });
  
  if (error) throw error;
  return data;
}

async function getActiveWebhooksForEvent(userId, event) {
  if (!supabase) return fallbackGetActiveWebhooksForEvent(userId, event);
  
  const { data, error } = await supabase
    .from('webhooks')
    .select('*')
    .eq('user_id', userId)
    .eq('is_active', true)
    .contains('events', [event]);
  
  if (error) throw error;
  return data;
}

async function updateWebhook(id, userId, updates) {
  if (!supabase) return fallbackUpdateWebhook(id, userId, updates);
  
  const { data, error } = await supabase
    .from('webhooks')
    .update(updates)
    .eq('id', id)
    .eq('user_id', userId)
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

async function deleteWebhook(id, userId) {
  if (!supabase) return fallbackDeleteWebhook(id, userId);
  
  const { error } = await supabase
    .from('webhooks')
    .delete()
    .eq('id', id)
    .eq('user_id', userId);
  
  if (error) throw error;
}

// ============================================
// SCHEDULED SCANS OPERATIONS
// ============================================

async function createScheduledScan(userId, { url, projectId = null, schedule, timezone = 'UTC' }) {
  if (!supabase) return fallbackCreateScheduledScan(userId, { url, projectId, schedule, timezone });
  
  const { data, error } = await supabase
    .from('scheduled_scans')
    .insert({
      user_id: userId,
      project_id: projectId,
      url,
      schedule, // 'daily', 'weekly', or cron expression
      timezone,
      is_active: true,
      next_run_at: calculateNextRun(schedule, timezone)
    })
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

async function getScheduledScansByUserId(userId) {
  if (!supabase) return fallbackGetScheduledScansByUserId(userId);
  
  const { data, error } = await supabase
    .from('scheduled_scans')
    .select('*')
    .eq('user_id', userId)
    .order('created_at', { ascending: false });
  
  if (error) throw error;
  return data;
}

async function getDueScheduledScans() {
  if (!supabase) return fallbackGetDueScheduledScans();
  
  const { data, error } = await supabase
    .from('scheduled_scans')
    .select('*, users(*)')
    .eq('is_active', true)
    .lte('next_run_at', new Date().toISOString());
  
  if (error) throw error;
  return data;
}

async function updateScheduledScan(id, userId, updates) {
  if (!supabase) return fallbackUpdateScheduledScan(id, userId, updates);
  
  const { data, error } = await supabase
    .from('scheduled_scans')
    .update(updates)
    .eq('id', id)
    .eq('user_id', userId)
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

async function deleteScheduledScan(id, userId) {
  if (!supabase) return fallbackDeleteScheduledScan(id, userId);
  
  const { error } = await supabase
    .from('scheduled_scans')
    .delete()
    .eq('id', id)
    .eq('user_id', userId);
  
  if (error) throw error;
}

function calculateNextRun(schedule, timezone) {
  const now = new Date();
  if (schedule === 'daily') {
    // Run at 9am in user's timezone, or next day if past 9am
    const next = new Date(now);
    next.setHours(9, 0, 0, 0);
    if (next <= now) next.setDate(next.getDate() + 1);
    return next.toISOString();
  } else if (schedule === 'weekly') {
    // Run on Monday at 9am
    const next = new Date(now);
    const dayOfWeek = next.getDay();
    const daysUntilMonday = dayOfWeek === 0 ? 1 : dayOfWeek === 1 ? 7 : 8 - dayOfWeek;
    next.setDate(next.getDate() + daysUntilMonday);
    next.setHours(9, 0, 0, 0);
    return next.toISOString();
  }
  // Default: run tomorrow
  const next = new Date(now);
  next.setDate(next.getDate() + 1);
  return next.toISOString();
}

// ============================================
// INTEGRATIONS (SLACK/GITHUB) OPERATIONS
// ============================================

async function saveSlackIntegration(userId, { accessToken, teamId, teamName, channelId, channelName, webhookUrl }) {
  if (!supabase) return fallbackSaveSlackIntegration(userId, { accessToken, teamId, teamName, channelId, channelName, webhookUrl });
  
  const integrations = await getUserIntegrations(userId);
  integrations.slack = {
    accessToken,
    teamId,
    teamName,
    channelId,
    channelName,
    webhookUrl,
    connectedAt: new Date().toISOString()
  };
  
  await updateUser(userId, { integrations });
  return integrations.slack;
}

async function saveGitHubIntegration(userId, { accessToken, username, installationId }) {
  if (!supabase) return fallbackSaveGitHubIntegration(userId, { accessToken, username, installationId });
  
  const integrations = await getUserIntegrations(userId);
  integrations.github = {
    accessToken,
    username,
    installationId,
    connectedAt: new Date().toISOString()
  };
  
  await updateUser(userId, { integrations });
  return integrations.github;
}

async function getUserIntegrations(userId) {
  if (!supabase) return fallbackGetUserIntegrations(userId);
  
  const { data, error } = await supabase
    .from('users')
    .select('integrations')
    .eq('id', userId)
    .single();
  
  if (error) throw error;
  return data?.integrations || {};
}

// ============================================
// WEBHOOK/SCHEDULED SCAN FALLBACKS
// ============================================

function fallbackCreateWebhook(userId, { url, events, secret }) {
  const webhook = {
    id: crypto.randomUUID(),
    user_id: userId,
    url,
    events,
    secret: secret || crypto.randomBytes(16).toString('hex'),
    is_active: true,
    failure_count: 0,
    created_at: new Date().toISOString()
  };
  if (!inMemoryStore.webhooks) inMemoryStore.webhooks = new Map();
  inMemoryStore.webhooks.set(webhook.id, webhook);
  return webhook;
}

function fallbackGetWebhooksByUserId(userId) {
  if (!inMemoryStore.webhooks) return [];
  const webhooks = [];
  for (const wh of inMemoryStore.webhooks.values()) {
    if (wh.user_id === userId) webhooks.push(wh);
  }
  return webhooks;
}

function fallbackGetActiveWebhooksForEvent(userId, event) {
  if (!inMemoryStore.webhooks) return [];
  const webhooks = [];
  for (const wh of inMemoryStore.webhooks.values()) {
    if (wh.user_id === userId && wh.is_active && wh.events.includes(event)) {
      webhooks.push(wh);
    }
  }
  return webhooks;
}

function fallbackUpdateWebhook(id, userId, updates) {
  if (!inMemoryStore.webhooks) return null;
  const wh = inMemoryStore.webhooks.get(id);
  if (!wh || wh.user_id !== userId) return null;
  Object.assign(wh, updates);
  return wh;
}

function fallbackDeleteWebhook(id, userId) {
  if (!inMemoryStore.webhooks) return;
  const wh = inMemoryStore.webhooks.get(id);
  if (wh && wh.user_id === userId) inMemoryStore.webhooks.delete(id);
}

function fallbackCreateScheduledScan(userId, { url, projectId, schedule, timezone }) {
  const ss = {
    id: crypto.randomUUID(),
    user_id: userId,
    project_id: projectId,
    url,
    schedule,
    timezone,
    is_active: true,
    next_run_at: calculateNextRun(schedule, timezone),
    last_run_at: null,
    created_at: new Date().toISOString()
  };
  if (!inMemoryStore.scheduledScans) inMemoryStore.scheduledScans = new Map();
  inMemoryStore.scheduledScans.set(ss.id, ss);
  return ss;
}

function fallbackGetScheduledScansByUserId(userId) {
  if (!inMemoryStore.scheduledScans) return [];
  const scans = [];
  for (const ss of inMemoryStore.scheduledScans.values()) {
    if (ss.user_id === userId) scans.push(ss);
  }
  return scans;
}

function fallbackGetDueScheduledScans() {
  if (!inMemoryStore.scheduledScans) return [];
  const now = new Date();
  const due = [];
  for (const ss of inMemoryStore.scheduledScans.values()) {
    if (ss.is_active && new Date(ss.next_run_at) <= now) {
      const user = fallbackGetUserById(ss.user_id);
      due.push({ ...ss, users: user });
    }
  }
  return due;
}

function fallbackUpdateScheduledScan(id, userId, updates) {
  if (!inMemoryStore.scheduledScans) return null;
  const ss = inMemoryStore.scheduledScans.get(id);
  if (!ss || ss.user_id !== userId) return null;
  Object.assign(ss, updates);
  return ss;
}

function fallbackDeleteScheduledScan(id, userId) {
  if (!inMemoryStore.scheduledScans) return;
  const ss = inMemoryStore.scheduledScans.get(id);
  if (ss && ss.user_id === userId) inMemoryStore.scheduledScans.delete(id);
}

function fallbackSaveSlackIntegration(userId, data) {
  const user = inMemoryStore.users.get(userId);
  if (!user) return null;
  if (!user.integrations) user.integrations = {};
  user.integrations.slack = { ...data, connectedAt: new Date().toISOString() };
  return user.integrations.slack;
}

function fallbackSaveGitHubIntegration(userId, data) {
  const user = inMemoryStore.users.get(userId);
  if (!user) return null;
  if (!user.integrations) user.integrations = {};
  user.integrations.github = { ...data, connectedAt: new Date().toISOString() };
  return user.integrations.github;
}

function fallbackGetUserIntegrations(userId) {
  for (const user of inMemoryStore.users.values()) {
    if (user.id === userId) return user.integrations || {};
  }
  return {};
}

// ============================================
// EXPORTS
// ============================================

module.exports = {
  supabase,
  isConfigured: !!supabase,
  
  // Users
  createUser,
  getUserByEmail,
  getUserById,
  updateUser,
  verifyPassword,
  
  // Sessions
  createSession,
  getSessionByToken,
  deleteSession,
  deleteUserSessions,
  
  // Scans
  createScan,
  getScanById,
  updateScan,
  getUserScans,
  
  // Usage
  getUserUsage,
  incrementScanUsage,
  canScan,
  
  // API Keys
  createApiKey,
  getApiKeysByUserId,
  validateApiKey,
  deleteApiKey,
  
  // Webhooks
  createWebhook,
  getWebhooksByUserId,
  getActiveWebhooksForEvent,
  updateWebhook,
  deleteWebhook,
  
  // Scheduled Scans
  createScheduledScan,
  getScheduledScansByUserId,
  getDueScheduledScans,
  updateScheduledScan,
  deleteScheduledScan,
  calculateNextRun,
  
  // Integrations
  saveSlackIntegration,
  saveGitHubIntegration,
  getUserIntegrations,
  
  // Helpers
  hashPassword,
  sanitizeUser,
  
  // Password Reset
  createPasswordReset,
  verifyPasswordResetToken,
  completePasswordReset
};

// ============================================
// Password Reset
// ============================================

async function createPasswordReset(email) {
  if (!supabase) return null;
  
  // Find user by email
  const { data: user, error: userError } = await supabase
    .from('users')
    .select('id, email, name')
    .eq('email', email.toLowerCase())
    .single();
  
  if (userError || !user) return null;
  
  // Generate token (64 char hex)
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  
  // Invalidate any existing tokens for this user
  await supabase
    .from('password_resets')
    .delete()
    .eq('user_id', user.id);
  
  // Create new token
  const { error } = await supabase
    .from('password_resets')
    .insert({
      user_id: user.id,
      token,
      expires_at: expiresAt.toISOString()
    });
  
  if (error) {
    console.error('Error creating password reset:', error);
    return null;
  }
  
  return { token, user };
}

async function verifyPasswordResetToken(token) {
  if (!supabase) return null;
  
  const { data, error } = await supabase
    .from('password_resets')
    .select('*, users(id, email, name)')
    .eq('token', token)
    .is('used_at', null)
    .gte('expires_at', new Date().toISOString())
    .single();
  
  if (error || !data) return null;
  
  return {
    resetId: data.id,
    userId: data.user_id,
    user: data.users
  };
}

async function completePasswordReset(token, newPassword) {
  if (!supabase) return false;
  
  const reset = await verifyPasswordResetToken(token);
  if (!reset) return false;
  
  const passwordHash = hashPassword(newPassword);
  
  // Update password
  const { error: updateError } = await supabase
    .from('users')
    .update({ password_hash: passwordHash })
    .eq('id', reset.userId);
  
  if (updateError) return false;
  
  // Mark token as used
  await supabase
    .from('password_resets')
    .update({ used_at: new Date().toISOString() })
    .eq('id', reset.resetId);
  
  // Delete all sessions for this user (force re-login)
  await supabase
    .from('sessions')
    .delete()
    .eq('user_id', reset.userId);
  
  return true;
}
