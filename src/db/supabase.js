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
    .select('id, password_hash')
    .eq('email', email.toLowerCase())
    .single();
  
  if (error || !data) return null;
  
  const passwordHash = hashPassword(password);
  if (data.password_hash !== passwordHash) return null;
  
  // Update login stats
  await supabase
    .from('users')
    .update({ 
      last_login_at: new Date().toISOString(),
      login_count: supabase.raw('login_count + 1')
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
  
  // API Keys
  createApiKey,
  getApiKeysByUserId,
  validateApiKey,
  deleteApiKey,
  
  // Helpers
  hashPassword,
  sanitizeUser
};
