// Centralized pricing configuration
// Update here and it applies everywhere

const PLANS = {
  free: {
    id: 'free',
    name: 'Free',
    price: 0,
    priceDisplay: '$0',
    interval: 'month',
    limits: {
      scansPerDay: 1,
      scansPerMonth: 30,
      historyDays: 7,
      projects: 1,
      teamMembers: 1,
      apiRequests: 0,
      webhooks: 0,
    },
    features: [
      '1 scan per day',
      '7-day history',
      'Basic checks (SEO, mobile, performance)',
      'Email notifications',
    ],
    cta: 'Start Free',
    popular: false,
  },
  pro: {
    id: 'pro',
    name: 'Pro',
    price: 29,
    priceDisplay: '$29',
    interval: 'month',
    stripePriceId: process.env.STRIPE_PRO_PRICE_ID || 'price_pro_monthly',
    limits: {
      scansPerDay: 10,
      scansPerMonth: 100,
      historyDays: 90,
      projects: 10,
      teamMembers: 1,
      apiRequests: 1000,
      webhooks: 3,
    },
    features: [
      '100 scans per month',
      '90-day history',
      'AI-powered UX analysis',
      'API access',
      'GitHub integration',
      'Slack notifications',
      '3 webhooks',
      'Priority email support',
    ],
    cta: 'Start Pro Trial',
    popular: true,
  },
  team: {
    id: 'team',
    name: 'Team',
    price: 79,
    priceDisplay: '$79',
    interval: 'month',
    stripePriceId: process.env.STRIPE_TEAM_PRICE_ID || 'price_team_monthly',
    limits: {
      scansPerDay: Infinity,
      scansPerMonth: Infinity,
      historyDays: 365,
      projects: Infinity,
      teamMembers: 10,
      apiRequests: 10000,
      webhooks: 10,
    },
    features: [
      'Unlimited scans',
      '1-year history',
      'AI-powered UX analysis',
      'Full API access',
      'All integrations (GitHub, Slack, Vercel, etc.)',
      'Unlimited webhooks',
      'Team collaboration (up to 10)',
      'Priority support',
      'Custom scan schedules',
    ],
    cta: 'Start Team Trial',
    popular: false,
  },
  enterprise: {
    id: 'enterprise',
    name: 'Enterprise',
    price: null, // Custom pricing
    priceDisplay: 'Custom',
    interval: 'month',
    limits: {
      scansPerDay: Infinity,
      scansPerMonth: Infinity,
      historyDays: Infinity,
      projects: Infinity,
      teamMembers: Infinity,
      apiRequests: Infinity,
      webhooks: Infinity,
    },
    features: [
      'Everything in Team',
      'Unlimited team members',
      'SSO (SAML)',
      'SCIM provisioning',
      'Audit logs',
      'Custom integrations',
      'Dedicated support',
      'SLA guarantee',
      'On-premise option',
    ],
    cta: 'Contact Sales',
    popular: false,
  },
};

// Integration platforms available per plan
const INTEGRATIONS = {
  github: { name: 'GitHub', plans: ['pro', 'team', 'enterprise'], category: 'code' },
  gitlab: { name: 'GitLab', plans: ['pro', 'team', 'enterprise'], category: 'code' },
  vercel: { name: 'Vercel', plans: ['team', 'enterprise'], category: 'deploy' },
  netlify: { name: 'Netlify', plans: ['team', 'enterprise'], category: 'deploy' },
  slack: { name: 'Slack', plans: ['pro', 'team', 'enterprise'], category: 'notifications' },
  discord: { name: 'Discord', plans: ['pro', 'team', 'enterprise'], category: 'notifications' },
  linear: { name: 'Linear', plans: ['team', 'enterprise'], category: 'project' },
  jira: { name: 'Jira', plans: ['team', 'enterprise'], category: 'project' },
  cursor: { name: 'Cursor', plans: ['team', 'enterprise'], category: 'vibe' },
  bolt: { name: 'Bolt', plans: ['team', 'enterprise'], category: 'vibe' },
  replit: { name: 'Replit', plans: ['team', 'enterprise'], category: 'vibe' },
  v0: { name: 'v0', plans: ['team', 'enterprise'], category: 'vibe' },
  lovable: { name: 'Lovable', plans: ['team', 'enterprise'], category: 'vibe' },
};

// Usage tracking events
const USAGE_EVENTS = {
  SCAN_STARTED: 'scan_started',
  SCAN_COMPLETED: 'scan_completed',
  API_CALL: 'api_call',
  WEBHOOK_TRIGGERED: 'webhook_triggered',
  REPORT_EXPORTED: 'report_exported',
  TEAM_MEMBER_ADDED: 'team_member_added',
  INTEGRATION_CONNECTED: 'integration_connected',
};

// Upgrade triggers - when to nudge users
const UPGRADE_TRIGGERS = {
  // Percentage of limit used before showing upgrade prompt
  usageThreshold: 0.8, // 80%
  
  // Specific triggers
  triggers: [
    { event: 'scan_limit_reached', message: 'You\'ve hit your daily scan limit. Upgrade to Pro for 10 scans/day.' },
    { event: 'history_limit_reached', message: 'Your scan history is limited to 7 days. Upgrade for 90-day history.' },
    { event: 'api_requested', message: 'API access is available on Pro and above.' },
    { event: 'team_member_limit', message: 'Need more team members? Upgrade to Team for up to 10 collaborators.' },
    { event: 'integration_requested', message: 'Integrations are available on Pro and above.' },
    { event: 'ai_analysis_requested', message: 'AI-powered analysis is available on Pro and above.' },
  ],
};

function getPlanLimits(planId) {
  return PLANS[planId]?.limits || PLANS.free.limits;
}

function canAccessFeature(planId, feature) {
  const planOrder = ['free', 'pro', 'team', 'enterprise'];
  const userPlanIndex = planOrder.indexOf(planId);
  
  const featureMinPlan = {
    'api_access': 'pro',
    'ai_analysis': 'pro',
    'webhooks': 'pro',
    'github_integration': 'pro',
    'slack_integration': 'pro',
    'team_members': 'team',
    'vercel_integration': 'team',
    'linear_integration': 'team',
    'vibe_integrations': 'team',
    'sso': 'enterprise',
    'audit_logs': 'enterprise',
    'scim': 'enterprise',
  };
  
  const requiredPlanIndex = planOrder.indexOf(featureMinPlan[feature] || 'free');
  return userPlanIndex >= requiredPlanIndex;
}

function getUpgradeMessage(planId, attemptedFeature) {
  const trigger = UPGRADE_TRIGGERS.triggers.find(t => t.event === attemptedFeature);
  return trigger?.message || 'Upgrade your plan to access this feature.';
}

module.exports = {
  PLANS,
  INTEGRATIONS,
  USAGE_EVENTS,
  UPGRADE_TRIGGERS,
  getPlanLimits,
  canAccessFeature,
  getUpgradeMessage,
};
