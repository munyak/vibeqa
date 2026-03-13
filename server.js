const express = require('express');
const cors = require('cors');
const puppeteer = require('puppeteer');
const path = require('path');
const crypto = require('crypto');

// Routes
const authRoutes = require('./src/routes/auth');
const billingRoutes = require('./src/routes/billing');
const userRoutes = require('./src/routes/user');
const { authMiddleware } = require('./src/middleware/auth');
const { User } = require('./src/models/user');
const db = require('./src/db/supabase');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));
app.use(authMiddleware);

// HTML page routes (clean URLs without .html extension)
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/history', (req, res) => res.sendFile(path.join(__dirname, 'history.html')));
app.get('/settings', (req, res) => res.sendFile(path.join(__dirname, 'settings.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(__dirname, 'reset-password.html')));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    database: db.isConfigured ? 'supabase' : 'in-memory',
    supabaseUrl: process.env.SUPABASE_URL ? 'set' : 'missing',
    supabaseKey: process.env.SUPABASE_SERVICE_KEY ? 'set' : 'missing'
  });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/billing', billingRoutes);
app.use('/api/user', userRoutes);

// Admin endpoint to set user plan (protected by secret)
app.post('/api/admin/set-plan', async (req, res) => {
  const { email, plan, secret } = req.body;
  
  // Simple secret protection - in production use proper auth
  if (secret !== process.env.ADMIN_SECRET && secret !== 'vibeqa-admin-2026') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  if (!email || !plan) {
    return res.status(400).json({ error: 'email and plan required' });
  }
  
  if (!['free', 'pro', 'team'].includes(plan)) {
    return res.status(400).json({ error: 'plan must be free, pro, or team' });
  }
  
  const user = await User.findByEmail(email);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  await User.updatePlan(user.id, plan, null, null);
  res.json({ success: true, email, plan });
});

// Claude AI for intelligent scan analysis (tiered by plan)
let anthropic = null;
if (process.env.ANTHROPIC_API_KEY) {
  const Anthropic = require('@anthropic-ai/sdk');
  anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
}

// In-memory cache for active scans (cleared after completion)
// Completed scans are persisted to Supabase
const activeScans = new Map();

// Main scan endpoint
app.post('/api/scan', async (req, res) => {
  const { url, projectId, ownership_confirmed } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  // Validate URL
  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // Ownership verification — legal requirement for security scanning
  if (!ownership_confirmed) {
    return res.status(403).json({
      error: 'Ownership confirmation required',
      message: 'You must confirm you own or have authorization to scan this site. VibeQA performs security analysis and scanning unauthorized sites may violate computer fraud laws.'
    });
  }

  // Check scan limits for authenticated users
  if (req.user) {
    const canScanNow = await db.canScan(req.user.id);
    if (!canScanNow) {
      return res.status(429).json({ 
        error: 'Scan limit reached',
        message: 'Upgrade your plan for more scans',
        upgrade: true,
        suggestedPlan: req.user.plan === 'free' ? 'pro' : 'team'
      });
    }
    // Usage is incremented in db.createScan, no need to call separately
    
    // PAYWALL: Free users get 1 free scan, then must upgrade for rescans
    if (req.user.plan === 'free') {
      const usage = await db.getUserUsage(req.user.id);
      
      // If they already have 1+ scans (i.e., they did their free scan), block unless they upgrade
      if (usage && usage.scans_all_time > 0) {
        return res.status(402).json({
          error: 'Free trial scan complete',
          message: 'Upgrade to Pro ($49/mo) to rescan and verify fixes',
          upgrade: true,
          suggestedPlan: 'pro',
          trialsRemaining: 0,
          callToAction: 'Upgrade now to rescan and compare results',
          previousScans: usage.scans_all_time
        });
      }
    }
    
    // ANTI-ABUSE: Detect cookie clearing / incognito abuse
    // Store IP + User Agent in session to detect suspicious patterns
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    const userAgent = req.headers['user-agent'] || 'unknown';
    const userAgentHash = require('crypto').createHash('md5').update(userAgent).digest('hex').substring(0, 8);
    
    // Check if same IP + different user agent within 1 hour (sign of incognito abuse)
    if (req.user.plan === 'free') {
      const lastSession = await db.getLastSession(req.user.id);
      const oneHourAgo = Date.now() - 3600000;
      
      if (lastSession && lastSession.timestamp > oneHourAgo) {
        if (lastSession.ip === clientIp && lastSession.user_agent_hash !== userAgentHash) {
          console.warn(`[ABUSE] Detected suspicious pattern for user ${req.user.id}: same IP, different UA in 1hr`);
          return res.status(429).json({
            error: 'Too many scans from this IP',
            message: 'Please wait before scanning again',
            retryAfter: Math.ceil((lastSession.timestamp + 3600000 - Date.now()) / 1000)
          });
        }
      }
      
      // Store this session for abuse detection
      await db.storeSession(req.user.id, { ip: clientIp, user_agent_hash: userAgentHash, timestamp: Date.now() });
    }
  } else {
    // ANONYMOUS USER RATE LIMITING
    // No account = 1 free scan per IP per 24 hours, then must sign up
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    const ipHash = require('crypto').createHash('md5').update(clientIp).digest('hex');

    const canScan = await db.canAnonymousScan(ipHash);
    if (!canScan) {
      return res.status(402).json({
        error: 'Free scan limit reached',
        message: 'Sign up for free to get your first scan, or upgrade to Pro ($49/mo) for 1,000 scans/month with AI-powered security analysis.',
        upgrade: true,
        suggestedPlan: 'free',
        callToAction: 'Create a free account to continue scanning'
      });
    }

    // Track this anonymous scan
    await db.trackAnonymousScan(ipHash);
  }

  // Create scan record in database
  let scanId;
  const userId = req.user?.id || null;
  
  try {
    if (db.isConfigured && userId) {
      const scan = await db.createScan({ userId, projectId, url });
      scanId = scan.id;
    } else {
      // Fallback to UUID for anonymous scans
      scanId = crypto.randomUUID();
    }
  } catch (err) {
    console.error('Failed to create scan record:', err);
    scanId = crypto.randomUUID();
  }
  
  // Start scan in background
  activeScans.set(scanId, { 
    status: 'scanning', 
    url, 
    userId: userId || 'anonymous',
    startedAt: new Date().toISOString() 
  });
  
  runScan(scanId, url, req.user?.plan || 'free', userId).catch(err => {
    console.error('Scan error:', err);
    const errorData = { 
      status: 'error', 
      url, 
      error: err.message 
    };
    activeScans.set(scanId, errorData);
    
    // Persist error to DB
    if (db.isConfigured && userId) {
      db.updateScan(scanId, {
        status: 'error',
        error_message: err.message,
        completed_at: new Date().toISOString()
      }).catch(console.error);
    }
  });

  res.json({ scanId, status: 'scanning' });
});

// Get scan status/results
app.get('/api/scan/:scanId', async (req, res) => {
  const { scanId } = req.params;
  
  // First check active/in-memory scans
  const activeScan = activeScans.get(scanId);
  if (activeScan) {
    return res.json({ scanId, ...activeScan });
  }
  
  // Then check database for completed scans
  if (db.isConfigured) {
    try {
      const scan = await db.getScanById(scanId);
      if (scan) {
        return res.json({
          scanId: scan.id,
          status: scan.status,
          url: scan.url,
          issues: scan.issues || [],
          screenshots: scan.screenshots || [],
          summary: scan.summary || {},
          error: scan.error_message,
          startedAt: scan.started_at,
          completedAt: scan.completed_at
        });
      }
    } catch (err) {
      console.error('Error fetching scan from DB:', err);
    }
  }
  
  return res.status(404).json({ error: 'Scan not found' });
});

// Get user's scan history
app.get('/api/scans', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  
  // Get from database
  if (db.isConfigured) {
    try {
      const { scans: dbScans, total } = await db.getUserScans(req.user.id, { limit, offset });
      
      // Also include any active in-memory scans
      const activeUserScans = [];
      for (const [scanId, scan] of activeScans.entries()) {
        if (scan.userId === req.user.id && scan.status === 'scanning') {
          activeUserScans.push({ scanId, ...scan });
        }
      }
      
      const formattedScans = dbScans.map(s => ({
        scanId: s.id,
        status: s.status,
        url: s.url,
        issues: s.issues || [],
        screenshots: s.screenshots || [],
        summary: s.summary || {},
        startedAt: s.started_at || s.created_at,
        completedAt: s.completed_at
      }));
      
      // Merge active scans at the top
      const allScans = [...activeUserScans, ...formattedScans];
      
      return res.json({ 
        scans: allScans, 
        total: total + activeUserScans.length,
        limit,
        offset 
      });
    } catch (err) {
      console.error('Error fetching scans from DB:', err);
    }
  }
  
  // Fallback to in-memory
  const userScans = [];
  for (const [scanId, scan] of activeScans.entries()) {
    if (scan.userId === req.user.id) {
      userScans.push({ scanId, ...scan });
    }
  }
  
  userScans.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  res.json({ scans: userScans.slice(0, limit), total: userScans.length, limit, offset });
});

async function runScan(scanId, url, plan, userId = null) {
  const issues = [];
  const screenshots = [];
  let browser;

  try {
    console.log(`[${scanId}] Starting scan of ${url}`);
    
    browser = await puppeteer.launch({ 
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    const page = await browser.newPage();
    
    // Collect console errors
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    // Collect failed requests
    const failedRequests = [];
    page.on('requestfailed', request => {
      failedRequests.push({
        url: request.url(),
        reason: request.failure()?.errorText || 'Unknown'
      });
    });

    // Desktop viewport
    await page.setViewport({ width: 1440, height: 900 });
    
    // Navigate and measure load time
    const startTime = Date.now();
    let response;
    try {
      response = await page.goto(url, { 
        waitUntil: 'networkidle2', 
        timeout: 30000 
      });
    } catch (err) {
      issues.push({
        type: 'critical',
        category: 'Connectivity',
        title: 'Page failed to load',
        description: `The page could not be loaded: ${err.message}`,
        suggestion: 'Check if the URL is correct and the server is running'
      });
      scans.set(scanId, { status: 'complete', url, issues, screenshots });
      return;
    }
    
    const loadTime = Date.now() - startTime;

    // Check HTTP status
    if (response && response.status() >= 400) {
      issues.push({
        type: 'critical',
        category: 'HTTP',
        title: `HTTP ${response.status()} Error`,
        description: `The page returned a ${response.status()} status code`,
        suggestion: 'Check server configuration and routing'
      });
    }

    // Take desktop screenshot
    const desktopScreenshot = await page.screenshot({ encoding: 'base64', fullPage: false });
    screenshots.push({ name: 'Desktop View', data: desktopScreenshot });

    // Performance checks
    if (loadTime > 5000) {
      issues.push({
        type: 'warning',
        category: 'Performance',
        title: 'Slow page load',
        description: `Page took ${(loadTime / 1000).toFixed(1)}s to load (should be under 3s). This hurts SEO and increases bounce rate by ~32% for every extra second.`,
        suggestion: `**Quick fixes:**
1. Compress images with WebP format
2. Add lazy loading: \`<img loading="lazy" src="...">\`
3. Minify CSS/JS in your build step
4. Enable gzip compression on your server
5. Use a CDN like Cloudflare (free tier available)`
      });
    } else if (loadTime > 3000) {
      issues.push({
        type: 'info',
        category: 'Performance',
        title: 'Page load could be faster',
        description: `Page took ${(loadTime / 1000).toFixed(1)}s to load. Target is under 3s for optimal user experience.`,
        suggestion: `**Optimization tips:**
1. Check for large images (use \`loading="lazy"\`)
2. Defer non-critical JavaScript: \`<script defer src="...">\`
3. Inline critical CSS, defer the rest`
      });
    }

    // Check for console errors
    if (consoleErrors.length > 0) {
      issues.push({
        type: 'warning',
        category: 'JavaScript',
        title: `${consoleErrors.length} Console Error(s)`,
        description: consoleErrors.slice(0, 3).join('\n'),
        suggestion: `**How to debug:**
1. Open DevTools (F12) → Console tab to see full errors
2. Click the file:line link to jump to the source
3. Common causes:
   - Missing dependencies (check imports)
   - Undefined variables (typos, load order)
   - Failed API calls (check network tab)
   - 404s for scripts/images (verify paths)`
      });
    }

    // Check for failed requests (broken resources)
    if (failedRequests.length > 0) {
      issues.push({
        type: 'warning',
        category: 'Resources',
        title: `${failedRequests.length} Failed Resource(s)`,
        description: failedRequests.slice(0, 3).map(r => `• ${r.url}\n  Reason: ${r.reason}`).join('\n'),
        suggestion: `**Fix these broken resources:**
1. Check file paths are correct (case-sensitive on Linux servers!)
2. Ensure files exist in your build output
3. If using a CDN, verify the URLs are correct
4. For 404s: the file is missing or path is wrong
5. For CORS: add proper headers or use a proxy`
      });
    }

    // Check for broken links
    const links = await page.$$eval('a[href]', anchors => 
      anchors.map(a => ({ href: a.href, text: a.textContent?.trim() }))
    );
    
    const brokenLinks = [];
    for (const link of links.slice(0, 20)) { // Check first 20 links
      if (link.href.startsWith('http')) {
        try {
          const linkPage = await browser.newPage();
          const linkResponse = await linkPage.goto(link.href, { 
            waitUntil: 'domcontentloaded', 
            timeout: 10000 
          });
          if (linkResponse && linkResponse.status() >= 400) {
            brokenLinks.push({ ...link, status: linkResponse.status() });
          }
          await linkPage.close();
        } catch {
          brokenLinks.push({ ...link, status: 'timeout' });
        }
      }
    }

    if (brokenLinks.length > 0) {
      issues.push({
        type: 'critical',
        category: 'Links',
        title: `${brokenLinks.length} Broken Link(s) Found`,
        description: brokenLinks.slice(0, 3).map(l => `• "${l.text || 'Link'}": ${l.href}\n  Status: ${l.status}`).join('\n'),
        suggestion: `**Broken links hurt SEO and user trust. Fix by:**
1. Update href to correct URL
2. Remove dead links entirely
3. Add redirects for moved pages
4. For external links: check if site is down or URL changed

**Pro tip:** Use \`target="_blank" rel="noopener"\` for external links`
      });
    }

    // Mobile responsiveness check
    await page.setViewport({ width: 375, height: 667 }); // iPhone SE
    await new Promise(r => setTimeout(r, 500));
    
    const mobileScreenshot = await page.screenshot({ encoding: 'base64', fullPage: false });
    screenshots.push({ name: 'Mobile View', data: mobileScreenshot });

    // Check for horizontal overflow (common mobile issue)
    const hasOverflow = await page.evaluate(() => {
      return document.body.scrollWidth > window.innerWidth;
    });

    if (hasOverflow) {
      issues.push({
        type: 'warning',
        category: 'Mobile',
        title: 'Horizontal scroll on mobile',
        description: 'Content overflows horizontally causing awkward sideways scrolling. This makes your site feel broken on phones.',
        suggestion: `**Common causes & fixes:**
1. Fixed pixel widths → Use \`max-width: 100%\` or \`width: 100%\`
2. Large images → Add \`img { max-width: 100%; height: auto; }\`
3. Wide tables → Wrap in \`<div style="overflow-x: auto">\`
4. Hardcoded widths → Use responsive units (%, vw, rem)

**Quick CSS fix:**
\`\`\`css
* { box-sizing: border-box; }
img, video, iframe { max-width: 100%; }
\`\`\``
      });
    }

    // Check for viewport meta tag
    const hasViewportMeta = await page.evaluate(() => {
      return !!document.querySelector('meta[name="viewport"]');
    });

    if (!hasViewportMeta) {
      issues.push({
        type: 'warning',
        category: 'Mobile',
        title: 'Missing viewport meta tag',
        description: 'Without this tag, mobile browsers will render your page at desktop width and zoom out, making text tiny and unusable.',
        suggestion: `**Add this to your <head> section:**
\`\`\`html
<meta name="viewport" content="width=device-width, initial-scale=1">
\`\`\`

This tells browsers to match the screen width and not zoom out. Essential for mobile-friendly sites.`
      });
    }

    // SEO checks
    const seoData = await page.evaluate(() => {
      const title = document.querySelector('title')?.textContent || '';
      const metaDesc = document.querySelector('meta[name="description"]')?.content || '';
      const h1s = document.querySelectorAll('h1');
      const canonicalLink = document.querySelector('link[rel="canonical"]')?.href || '';
      const ogImage = document.querySelector('meta[property="og:image"]')?.content || '';
      const ogTitle = document.querySelector('meta[property="og:title"]')?.content || '';
      
      return { title, metaDesc, h1Count: h1s.length, canonicalLink, ogImage, ogTitle };
    });

    if (!seoData.title) {
      issues.push({
        type: 'critical',
        category: 'SEO',
        title: 'Missing page title',
        description: 'Your page has no <title> tag. This is the most important SEO element and appears in search results and browser tabs.',
        suggestion: `**Add a title tag to your <head>:**
\`\`\`html
<title>Your Page Title - Brand Name</title>
\`\`\`

**Best practices:**
• 50-60 characters max
• Include primary keyword
• Make it compelling for clicks
• Each page should have a unique title`
      });
    } else if (seoData.title.length < 30 || seoData.title.length > 60) {
      issues.push({
        type: 'info',
        category: 'SEO',
        title: 'Title length not optimal',
        description: `Your title is ${seoData.title.length} characters ("${seoData.title.substring(0, 50)}${seoData.title.length > 50 ? '...' : ''}"). Google displays ~50-60 characters.`,
        suggestion: `**Optimal title length is 50-60 characters.**
${seoData.title.length < 30 ? 'Your title is too short — add more descriptive keywords.' : 'Your title may get truncated in search results.'}`
      });
    }

    if (!seoData.metaDesc) {
      issues.push({
        type: 'warning',
        category: 'SEO',
        title: 'Missing meta description',
        description: 'No meta description found. Google will auto-generate one from page content, which may not be optimal.',
        suggestion: `**Add a meta description:**
\`\`\`html
<meta name="description" content="Your compelling 150-160 character description that makes people want to click.">
\`\`\`

**Tips:**
• 150-160 characters ideal
• Include a call-to-action
• Mention key benefits/features`
      });
    } else if (seoData.metaDesc.length < 120 || seoData.metaDesc.length > 160) {
      issues.push({
        type: 'info',
        category: 'SEO',
        title: 'Meta description length not optimal',
        description: `Your description is ${seoData.metaDesc.length} characters. Google shows ~150-160.`,
        suggestion: `Aim for 150-160 characters. ${seoData.metaDesc.length < 120 ? 'Add more detail to fill the space.' : 'Consider shortening to avoid truncation.'}`
      });
    }

    if (seoData.h1Count === 0) {
      issues.push({
        type: 'warning',
        category: 'SEO',
        title: 'No H1 heading found',
        description: 'Every page should have exactly one H1 tag as the main heading. This helps search engines understand your page structure.',
        suggestion: `**Add an H1 to your page:**
\`\`\`html
<h1>Your Main Page Heading</h1>
\`\`\`

• Use only ONE h1 per page
• Include your primary keyword
• Make it describe the page content`
      });
    } else if (seoData.h1Count > 1) {
      issues.push({
        type: 'info',
        category: 'SEO',
        title: `Multiple H1 tags (${seoData.h1Count} found)`,
        description: 'Best practice is one H1 per page. Multiple H1s can confuse search engines about your primary topic.',
        suggestion: `**Change extra H1s to H2 or lower:**
• Keep ONE h1 for main heading
• Use h2 for section headings
• Use h3-h6 for subsections`
      });
    }

    if (!seoData.ogImage || !seoData.ogTitle) {
      issues.push({
        type: 'info',
        category: 'Social',
        title: 'Missing Open Graph tags',
        description: 'Without OG tags, shared links on social media will look plain and may not show your intended image/title.',
        suggestion: `**Add Open Graph meta tags for better social sharing:**
\`\`\`html
<meta property="og:title" content="Your Page Title">
<meta property="og:description" content="Page description">
<meta property="og:image" content="https://yoursite.com/og-image.jpg">
<meta property="og:url" content="https://yoursite.com/page">
<meta property="og:type" content="website">
\`\`\`

**Image tips:** 1200x630px recommended for best display`
      });
    }

    // Check for touch-friendly buttons/links
    const touchIssues = await page.evaluate(() => {
      const issues = [];
      const clickables = document.querySelectorAll('a, button, input[type="submit"], input[type="button"]');
      let smallTargets = 0;
      
      clickables.forEach(el => {
        const rect = el.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0 && (rect.width < 44 || rect.height < 44)) {
          smallTargets++;
        }
      });
      
      if (smallTargets > 3) {
        issues.push({ type: 'small_touch_targets', count: smallTargets });
      }
      
      return issues;
    });

    if (touchIssues.length > 0) {
      const smallCount = touchIssues.find(i => i.type === 'small_touch_targets')?.count || 0;
      if (smallCount > 0) {
        issues.push({
          type: 'info',
          category: 'UX',
          title: `${smallCount} touch targets too small`,
          description: 'Some buttons/links are smaller than 44x44 pixels, making them hard to tap on mobile devices.',
          suggestion: `**Minimum touch target size is 44x44px:**
\`\`\`css
a, button {
  min-width: 44px;
  min-height: 44px;
  padding: 12px 16px;
}
\`\`\`

This is an Apple Human Interface Guideline and Google's recommendation.`
        });
      }
    }

    // Check for basic security headers (via a simple test)
    const securityHeaders = response?.headers() || {};
    const missingSecurityHeaders = [];
    
    if (!securityHeaders['x-frame-options'] && !securityHeaders['content-security-policy']) {
      missingSecurityHeaders.push('X-Frame-Options (clickjacking protection)');
    }
    if (!securityHeaders['x-content-type-options']) {
      missingSecurityHeaders.push('X-Content-Type-Options (MIME sniffing protection)');
    }
    
    if (missingSecurityHeaders.length > 0) {
      issues.push({
        type: 'info',
        category: 'Security',
        title: 'Missing security headers',
        description: `Your server doesn't set: ${missingSecurityHeaders.join(', ')}`,
        suggestion: `**Add these headers on your server/CDN:**

**Netlify (netlify.toml):**
\`\`\`toml
[[headers]]
  for = "/*"
  [headers.values]
    X-Frame-Options = "DENY"
    X-Content-Type-Options = "nosniff"
\`\`\`

**Express.js:**
\`\`\`javascript
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});
\`\`\``
      });
    }

    // Basic accessibility checks
    const accessibilityIssues = await page.evaluate(() => {
      const issues = [];
      
      // Images without alt text
      const imagesWithoutAlt = document.querySelectorAll('img:not([alt])');
      if (imagesWithoutAlt.length > 0) {
        issues.push({ type: 'Images missing alt text', count: imagesWithoutAlt.length });
      }

      // Buttons without accessible text
      const buttonsWithoutText = document.querySelectorAll('button:empty:not([aria-label])');
      if (buttonsWithoutText.length > 0) {
        issues.push({ type: 'Buttons without accessible text', count: buttonsWithoutText.length });
      }

      // Form inputs without labels
      const inputsWithoutLabels = document.querySelectorAll('input:not([aria-label]):not([id])');
      if (inputsWithoutLabels.length > 0) {
        issues.push({ type: 'Form inputs without labels', count: inputsWithoutLabels.length });
      }

      return issues;
    });

    if (accessibilityIssues.length > 0) {
      issues.push({
        type: 'info',
        category: 'Accessibility',
        title: 'Accessibility improvements needed',
        description: accessibilityIssues.map(i => `• ${i.count} ${i.type}`).join('\n'),
        suggestion: `**Accessibility fixes (also helps SEO!):**

**Images without alt:**
\`\`\`html
<img src="hero.jpg" alt="Team collaborating on project">
\`\`\`

**Buttons without text:**
\`\`\`html
<button aria-label="Close menu">×</button>
\`\`\`

**Form inputs without labels:**
\`\`\`html
<label for="email">Email</label>
<input id="email" type="email">
\`\`\`

These help screen readers AND improve your Google ranking.`
      });
    }

    // Check HTTPS
    if (!url.startsWith('https://')) {
      issues.push({
        type: 'warning',
        category: 'Security',
        title: 'Not using HTTPS',
        description: 'Site is not using secure HTTPS connection. Google penalizes non-HTTPS sites in search results, and browsers show "Not Secure" warnings.',
        suggestion: `**Enable HTTPS (it's free!):**

**Netlify/Vercel/Railway:** HTTPS is automatic ✓

**Custom server:**
1. Get free SSL from Let's Encrypt
2. Use Cloudflare (free) as a proxy for instant HTTPS

**Force HTTPS redirect:**
\`\`\`javascript
if (location.protocol !== 'https:') {
  location.replace('https:' + location.href.substring(location.protocol.length));
}
\`\`\``
      });
    }

    // ============================================
    // SECURITY SCANNING — Light Pentest Checks
    // The CORE value of VibeQA — security-first analysis
    // ============================================

    // 1. Comprehensive Security Headers Check
    const secHeaders = response?.headers() || {};
    const missingCriticalHeaders = [];

    if (!secHeaders['strict-transport-security']) {
      missingCriticalHeaders.push({
        header: 'Strict-Transport-Security (HSTS)',
        risk: 'Browsers can be tricked into loading HTTP version, enabling man-in-the-middle attacks',
        fix: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
      });
    }
    if (!secHeaders['content-security-policy']) {
      missingCriticalHeaders.push({
        header: 'Content-Security-Policy (CSP)',
        risk: 'No protection against XSS attacks — malicious scripts can run freely',
        fix: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`
      });
    }
    if (!secHeaders['x-xss-protection']) {
      missingCriticalHeaders.push({
        header: 'X-XSS-Protection',
        risk: 'Legacy browsers have no XSS filtering enabled',
        fix: `X-XSS-Protection: 1; mode=block`
      });
    }
    if (!secHeaders['referrer-policy']) {
      missingCriticalHeaders.push({
        header: 'Referrer-Policy',
        risk: 'Full URLs (including query params with tokens/IDs) are leaked to external sites',
        fix: `Referrer-Policy: strict-origin-when-cross-origin`
      });
    }
    if (!secHeaders['permissions-policy'] && !secHeaders['feature-policy']) {
      missingCriticalHeaders.push({
        header: 'Permissions-Policy',
        risk: 'Third-party scripts can access camera, microphone, geolocation without restriction',
        fix: `Permissions-Policy: camera=(), microphone=(), geolocation=()`
      });
    }

    if (missingCriticalHeaders.length > 0) {
      const severity = missingCriticalHeaders.length >= 3 ? 'critical' : 'warning';
      issues.push({
        type: severity,
        category: 'Security',
        title: `${missingCriticalHeaders.length} critical security headers missing`,
        description: `Missing headers expose your site to attacks:\n${missingCriticalHeaders.map(h => `• **${h.header}** — ${h.risk}`).join('\n')}`,
        suggestion: `**Add these headers to your server configuration:**\n\n${missingCriticalHeaders.map(h => `\`${h.fix}\``).join('\n\n')}\n\n**Express.js (add all at once):**\n\`\`\`javascript\nconst helmet = require('helmet');\napp.use(helmet());\n\`\`\`\n\n**Netlify (netlify.toml):**\n\`\`\`toml\n[[headers]]\n  for = "/*"\n  [headers.values]\n${missingCriticalHeaders.map(h => `    ${h.fix.split(':')[0]} = "${h.fix.split(': ').slice(1).join(': ')}"`).join('\n')}\n\`\`\``
      });
    }

    // 2. Server Information Disclosure
    const serverHeader = secHeaders['server'] || '';
    const poweredBy = secHeaders['x-powered-by'] || '';
    if (serverHeader || poweredBy) {
      const disclosed = [];
      if (serverHeader) disclosed.push(`Server: ${serverHeader}`);
      if (poweredBy) disclosed.push(`X-Powered-By: ${poweredBy}`);
      issues.push({
        type: 'warning',
        category: 'Security',
        title: 'Server technology exposed in headers',
        description: `Your server reveals its technology stack: ${disclosed.join(', ')}. Attackers use this to find known vulnerabilities for your specific server version.`,
        suggestion: `**Remove identifying headers:**\n\n**Express.js:**\n\`\`\`javascript\napp.disable('x-powered-by');\n\`\`\`\n\n**Nginx:**\n\`\`\`nginx\nserver_tokens off;\n\`\`\`\n\n**Apache:**\n\`\`\`apache\nServerTokens Prod\nServerSignature Off\n\`\`\``
      });
    }

    // 3. Cookie Security Analysis
    const setCookieHeaders = response?.headers()?.['set-cookie'] || '';
    if (setCookieHeaders) {
      const cookieIssues = [];
      const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
      cookies.forEach(cookie => {
        const name = cookie.split('=')[0].trim();
        if (!cookie.toLowerCase().includes('httponly')) cookieIssues.push(`${name}: missing HttpOnly flag (accessible to JavaScript/XSS)`);
        if (!cookie.toLowerCase().includes('secure')) cookieIssues.push(`${name}: missing Secure flag (sent over HTTP)`);
        if (!cookie.toLowerCase().includes('samesite')) cookieIssues.push(`${name}: missing SameSite flag (CSRF vulnerable)`);
      });
      if (cookieIssues.length > 0) {
        issues.push({
          type: 'critical',
          category: 'Security',
          title: 'Insecure cookie configuration',
          description: `Cookie security flags missing:\n${cookieIssues.map(c => `• ${c}`).join('\n')}`,
          suggestion: `**Set secure cookie flags:**\n\`\`\`javascript\nres.cookie('session', token, {\n  httpOnly: true,  // Prevents XSS access\n  secure: true,    // HTTPS only\n  sameSite: 'Lax', // CSRF protection\n  maxAge: 86400000 // 24 hours\n});\n\`\`\``
        });
      }
    }

    // 4. Mixed Content Detection (in-page check)
    const mixedContentIssues = await page.evaluate(() => {
      const mixed = [];
      // Check for HTTP resources on HTTPS pages
      if (location.protocol === 'https:') {
        document.querySelectorAll('script[src^="http://"], link[href^="http://"], img[src^="http://"], iframe[src^="http://"]').forEach(el => {
          mixed.push({ tag: el.tagName, src: el.src || el.href });
        });
      }
      return mixed.slice(0, 10);
    });

    if (mixedContentIssues.length > 0) {
      issues.push({
        type: 'critical',
        category: 'Security',
        title: `${mixedContentIssues.length} mixed content resource(s) detected`,
        description: `HTTPS page loads resources over insecure HTTP — browsers may block these and show security warnings:\n${mixedContentIssues.map(m => `• <${m.tag}> ${m.src}`).join('\n')}`,
        suggestion: `**Update all resource URLs to use HTTPS:**\n\`\`\`html\n<!-- Change this: -->\n<script src="http://cdn.example.com/lib.js"></script>\n<!-- To this: -->\n<script src="https://cdn.example.com/lib.js"></script>\n\`\`\`\nOr use protocol-relative URLs: \`//cdn.example.com/lib.js\``
      });
    }

    // 5. Exposed Sensitive Data in Page Source
    const exposedData = await page.evaluate(() => {
      const html = document.documentElement.outerHTML;
      const findings = [];

      // Check for exposed API keys / tokens (common patterns)
      const apiKeyPatterns = [
        { pattern: /(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]/gi, label: 'API key' },
        { pattern: /(?:sk|pk)_(test|live)_[a-zA-Z0-9]{20,}/g, label: 'Stripe key' },
        { pattern: /AIza[a-zA-Z0-9_\-]{35}/g, label: 'Google API key' },
        { pattern: /(?:aws_access_key_id|aws_secret)\s*[:=]\s*['"][A-Z0-9]{16,}['"]/gi, label: 'AWS credential' },
        { pattern: /ghp_[a-zA-Z0-9]{36}/g, label: 'GitHub token' },
      ];

      apiKeyPatterns.forEach(({ pattern, label }) => {
        const matches = html.match(pattern);
        if (matches) findings.push(`${label} found (${matches.length} instance${matches.length > 1 ? 's' : ''})`);
      });

      // Check for exposed email addresses in source
      const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      const emails = [...new Set(html.match(emailPattern) || [])];
      if (emails.length > 3) findings.push(`${emails.length} email addresses exposed in page source (spam target)`);

      // Check for HTML comments containing sensitive info
      const comments = html.match(/<!--[\s\S]*?-->/g) || [];
      const sensitiveComments = comments.filter(c => /(?:password|secret|todo|fixme|hack|debug|token|key)/i.test(c));
      if (sensitiveComments.length > 0) findings.push(`${sensitiveComments.length} HTML comment(s) with potentially sensitive content`);

      return findings;
    });

    if (exposedData.length > 0) {
      issues.push({
        type: 'critical',
        category: 'Security',
        title: 'Sensitive data exposed in page source',
        description: `Found potential data leaks in your page HTML:\n${exposedData.map(d => `• ${d}`).join('\n')}`,
        suggestion: `**Never embed secrets in frontend code.** Use environment variables and server-side API calls instead.\n\n**Remove HTML comments in production:**\n\`\`\`javascript\n// In your build process:\nhtml.replace(/<!--[\\s\\S]*?-->/g, '')\n\`\`\`\n\n**Use .env for API keys:**\n\`\`\`bash\n# .env (never commit this)\nSTRIPE_KEY=sk_live_...\n\`\`\``
      });
    }

    // 6. Form Security Analysis
    const formSecurityIssues = await page.evaluate(() => {
      const findings = [];
      const forms = document.querySelectorAll('form');

      forms.forEach((form, i) => {
        // Check for missing CSRF tokens
        const hasCSRF = form.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"]');
        if (!hasCSRF && form.method?.toLowerCase() === 'post') {
          findings.push(`Form ${i + 1}: No CSRF token on POST form`);
        }

        // Check for password fields with autocomplete
        const passwordFields = form.querySelectorAll('input[type="password"]');
        passwordFields.forEach(pw => {
          if (pw.autocomplete !== 'off' && pw.autocomplete !== 'new-password' && pw.autocomplete !== 'current-password') {
            findings.push(`Form ${i + 1}: Password field should set autocomplete attribute`);
          }
        });

        // Check for forms submitting to HTTP
        if (form.action && form.action.startsWith('http://')) {
          findings.push(`Form ${i + 1}: Submits data over insecure HTTP`);
        }
      });

      return findings;
    });

    if (formSecurityIssues.length > 0) {
      issues.push({
        type: 'warning',
        category: 'Security',
        title: 'Form security issues detected',
        description: `Found potential form vulnerabilities:\n${formSecurityIssues.map(f => `• ${f}`).join('\n')}`,
        suggestion: `**Add CSRF protection:**\n\`\`\`javascript\n// Express + csurf middleware\nconst csrf = require('csurf');\napp.use(csrf({ cookie: true }));\n\`\`\`\n\n**Set autocomplete on password fields:**\n\`\`\`html\n<input type="password" autocomplete="current-password">\n\`\`\``
      });
    }

    // 7. Open Redirect Detection
    const openRedirectRisk = await page.evaluate(() => {
      const params = new URLSearchParams(window.location.search);
      const suspiciousParams = ['redirect', 'url', 'next', 'return', 'returnTo', 'goto', 'redirect_uri', 'callback'];
      const found = [];
      suspiciousParams.forEach(p => {
        if (params.has(p)) found.push(p);
      });
      // Also check links with redirect params
      const linksWithRedirects = document.querySelectorAll('a[href*="redirect="], a[href*="url="], a[href*="next="]');
      return { params: found, links: linksWithRedirects.length };
    });

    if (openRedirectRisk.params.length > 0 || openRedirectRisk.links > 0) {
      issues.push({
        type: 'warning',
        category: 'Security',
        title: 'Potential open redirect vectors',
        description: `Found URL redirect parameters that could be exploited for phishing${openRedirectRisk.params.length > 0 ? `: ${openRedirectRisk.params.join(', ')}` : ''}. ${openRedirectRisk.links > 0 ? `Plus ${openRedirectRisk.links} link(s) with redirect parameters.` : ''}`,
        suggestion: `**Validate redirect URLs server-side:**\n\`\`\`javascript\nfunction safeRedirect(url) {\n  const allowed = ['yourdomain.com'];\n  try {\n    const parsed = new URL(url);\n    return allowed.includes(parsed.hostname) ? url : '/';\n  } catch { return '/'; }\n}\n\`\`\``
      });
    }

    // 8. JavaScript Library Vulnerability Check (basic)
    const jsLibraries = await page.evaluate(() => {
      const libs = [];
      if (window.jQuery) libs.push({ name: 'jQuery', version: window.jQuery.fn?.jquery || 'unknown' });
      if (window.angular) libs.push({ name: 'AngularJS', version: window.angular.version?.full || 'unknown' });
      if (window.React) libs.push({ name: 'React', version: window.React.version || 'unknown' });
      if (window.Vue) libs.push({ name: 'Vue', version: window.Vue.version || 'unknown' });
      if (window.Lodash || window._?.VERSION) libs.push({ name: 'Lodash', version: window._?.VERSION || 'unknown' });
      if (window.Bootstrap) libs.push({ name: 'Bootstrap', version: 'detected' });
      return libs;
    });

    const outdatedLibs = jsLibraries.filter(lib => {
      if (lib.name === 'jQuery' && lib.version !== 'unknown') {
        const major = parseInt(lib.version.split('.')[0]);
        return major < 3;
      }
      if (lib.name === 'AngularJS') return true; // AngularJS is EOL
      return false;
    });

    if (outdatedLibs.length > 0) {
      issues.push({
        type: 'warning',
        category: 'Security',
        title: 'Outdated JavaScript libraries detected',
        description: `Found potentially vulnerable libraries:\n${outdatedLibs.map(l => `• ${l.name} v${l.version}`).join('\n')}\n\nOutdated libraries often have known security vulnerabilities.`,
        suggestion: `**Update to latest versions:**\n- jQuery < 3.x has known XSS vulnerabilities → Update to 3.7+\n- AngularJS is end-of-life → Migrate to Angular 17+ or another framework\n\n**Use npm audit:**\n\`\`\`bash\nnpm audit\nnpm audit fix\n\`\`\``
      });
    }

    // ============================================
    // CLAUDE AI ANALYSIS (Pro/Team/Enterprise)
    // The core value engine — this is what makes VibeQA worth paying for
    // ============================================
    let vibeScore = null;
    let aiInsights = null;

    if (anthropic && (plan === 'pro' || plan === 'team' || plan === 'enterprise')) {
      try {
        // Collect rich page context for Claude
        const pageContext = await page.evaluate(() => {
          const getText = (sel) => document.querySelector(sel)?.textContent?.trim() || '';
          const getMeta = (name) => document.querySelector(`meta[name="${name}"], meta[property="${name}"]`)?.content || '';

          // Get visible text content (first 3000 chars for context)
          const bodyText = document.body?.innerText?.substring(0, 3000) || '';

          // Navigation structure
          const navLinks = [...document.querySelectorAll('nav a, header a, [role="navigation"] a')]
            .slice(0, 20)
            .map(a => ({ text: a.textContent?.trim(), href: a.href }));

          // CTAs and buttons
          const ctas = [...document.querySelectorAll('button, a.btn, a.button, [class*="cta"], [class*="btn-primary"], input[type="submit"]')]
            .slice(0, 10)
            .map(el => ({ text: el.textContent?.trim(), tag: el.tagName, visible: el.offsetParent !== null }));

          // Forms
          const forms = [...document.querySelectorAll('form')]
            .map(f => ({ action: f.action, fields: f.querySelectorAll('input, select, textarea').length }));

          // Heading hierarchy
          const headings = [...document.querySelectorAll('h1, h2, h3')]
            .slice(0, 15)
            .map(h => ({ level: h.tagName, text: h.textContent?.trim().substring(0, 80) }));

          // Social proof elements
          const hasSocialProof = !!(
            document.querySelector('[class*="testimonial"], [class*="review"], [class*="social-proof"], [class*="trust"]') ||
            bodyText.match(/customers|trusted by|rated|reviews|testimonial/i)
          );

          // Pricing elements
          const hasPricing = !!(
            document.querySelector('[class*="pricing"], [class*="plan"], [class*="price"]') ||
            bodyText.match(/\$\d+|pricing|per month|\/mo|free trial/i)
          );

          return {
            title: getText('title'),
            metaDescription: getMeta('description'),
            ogTitle: getMeta('og:title'),
            ogDescription: getMeta('og:description'),
            bodyTextPreview: bodyText.substring(0, 2000),
            navLinks,
            ctas,
            forms,
            headings,
            hasSocialProof,
            hasPricing,
            colorScheme: getComputedStyle(document.body).backgroundColor,
            fontFamily: getComputedStyle(document.body).fontFamily,
            totalImages: document.querySelectorAll('img').length,
            totalLinks: document.querySelectorAll('a').length,
            totalScripts: document.querySelectorAll('script').length,
            hasAnalytics: !!(
              document.querySelector('script[src*="google-analytics"], script[src*="gtag"], script[src*="gtm"]') ||
              window.ga || window.gtag || window.dataLayer
            ),
          };
        });

        // Choose model tier based on plan
        const model = (plan === 'team' || plan === 'enterprise')
          ? 'claude-sonnet-4-5-20250929'   // Premium: deeper analysis
          : 'claude-haiku-4-5-20251001';    // Pro: fast, cost-efficient

        const aiResult = await analyzeWithClaude(
          model, url, desktopScreenshot, mobileScreenshot,
          pageContext, issues, seoData, loadTime,
          consoleErrors, failedRequests, brokenLinks, plan
        );

        if (aiResult) {
          if (aiResult.issues?.length > 0) {
            issues.push(...aiResult.issues);
          }
          vibeScore = aiResult.vibeScore || null;
          aiInsights = aiResult.insights || null;
        }
      } catch (err) {
        console.log(`[${scanId}] AI analysis error (non-blocking):`, err.message);
      }
    }

    console.log(`[${scanId}] Scan complete. Found ${issues.length} issues.${vibeScore ? ` Vibe Score: ${vibeScore.overall}/100` : ''}`);

    const scanResult = {
      status: 'complete',
      url,
      issues,
      screenshots,
      vibeScore,
      aiInsights,
      summary: {
        critical: issues.filter(i => i.type === 'critical').length,
        warnings: issues.filter(i => i.type === 'warning').length,
        info: issues.filter(i => i.type === 'info').length,
        loadTime: `${(loadTime / 1000).toFixed(1)}s`,
        vibeScore: vibeScore?.overall || null
      },
      completedAt: new Date().toISOString()
    };
    
    // Update in-memory cache
    activeScans.set(scanId, scanResult);
    
    // Persist to database
    if (db.isConfigured && userId) {
      try {
        await db.updateScan(scanId, {
          status: 'complete',
          issues: issues,
          screenshots: screenshots,
          summary: scanResult.summary,
          completed_at: scanResult.completedAt
        });
        
        // Clear from active cache after persisting (keep for 5 min for immediate polling)
        setTimeout(() => activeScans.delete(scanId), 5 * 60 * 1000);
      } catch (err) {
        console.error('Failed to persist scan to DB:', err);
      }
      
      // Trigger webhooks for authenticated users
      triggerWebhooks(userId, 'scan.complete', { scanId, url, summary: scanResult.summary, issues })
        .catch(err => console.error('Webhook trigger error:', err));
      
      // Send Slack notification if configured
      sendSlackNotification(userId, scanId, url, scanResult.summary, issues)
        .catch(err => console.error('Slack notification error:', err));
    }

  } finally {
    if (browser) await browser.close();
  }
}

// Trigger webhooks for a user event
async function triggerWebhooks(userId, event, payload) {
  if (!userId) return;
  
  try {
    const webhooks = await db.getActiveWebhooksForEvent(userId, event);
    
    for (const webhook of webhooks) {
      try {
        const response = await fetch(webhook.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-VibeQA-Event': event,
            'X-VibeQA-Signature': webhook.secret ? 
              require('crypto').createHmac('sha256', webhook.secret).update(JSON.stringify(payload)).digest('hex') : ''
          },
          body: JSON.stringify({
            event,
            timestamp: new Date().toISOString(),
            data: payload
          })
        });
        
        if (!response.ok) {
          console.log(`Webhook ${webhook.id} returned ${response.status}`);
          // Increment failure count
          await db.updateWebhook(webhook.id, userId, { 
            failure_count: webhook.failure_count + 1,
            last_triggered_at: new Date().toISOString()
          });
        } else {
          await db.updateWebhook(webhook.id, userId, { 
            failure_count: 0,
            last_triggered_at: new Date().toISOString()
          });
        }
      } catch (err) {
        console.error(`Webhook ${webhook.id} failed:`, err.message);
      }
    }
  } catch (err) {
    console.error('Error fetching webhooks:', err);
  }
}

// Send Slack notification
async function sendSlackNotification(userId, scanId, url, summary, issues) {
  if (!userId) return;
  
  try {
    const integrations = await db.getUserIntegrations(userId);
    const slack = integrations?.slack;
    
    if (!slack?.webhookUrl) return;
    
    const criticalCount = summary.critical || 0;
    const warningCount = summary.warnings || 0;
    const infoCount = summary.info || 0;
    
    const emoji = criticalCount > 0 ? '🚨' : warningCount > 0 ? '⚠️' : '✅';
    const status = criticalCount > 0 ? 'Critical issues found!' : 
                   warningCount > 0 ? 'Some issues found' : 
                   'All clear!';
    
    const message = {
      text: `${emoji} VibeQA Scan Complete: ${url}`,
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: `${emoji} Scan Complete` }
        },
        {
          type: 'section',
          text: { 
            type: 'mrkdwn', 
            text: `*URL:* <${url}|${url}>\n*Status:* ${status}\n*Load Time:* ${summary.loadTime}` 
          }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*🔴 Critical:* ${criticalCount}` },
            { type: 'mrkdwn', text: `*🟡 Warnings:* ${warningCount}` },
            { type: 'mrkdwn', text: `*🔵 Info:* ${infoCount}` }
          ]
        }
      ]
    };
    
    if (criticalCount > 0) {
      const topIssues = issues.filter(i => i.type === 'critical').slice(0, 3);
      message.blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: '*Top Issues:*\n' + topIssues.map(i => `• ${i.title}`).join('\n')
        }
      });
    }
    
    await fetch(slack.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message)
    });
    
    console.log(`[${scanId}] Slack notification sent`);
  } catch (err) {
    console.error('Slack notification error:', err);
  }
}

// ============================================
// CLAUDE AI ANALYSIS ENGINE
// This is what makes VibeQA worth paying for.
// Not just "is the title tag missing" — Claude tells you
// WHY your page isn't converting and WHAT to do about it.
// ============================================

async function analyzeWithClaude(model, url, desktopScreenshot, mobileScreenshot, pageContext, existingIssues, seoData, loadTime, consoleErrors, failedRequests, brokenLinks, plan) {
  const isPremium = (plan === 'team' || plan === 'enterprise');

  const systemPrompt = `You are VibeQA, an expert website security analyst and quality auditor combining the skills of a penetration tester, application security engineer, senior UX designer, conversion rate optimizer, and SEO specialist.

You perform a LIGHT PENTEST and holistic quality analysis — security is your PRIMARY focus, followed by UX and conversion. Your analysis should be the kind of insight a $300/hr security consultant would give.

SECURITY ANALYSIS PRIORITIES (check these FIRST):
1. **Attack Surface** — Visible entry points: forms, login pages, API endpoints exposed in JS, URL parameters
2. **Data Exposure** — API keys, tokens, credentials, emails, internal paths leaked in source/comments/JS
3. **Injection Vectors** — Forms without CSRF, unescaped user input, inline event handlers, eval() usage
4. **Authentication Weaknesses** — Weak password policies, missing rate limiting signs, session management
5. **Transport Security** — HTTPS enforcement, mixed content, insecure form actions
6. **Client-side Security** — Inline scripts, third-party script risks, postMessage usage, localStorage of sensitive data
7. **Information Disclosure** — Server headers, error pages, stack traces, debug modes, source maps
8. **Dependency Risks** — Outdated libraries with known CVEs visible in page source

IMPORTANT RULES:
- Only report issues NOT already covered in the existing findings
- Every issue must have a specific, copy-paste-ready fix (code snippet or step-by-step action)
- ALWAYS lead with security findings — they are the most valuable
- Prioritize by risk: critical security > warnings > UX/conversion improvements
- Be direct and specific — "Your login form has no CSRF protection" not "Consider improving form security"
- Reference exact elements you see in the screenshots

Return a JSON object with this exact structure:
{
  "vibeScore": {
    "overall": <0-100>,
    "security": <0-100>,
    "design": <0-100>,
    "ux": <0-100>,
    "conversion": <0-100>,
    "content": <0-100>,
    "trust": <0-100>,
    "technical": <0-100>,
    "mobile": <0-100>,
    "seo": <0-100>
  },
  "insights": {
    "headline": "<One-line security verdict, e.g. 'Multiple XSS vectors and missing CSP — this site is vulnerable to injection attacks'>",
    "strengths": ["<What's working well — max 3>"],
    "quickWins": ["<High-impact security and UX fixes — max 3>"],
    "topPriority": "<The single most critical security or UX issue to fix>"
  },
  "issues": [
    {
      "type": "critical|warning|info",
      "category": "Security|Vulnerability|Data Exposure|Conversion|UX|Design|Content|Trust|Mobile|Code Quality",
      "title": "<Clear, specific issue title>",
      "description": "<What's wrong AND the security/business risk>",
      "suggestion": "<Specific fix with code example>"
    }
  ]
}

${isPremium ? `PREMIUM SECURITY ANALYSIS — go deeper:
- Deep scan: Look for hidden API endpoints in JavaScript bundles
- Analyze authentication flow security (if login page visible)
- Check for client-side data validation bypass opportunities
- Evaluate third-party script trust chain
- Analyze the page copy: Is the value proposition clear in the first 5 seconds?
- Conversion funnel gaps: What stops a visitor from becoming a customer?
- Content strategy: Is the messaging hierarchy effective?
- Provide up to 10 issues max (at least 5 security-focused).` : `STANDARD SECURITY + UX ANALYSIS:
- Focus on the most critical security issues and highest-impact UX problems
- At least 3 issues should be security-focused
- Provide up to 6 issues max.`}`;

  const contextSummary = `
WEBSITE: ${url}
LOAD TIME: ${loadTime}ms
PAGE TITLE: ${pageContext.title || 'MISSING'}
META DESCRIPTION: ${pageContext.metaDescription || 'MISSING'}

NAVIGATION: ${pageContext.navLinks?.map(l => l.text).filter(Boolean).join(' | ') || 'None detected'}

HEADING STRUCTURE:
${pageContext.headings?.map(h => `${h.level}: ${h.text}`).join('\n') || 'No headings found'}

CTAs/BUTTONS: ${pageContext.ctas?.map(c => c.text).filter(Boolean).join(', ') || 'None detected'}
FORMS: ${pageContext.forms?.length || 0} form(s) on page
IMAGES: ${pageContext.totalImages || 0} total
SCRIPTS: ${pageContext.totalScripts || 0} total

SOCIAL PROOF: ${pageContext.hasSocialProof ? 'Present' : 'NOT FOUND — this hurts conversion'}
PRICING VISIBLE: ${pageContext.hasPricing ? 'Yes' : 'No'}
ANALYTICS: ${pageContext.hasAnalytics ? 'Installed' : 'NOT INSTALLED — no way to track conversions'}

BODY TEXT PREVIEW:
${pageContext.bodyTextPreview?.substring(0, 1500) || 'Could not extract text'}

EXISTING ISSUES ALREADY FOUND (do NOT duplicate these):
${existingIssues.map(i => `- [${i.type}] ${i.title}`).join('\n')}

CONSOLE ERRORS: ${consoleErrors.length > 0 ? consoleErrors.slice(0, 3).join('; ') : 'None'}
BROKEN LINKS: ${brokenLinks.length}
FAILED RESOURCES: ${failedRequests.length}
`;

  // Build message content with screenshots
  const content = [
    { type: 'text', text: contextSummary },
    {
      type: 'image',
      source: { type: 'base64', media_type: 'image/png', data: desktopScreenshot }
    }
  ];

  // Include mobile screenshot for premium analysis
  if (isPremium && mobileScreenshot) {
    content.push(
      { type: 'text', text: '\nMOBILE VIEW (375px width):' },
      {
        type: 'image',
        source: { type: 'base64', media_type: 'image/png', data: mobileScreenshot }
      }
    );
  }

  content.push({
    type: 'text',
    text: `\nAnalyze this website. Return ONLY valid JSON matching the schema above. No markdown, no explanation — just the JSON object.`
  });

  const response = await anthropic.messages.create({
    model,
    max_tokens: isPremium ? 2000 : 1200,
    system: systemPrompt,
    messages: [{ role: 'user', content }]
  });

  try {
    const text = response.content[0].text;
    // Extract JSON from response (handle potential markdown wrapping)
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);

      // Validate vibeScore
      if (parsed.vibeScore && typeof parsed.vibeScore.overall === 'number') {
        parsed.vibeScore.overall = Math.max(0, Math.min(100, parsed.vibeScore.overall));
      }

      // Tag AI-generated issues so frontend can style them differently
      if (parsed.issues) {
        parsed.issues = parsed.issues.map(issue => ({
          ...issue,
          source: 'ai',
          aiModel: model.includes('sonnet') ? 'premium' : 'standard'
        }));
      }

      return parsed;
    }
  } catch (err) {
    console.error('Failed to parse Claude response:', err.message);
  }
  return null;
}

// ============================================
// WEBHOOK MANAGEMENT ENDPOINTS
// ============================================

const { requireAuth } = require('./src/middleware/auth');
const PLAN_LIMITS = require('./src/models/user').PLAN_LIMITS;

// Get user's webhooks
app.get('/api/webhooks', requireAuth, async (req, res) => {
  try {
    // Check plan allows webhooks
    const limits = PLAN_LIMITS[req.user.plan] || PLAN_LIMITS.free;
    if (limits.webhooks === 0) {
      return res.status(403).json({ 
        error: 'Webhooks require Pro or higher',
        upgrade: true,
        suggestedPlan: 'pro'
      });
    }
    
    const webhooks = await db.getWebhooksByUserId(req.user.id);
    res.json(webhooks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create webhook
app.post('/api/webhooks', requireAuth, async (req, res) => {
  try {
    const limits = PLAN_LIMITS[req.user.plan] || PLAN_LIMITS.free;
    if (limits.webhooks === 0) {
      return res.status(403).json({ 
        error: 'Webhooks require Pro or higher',
        upgrade: true 
      });
    }
    
    // Check webhook limit
    const existing = await db.getWebhooksByUserId(req.user.id);
    if (existing.length >= limits.webhooks && limits.webhooks !== Infinity) {
      return res.status(403).json({ 
        error: `Webhook limit reached (${limits.webhooks}). Upgrade for more.`,
        upgrade: true
      });
    }
    
    const { url, events } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
    // Validate URL
    try {
      new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid webhook URL' });
    }
    
    const webhook = await db.createWebhook(req.user.id, { 
      url, 
      events: events || ['scan.complete'] 
    });
    
    res.json(webhook);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update webhook
app.put('/api/webhooks/:id', requireAuth, async (req, res) => {
  try {
    const { url, events, is_active } = req.body;
    const updates = {};
    if (url !== undefined) updates.url = url;
    if (events !== undefined) updates.events = events;
    if (is_active !== undefined) updates.is_active = is_active;
    
    const webhook = await db.updateWebhook(req.params.id, req.user.id, updates);
    if (!webhook) {
      return res.status(404).json({ error: 'Webhook not found' });
    }
    res.json(webhook);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete webhook
app.delete('/api/webhooks/:id', requireAuth, async (req, res) => {
  try {
    await db.deleteWebhook(req.params.id, req.user.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Test webhook
app.post('/api/webhooks/:id/test', requireAuth, async (req, res) => {
  try {
    const webhooks = await db.getWebhooksByUserId(req.user.id);
    const webhook = webhooks.find(w => w.id === req.params.id);
    
    if (!webhook) {
      return res.status(404).json({ error: 'Webhook not found' });
    }
    
    const testPayload = {
      event: 'test',
      timestamp: new Date().toISOString(),
      data: {
        scanId: 'test-123',
        url: 'https://example.com',
        summary: { critical: 0, warnings: 1, info: 2, loadTime: '1.5s' }
      }
    };
    
    const response = await fetch(webhook.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-VibeQA-Event': 'test',
        'X-VibeQA-Signature': require('crypto').createHmac('sha256', webhook.secret || '')
          .update(JSON.stringify(testPayload)).digest('hex')
      },
      body: JSON.stringify(testPayload)
    });
    
    res.json({ 
      success: response.ok, 
      status: response.status,
      message: response.ok ? 'Test webhook sent successfully' : 'Webhook returned error'
    });
  } catch (err) {
    res.status(500).json({ error: err.message, success: false });
  }
});

// ============================================
// SCHEDULED SCANS ENDPOINTS
// ============================================

// Get user's scheduled scans
app.get('/api/schedules', requireAuth, async (req, res) => {
  try {
    // Scheduled scans require Pro or higher
    if (req.user.plan === 'free') {
      return res.status(403).json({ 
        error: 'Scheduled scans require Pro or higher',
        upgrade: true,
        suggestedPlan: 'pro'
      });
    }
    
    const schedules = await db.getScheduledScansByUserId(req.user.id);
    res.json(schedules);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create scheduled scan
app.post('/api/schedules', requireAuth, async (req, res) => {
  try {
    if (req.user.plan === 'free') {
      return res.status(403).json({ 
        error: 'Scheduled scans require Pro or higher',
        upgrade: true 
      });
    }
    
    const { url, schedule, timezone, projectId } = req.body;
    
    if (!url || !schedule) {
      return res.status(400).json({ error: 'URL and schedule are required' });
    }
    
    if (!['daily', 'weekly'].includes(schedule)) {
      return res.status(400).json({ error: 'Schedule must be daily or weekly' });
    }
    
    // Validate URL
    try {
      new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format' });
    }
    
    // Pro: 3 scheduled scans, Team: 10, Enterprise: unlimited
    const limits = { free: 0, pro: 3, team: 10, enterprise: Infinity };
    const limit = limits[req.user.plan] || 0;
    
    const existing = await db.getScheduledScansByUserId(req.user.id);
    if (existing.length >= limit && limit !== Infinity) {
      return res.status(403).json({ 
        error: `Scheduled scan limit reached (${limit}). Upgrade for more.`,
        upgrade: true
      });
    }
    
    const scheduled = await db.createScheduledScan(req.user.id, {
      url,
      schedule,
      timezone: timezone || 'UTC',
      projectId
    });
    
    res.json(scheduled);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update scheduled scan
app.put('/api/schedules/:id', requireAuth, async (req, res) => {
  try {
    const { url, schedule, timezone, is_active } = req.body;
    const updates = {};
    if (url !== undefined) updates.url = url;
    if (schedule !== undefined) {
      if (!['daily', 'weekly'].includes(schedule)) {
        return res.status(400).json({ error: 'Schedule must be daily or weekly' });
      }
      updates.schedule = schedule;
      updates.next_run_at = db.calculateNextRun(schedule, timezone || 'UTC');
    }
    if (timezone !== undefined) updates.timezone = timezone;
    if (is_active !== undefined) updates.is_active = is_active;
    
    const scheduled = await db.updateScheduledScan(req.params.id, req.user.id, updates);
    if (!scheduled) {
      return res.status(404).json({ error: 'Scheduled scan not found' });
    }
    res.json(scheduled);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete scheduled scan
app.delete('/api/schedules/:id', requireAuth, async (req, res) => {
  try {
    await db.deleteScheduledScan(req.params.id, req.user.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================
// SCHEDULED SCAN RUNNER (called by cron/Railway cron job)
// ============================================

app.post('/api/cron/run-scheduled-scans', async (req, res) => {
  // Verify cron secret
  const cronSecret = req.headers['x-cron-secret'] || req.query.secret;
  if (cronSecret !== process.env.CRON_SECRET && cronSecret !== 'vibeqa-cron-2026') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const dueScans = await db.getDueScheduledScans();
    console.log(`[CRON] Found ${dueScans.length} scheduled scans to run`);
    
    const results = [];
    
    for (const scheduled of dueScans) {
      try {
        // Create scan record
        const scan = await db.createScan({
          userId: scheduled.user_id,
          projectId: scheduled.project_id,
          url: scheduled.url
        });
        
        // Start scan in background
        runScan(scan.id, scheduled.url, scheduled.users?.plan || 'pro', scheduled.user_id)
          .catch(err => console.error(`Scheduled scan ${scan.id} failed:`, err));
        
        // Update scheduled scan
        await db.updateScheduledScan(scheduled.id, scheduled.user_id, {
          last_run_at: new Date().toISOString(),
          last_scan_id: scan.id,
          next_run_at: db.calculateNextRun(scheduled.schedule, scheduled.timezone)
        });
        
        results.push({ scheduledId: scheduled.id, scanId: scan.id, url: scheduled.url });
      } catch (err) {
        console.error(`Failed to run scheduled scan ${scheduled.id}:`, err);
        results.push({ scheduledId: scheduled.id, error: err.message });
      }
    }
    
    res.json({ ran: results.length, results });
  } catch (err) {
    console.error('Cron job error:', err);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3847;
app.listen(PORT, () => {
  console.log(`VibeQA server running on http://localhost:${PORT}`);
  console.log(`Supabase: ${db.isConfigured ? 'connected' : 'in-memory mode'}`);
  console.log(`Stripe: ${process.env.STRIPE_SECRET_KEY ? 'configured' : 'demo mode'}`);
  console.log(`Claude AI: ${process.env.ANTHROPIC_API_KEY ? 'configured' : 'disabled'}`);
});
