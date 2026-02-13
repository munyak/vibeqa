const express = require('express');
const cors = require('cors');
const puppeteer = require('puppeteer');
const path = require('path');
const crypto = require('crypto');

// Routes
const authRoutes = require('./src/routes/auth');
const billingRoutes = require('./src/routes/billing');
const { authMiddleware } = require('./src/middleware/auth');
const { User } = require('./src/models/user');
const db = require('./src/db/supabase');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));
app.use(authMiddleware);

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

// OpenAI for AI analysis (optional)
let openai = null;
if (process.env.OPENAI_API_KEY) {
  const { OpenAI } = require('openai');
  openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
}

// In-memory cache for active scans (cleared after completion)
// Completed scans are persisted to Supabase
const activeScans = new Map();

// Main scan endpoint
app.post('/api/scan', async (req, res) => {
  const { url, projectId } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  // Validate URL
  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // Check scan limits for authenticated users
  if (req.user) {
    const canScanNow = await db.canScan(req.user.id);
    if (!canScanNow) {
      return res.status(429).json({ 
        error: 'Scan limit reached',
        message: 'Upgrade your plan for more scans',
        upgrade: true
      });
    }
    // Usage is incremented in db.createScan, no need to call separately
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

    // Use AI to analyze screenshots for UX issues (Pro/Team plans only)
    if (openai && (plan === 'pro' || plan === 'team')) {
      try {
        const aiAnalysis = await analyzeWithAI(url, desktopScreenshot, issues);
        if (aiAnalysis && aiAnalysis.length > 0) {
          issues.push(...aiAnalysis);
        }
      } catch (err) {
        console.log('AI analysis skipped:', err.message);
      }
    }

    console.log(`[${scanId}] Scan complete. Found ${issues.length} issues.`);
    
    const scanResult = { 
      status: 'complete', 
      url, 
      issues,
      screenshots,
      summary: {
        critical: issues.filter(i => i.type === 'critical').length,
        warnings: issues.filter(i => i.type === 'warning').length,
        info: issues.filter(i => i.type === 'info').length,
        loadTime: `${(loadTime / 1000).toFixed(1)}s`
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

async function analyzeWithAI(url, screenshot, existingIssues) {
  const response = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      {
        role: 'system',
        content: `You are a UX expert reviewing a website screenshot. Identify 2-3 specific, actionable UX issues that aren't already covered. Focus on:
- Visual hierarchy problems
- Confusing navigation
- Poor call-to-action visibility
- Text readability issues
- Trust signals missing

Return JSON array: [{"type":"warning","category":"UX","title":"Issue","description":"Details","suggestion":"Fix"}]
Return empty array [] if no significant issues found.`
      },
      {
        role: 'user',
        content: [
          { type: 'text', text: `Website: ${url}\nAlready found: ${existingIssues.map(i => i.title).join(', ')}\n\nAnalyze this screenshot for additional UX issues:` },
          { type: 'image_url', image_url: { url: `data:image/png;base64,${screenshot}` } }
        ]
      }
    ],
    max_tokens: 500
  });

  try {
    const content = response.choices[0].message.content;
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
  } catch {
    return [];
  }
  return [];
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
  console.log(`OpenAI: ${process.env.OPENAI_API_KEY ? 'configured' : 'disabled'}`);
});
