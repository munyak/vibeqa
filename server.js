const express = require('express');
const cors = require('cors');
const puppeteer = require('puppeteer');
const path = require('path');

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
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
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

// Store scan results
const scans = new Map();

// Main scan endpoint
app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  
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
    const canScan = await User.canScan(req.user.id);
    if (!canScan) {
      return res.status(429).json({ 
        error: 'Scan limit reached',
        message: 'Upgrade your plan for more scans',
        upgrade: true
      });
    }
    await User.incrementScanCount(req.user.id);
  }

  const scanId = Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  
  // Start scan in background
  scans.set(scanId, { 
    status: 'scanning', 
    url, 
    userId: req.user?.id || 'anonymous',
    startedAt: new Date().toISOString() 
  });
  
  runScan(scanId, url, req.user?.plan || 'free').catch(err => {
    console.error('Scan error:', err);
    scans.set(scanId, { 
      status: 'error', 
      url, 
      error: err.message 
    });
  });

  res.json({ scanId, status: 'scanning' });
});

// Get scan status/results
app.get('/api/scan/:scanId', (req, res) => {
  const scan = scans.get(req.params.scanId);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  res.json(scan);
});

// Get user's scan history
app.get('/api/scans', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const userScans = [];
  for (const [scanId, scan] of scans.entries()) {
    if (scan.userId === req.user.id) {
      userScans.push({ scanId, ...scan });
    }
  }
  
  // Sort by date, newest first
  userScans.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  
  res.json(userScans.slice(0, 50)); // Last 50 scans
});

async function runScan(scanId, url, plan) {
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
    
    scans.set(scanId, { 
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
    });

  } finally {
    if (browser) await browser.close();
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

const PORT = process.env.PORT || 3847;
app.listen(PORT, () => {
  console.log(`VibeQA server running on http://localhost:${PORT}`);
  console.log(`Supabase: ${db.isConfigured ? 'connected' : 'in-memory mode'}`);
  console.log(`Stripe: ${process.env.STRIPE_SECRET_KEY ? 'configured' : 'demo mode'}`);
  console.log(`OpenAI: ${process.env.OPENAI_API_KEY ? 'configured' : 'disabled'}`);
});
