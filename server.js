const express = require('express');
const cors = require('cors');
const puppeteer = require('puppeteer');
const { OpenAI } = require('openai');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

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

  const scanId = Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  
  // Start scan in background
  scans.set(scanId, { status: 'scanning', url, startedAt: new Date().toISOString() });
  
  runScan(scanId, url).catch(err => {
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

async function runScan(scanId, url) {
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
        description: `Page took ${(loadTime / 1000).toFixed(1)}s to load (should be under 3s)`,
        suggestion: 'Optimize images, reduce JavaScript, enable caching'
      });
    } else if (loadTime > 3000) {
      issues.push({
        type: 'info',
        category: 'Performance',
        title: 'Page load could be faster',
        description: `Page took ${(loadTime / 1000).toFixed(1)}s to load`,
        suggestion: 'Consider optimizing for faster load times'
      });
    }

    // Check for console errors
    if (consoleErrors.length > 0) {
      issues.push({
        type: 'warning',
        category: 'JavaScript',
        title: `${consoleErrors.length} Console Error(s)`,
        description: consoleErrors.slice(0, 3).join('\n'),
        suggestion: 'Fix JavaScript errors to ensure proper functionality'
      });
    }

    // Check for failed requests (broken resources)
    if (failedRequests.length > 0) {
      issues.push({
        type: 'warning',
        category: 'Resources',
        title: `${failedRequests.length} Failed Resource(s)`,
        description: failedRequests.slice(0, 3).map(r => r.url).join('\n'),
        suggestion: 'Fix broken resource links'
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
        title: `${brokenLinks.length} Broken Link(s)`,
        description: brokenLinks.slice(0, 3).map(l => `${l.text || 'Link'}: ${l.href} (${l.status})`).join('\n'),
        suggestion: 'Fix or remove broken links'
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
        description: 'Content overflows horizontally on mobile viewport',
        suggestion: 'Check for fixed widths and ensure responsive design'
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
        description: 'Page may not render correctly on mobile devices',
        suggestion: 'Add <meta name="viewport" content="width=device-width, initial-scale=1">'
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
        description: accessibilityIssues.map(i => `${i.count} ${i.type}`).join('\n'),
        suggestion: 'Add proper alt text, labels, and ARIA attributes'
      });
    }

    // Check HTTPS
    if (!url.startsWith('https://')) {
      issues.push({
        type: 'warning',
        category: 'Security',
        title: 'Not using HTTPS',
        description: 'Site is not using secure HTTPS connection',
        suggestion: 'Enable HTTPS for better security and SEO'
      });
    }

    // Use AI to analyze screenshots for UX issues
    try {
      const aiAnalysis = await analyzeWithAI(url, desktopScreenshot, issues);
      if (aiAnalysis && aiAnalysis.length > 0) {
        issues.push(...aiAnalysis);
      }
    } catch (err) {
      console.log('AI analysis skipped:', err.message);
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
});
