const https = require('https');
const http = require('http');

exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // POST /api/scan - run a scan
  if (event.httpMethod === 'POST') {
    try {
      const { url } = JSON.parse(event.body || '{}');
      
      if (!url) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'URL is required' })
        };
      }

      // Validate URL
      let parsedUrl;
      try {
        parsedUrl = new URL(url);
      } catch {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Invalid URL format' })
        };
      }

      // Run lightweight scan
      const result = await runScan(parsedUrl);
      
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify(result)
      };
    } catch (error) {
      console.error('Scan error:', error);
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ error: 'Scan failed', message: error.message })
      };
    }
  }

  return {
    statusCode: 404,
    headers,
    body: JSON.stringify({ error: 'Not found' })
  };
};

async function runScan(parsedUrl) {
  const issues = [];
  const url = parsedUrl.href;
  
  // Fetch the page
  const startTime = Date.now();
  let response;
  let html = '';
  
  try {
    response = await fetchUrl(url, 15000);
    html = response.body;
  } catch (err) {
    issues.push({
      type: 'critical',
      category: 'Connectivity',
      title: 'Page failed to load',
      description: `Could not fetch the page: ${err.message}`,
      suggestion: 'Check if the URL is correct and the server is running'
    });
    
    return {
      status: 'complete',
      url,
      issues,
      summary: { critical: 1, warnings: 0, info: 0, loadTime: 'N/A' },
      completedAt: new Date().toISOString()
    };
  }
  
  const loadTime = Date.now() - startTime;

  // Check HTTP status
  if (response.statusCode >= 400) {
    issues.push({
      type: 'critical',
      category: 'HTTP',
      title: `HTTP ${response.statusCode} Error`,
      description: `The page returned a ${response.statusCode} status code`,
      suggestion: 'Check server configuration and routing'
    });
  }

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

  // Check HTTPS
  if (parsedUrl.protocol !== 'https:') {
    issues.push({
      type: 'warning',
      category: 'Security',
      title: 'Not using HTTPS',
      description: 'Site is not using secure HTTPS connection',
      suggestion: 'Enable HTTPS for better security and SEO'
    });
  }

  // Check for viewport meta tag
  if (!html.includes('viewport')) {
    issues.push({
      type: 'warning',
      category: 'Mobile',
      title: 'Missing viewport meta tag',
      description: 'Page may not render correctly on mobile devices',
      suggestion: 'Add <meta name="viewport" content="width=device-width, initial-scale=1">'
    });
  }

  // Check for title tag
  const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
  if (!titleMatch || !titleMatch[1].trim()) {
    issues.push({
      type: 'warning',
      category: 'SEO',
      title: 'Missing or empty title tag',
      description: 'Page has no title, which hurts SEO and accessibility',
      suggestion: 'Add a descriptive <title> tag in the <head>'
    });
  }

  // Check for meta description
  if (!html.includes('name="description"') && !html.includes("name='description'")) {
    issues.push({
      type: 'info',
      category: 'SEO',
      title: 'Missing meta description',
      description: 'No meta description found',
      suggestion: 'Add <meta name="description" content="..."> for better SEO'
    });
  }

  // Check for images without alt text
  const imgTags = html.match(/<img[^>]*>/gi) || [];
  const imgsWithoutAlt = imgTags.filter(img => !img.includes('alt=')).length;
  if (imgsWithoutAlt > 0) {
    issues.push({
      type: 'info',
      category: 'Accessibility',
      title: `${imgsWithoutAlt} image(s) missing alt text`,
      description: 'Images without alt attributes hurt accessibility and SEO',
      suggestion: 'Add descriptive alt text to all images'
    });
  }

  // Check for broken resource hints (common patterns)
  const brokenPatterns = [
    { pattern: /src=["'][^"']*undefined/i, msg: 'undefined in src attribute' },
    { pattern: /href=["'][^"']*undefined/i, msg: 'undefined in href attribute' },
    { pattern: /src=["']\/\//i, msg: 'Protocol-relative URLs (use https://)' }
  ];
  
  for (const { pattern, msg } of brokenPatterns) {
    if (pattern.test(html)) {
      issues.push({
        type: 'warning',
        category: 'Resources',
        title: 'Potential broken resource',
        description: msg,
        suggestion: 'Check resource URLs for errors'
      });
      break;
    }
  }

  // Check for console.log in production (basic check)
  if (html.includes('console.log(') && !html.includes('//console.log')) {
    issues.push({
      type: 'info',
      category: 'Code Quality',
      title: 'Console.log detected',
      description: 'Console.log statements found in page source',
      suggestion: 'Remove console.log statements for production'
    });
  }

  // If no issues found, add a positive note
  if (issues.length === 0) {
    issues.push({
      type: 'info',
      category: 'Overall',
      title: 'Looking good!',
      description: 'No major issues detected in this quick scan',
      suggestion: 'Consider a full browser-based scan for deeper analysis'
    });
  }

  return {
    status: 'complete',
    url,
    issues,
    summary: {
      critical: issues.filter(i => i.type === 'critical').length,
      warnings: issues.filter(i => i.type === 'warning').length,
      info: issues.filter(i => i.type === 'info').length,
      loadTime: `${(loadTime / 1000).toFixed(1)}s`
    },
    completedAt: new Date().toISOString()
  };
}

function fetchUrl(url, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      headers: {
        'User-Agent': 'VibeQA Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      timeout
    };

    const req = protocol.request(options, (res) => {
      // Handle redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const redirectUrl = new URL(res.headers.location, url);
        return fetchUrl(redirectUrl.href, timeout).then(resolve).catch(reject);
      }

      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body
        });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
    
    req.end();
  });
}
