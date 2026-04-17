// server/routes/reports.js - Executive Report Generation
const express = require('express');
const router = express.Router();
const puppeteer = require('puppeteer');
const { requireAuth } = require('../middleware/auth');
const { supabase } = require('../lib/supabase');
const { getVibeScore } = require('../lib/scoring');

/**
 * POST /api/scans/:id/report
 * Generate executive report for a scan
 * Returns PDF file for download
 */
router.post('/:id/report', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { format = 'pdf' } = req.body; // pdf, html, email

    // 1. Fetch scan from database
    const { data: scan, error: scanError } = await supabase
      .from('scans')
      .select('*')
      .eq('id', id)
      .eq('user_id', req.user.id)
      .single();

    if (scanError || !scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // 2. Get user subscription tier
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('subscription_tier, company_name, company_logo')
      .eq('id', req.user.id)
      .single();

    if (userError) {
      return res.status(400).json({ error: 'Unable to retrieve user data' });
    }

    const isPaidUser = ['pro', 'team', 'enterprise'].includes(user.subscription_tier);
    const isTeamOrEnterprise = ['team', 'enterprise'].includes(user.subscription_tier);

    // 3. Generate report HTML
    const reportHTML = generateReportHTML(scan, user, isPaidUser);

    // 4. Handle different formats
    if (format === 'html') {
      return res.setHeader('Content-Type', 'text/html').send(reportHTML);
    }

    if (format === 'pdf') {
      const pdfBuffer = await generatePDF(reportHTML);
      
      // Record report generation
      await supabase.from('report_exports').insert({
        scan_id: id,
        user_id: req.user.id,
        format: 'pdf',
        generated_at: new Date().toISOString(),
        subscription_tier: user.subscription_tier
      });

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="vibeqa-report-${id}.pdf"`);
      return res.send(pdfBuffer);
    }

    if (format === 'email') {
      // TODO: Implement email delivery
      const pdfBuffer = await generatePDF(reportHTML);
      await sendReportEmail(req.user.email, scan.url, pdfBuffer);
      return res.json({ success: true, message: 'Report emailed successfully' });
    }

    res.status(400).json({ error: 'Invalid format' });
  } catch (error) {
    console.error('Report generation error:', error);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

/**
 * Generate report HTML template
 * Includes watermark for free users
 */
function generateReportHTML(scan, user, isPaidUser) {
  const vibeScore = getVibeScore(scan.results);
  const timestamp = new Date(scan.created_at).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  const categories = extractCategories(scan.results);
  const topIssues = getTopIssues(scan.results, 5);
  const recommendations = generateRecommendations(scan.results, categories);

  const watermarkHTML = !isPaidUser ? `
    <div class="watermark">VibeQA.io</div>
    <div class="demo-banner">DEMO REPORT - Upgrade for full features</div>
  ` : '';

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeQA Executive Report - ${scan.url}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      color: #1a1a1a;
      line-height: 1.6;
      background: #fff;
    }

    .page {
      page-break-after: always;
      padding: 60px 50px;
      min-height: 11in;
      position: relative;
      background: #fff;
    }

    .page:last-child { page-break-after: avoid; }

    /* Watermark */
    .watermark {
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%) rotate(-45deg);
      font-size: 120px;
      font-weight: 300;
      color: rgba(0,0,0,0.08);
      white-space: nowrap;
      pointer-events: none;
      z-index: 0;
      width: 200%;
    }

    .demo-banner {
      position: fixed;
      top: 20px;
      right: 0;
      background: #ff4444;
      color: white;
      padding: 8px 20px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 1px;
      z-index: 100;
    }

    /* Page content */
    .content { position: relative; z-index: 1; }

    /* Cover Page (Page 1) */
    .cover-page {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      min-height: 11in;
    }

    .cover-header {
      text-align: center;
      margin-bottom: 40px;
    }

    .logo { font-size: 24px; font-weight: 700; color: #6b5b95; margin-bottom: 20px; }
    .report-title { font-size: 32px; font-weight: 600; color: #1a1a1a; margin: 20px 0; }
    .url { font-size: 16px; color: #666; word-break: break-all; }

    .score-section {
      text-align: center;
      margin: 40px 0;
      padding: 40px;
      background: linear-gradient(135deg, #f5f7fa 0%, #faf8f5 100%);
      border-radius: 12px;
    }

    .score-circle {
      width: 180px;
      height: 180px;
      border-radius: 50%;
      margin: 0 auto 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 72px;
      font-weight: 700;
      color: white;
    }

    .score-circle.excellent { background: #4caf50; }
    .score-circle.good { background: #8bc34a; }
    .score-circle.fair { background: #ff9800; }
    .score-circle.poor { background: #f44336; }

    .score-label { font-size: 18px; color: #666; font-weight: 500; }

    .key-findings {
      margin-top: 40px;
      padding: 20px;
      background: #f9f9f9;
      border-left: 4px solid #6b5b95;
    }

    .key-findings h3 { margin-bottom: 12px; color: #1a1a1a; }
    .key-findings ul { margin-left: 20px; }
    .key-findings li { margin: 8px 0; color: #555; }

    .cover-footer {
      text-align: center;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #ddd;
      color: #999;
      font-size: 12px;
    }

    /* Dashboard Page (Page 2) */
    .dashboard {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 30px;
    }

    .metric-card {
      border: 1px solid #e0e0e0;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }

    .metric-label { font-size: 12px; text-transform: uppercase; color: #999; font-weight: 600; letter-spacing: 0.5px; }
    .metric-value { font-size: 36px; font-weight: 700; margin: 10px 0; }
    .metric-status { font-size: 12px; color: #666; }

    .status-pass { color: #4caf50; font-weight: 600; }
    .status-fail { color: #f44336; font-weight: 600; }
    .status-warning { color: #ff9800; font-weight: 600; }

    /* Issues Section */
    .issues-section {
      margin-top: 40px;
      page-break-inside: avoid;
    }

    .section-title {
      font-size: 20px;
      font-weight: 600;
      color: #1a1a1a;
      margin: 30px 0 15px;
      padding-bottom: 10px;
      border-bottom: 2px solid #6b5b95;
    }

    .issue {
      margin: 15px 0;
      padding: 15px;
      border-left: 4px solid #ddd;
      background: #f9f9f9;
      border-radius: 4px;
    }

    .issue.critical { border-left-color: #f44336; background: #ffebee; }
    .issue.high { border-left-color: #ff9800; background: #fff3e0; }
    .issue.medium { border-left-color: #ffc107; background: #fffde7; }
    .issue.low { border-left-color: #4caf50; background: #f1f8e9; }

    .issue-severity {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      margin-bottom: 8px;
    }

    .issue-severity.critical { background: #f44336; color: white; }
    .issue-severity.high { background: #ff9800; color: white; }
    .issue-severity.medium { background: #ffc107; color: #333; }
    .issue-severity.low { background: #4caf50; color: white; }

    .issue-title { font-weight: 600; color: #1a1a1a; margin: 8px 0; }
    .issue-description { font-size: 13px; color: #666; line-height: 1.5; }

    /* Recommendations */
    .recommendations {
      page-break-inside: avoid;
      margin-top: 40px;
      padding: 20px;
      background: linear-gradient(135deg, #f0f4ff 0%, #f5f9ff 100%);
      border-radius: 8px;
      border-left: 4px solid #6b5b95;
    }

    .recommendations h3 { color: #1a1a1a; margin-bottom: 15px; }
    .rec-item { margin: 12px 0; padding-left: 20px; position: relative; }
    .rec-item:before { content: "✓"; position: absolute; left: 0; color: #4caf50; font-weight: 700; }

    /* Footer */
    .footer {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #ddd;
      font-size: 11px;
      color: #999;
      text-align: center;
    }

    @media print {
      body { background: white; }
      .page { box-shadow: none; margin: 0; page-break-after: always; }
    }
  </style>
</head>
<body>
  ${watermarkHTML}

  <!-- Page 1: Cover Page -->
  <div class="page cover-page">
    <div class="content">
      <div class="cover-header">
        <div class="logo">VibeQA</div>
        <h1 class="report-title">Executive Summary Report</h1>
        <p class="url">${escapeHTML(scan.url)}</p>
        <p style="color: #999; margin-top: 10px; font-size: 13px;">Generated ${timestamp}</p>
      </div>

      <div class="score-section">
        <div class="score-circle ${getScoreBadge(vibeScore)}">${Math.round(vibeScore)}</div>
        <div class="score-label">Vibe Score</div>
      </div>

      <div class="key-findings">
        <h3>Key Findings</h3>
        <ul>
          ${topIssues.slice(0, 3).map(issue => `
            <li><strong>${issue.title}:</strong> ${issue.description}</li>
          `).join('')}
        </ul>
      </div>

      <div class="cover-footer">
        <p>This report is confidential and intended for authorized recipients only.</p>
        <p>For questions or clarification, contact support@vibeqa.io</p>
      </div>
    </div>
  </div>

  <!-- Page 2: Dashboard -->
  <div class="page">
    <div class="content">
      <h2 class="section-title">Key Metrics Dashboard</h2>
      
      <div class="dashboard">
        ${generateMetricsHTML(categories, scan.results)}
      </div>

      <div class="issues-section">
        <h3 style="margin-top: 30px;">Issues Summary by Severity</h3>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 15px;">
          <div class="metric-card">
            <div class="metric-label">Critical Issues</div>
            <div class="metric-value status-fail">${countBySeverity(scan.results, 'critical')}</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">High Issues</div>
            <div class="metric-value status-warning">${countBySeverity(scan.results, 'high')}</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Medium Issues</div>
            <div class="metric-value">${countBySeverity(scan.results, 'medium')}</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Low Issues</div>
            <div class="metric-value status-pass">${countBySeverity(scan.results, 'low')}</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Page 3+: Detailed Findings -->
  ${generateDetailedFindingsHTML(scan.results, categories)}

  <!-- Final Page: Recommendations -->
  <div class="page">
    <div class="content">
      <h2 class="section-title">Recommendations & Next Steps</h2>
      
      <div class="recommendations">
        <h3>Priority Actions (Quick Wins)</h3>
        ${recommendations.quickWins.map(rec => `
          <div class="rec-item">${rec}</div>
        `).join('')}
      </div>

      <div class="recommendations" style="margin-top: 20px;">
        <h3>Strategic Improvements</h3>
        ${recommendations.strategic.map(rec => `
          <div class="rec-item">${rec}</div>
        `).join('')}
      </div>

      <div style="margin-top: 40px; padding: 20px; background: #f5f5f5; border-radius: 8px;">
        <h3 style="margin-bottom: 12px;">Next Steps</h3>
        <ol style="margin-left: 20px; color: #666;">
          <li>Review findings with stakeholders</li>
          <li>Prioritize issues based on impact and effort</li>
          <li>Assign owners for each category of work</li>
          <li>Track progress and schedule follow-up scan in 2-4 weeks</li>
          <li>Use VibeQA API for continuous monitoring (Pro/Team users)</li>
        </ol>
      </div>

      <div style="margin-top: 40px; padding: 20px; background: #f0f4ff; border-radius: 8px; border-left: 4px solid #6b5b95;">
        <h3 style="color: #6b5b95; margin-bottom: 12px;">Want automated scanning?</h3>
        <p style="font-size: 13px; color: #666;">
          ${isPaidUser ? 
            'Upgrade to our Pro or Team plan for scheduled scans, API access, and team collaboration features.' :
            'Upgrade to our Pro plan for scheduled scans, API access, and automated monitoring.'}
        </p>
      </div>

      <div class="footer">
        <p>VibeQA - Real User Testing for Vibe Coders</p>
        <p>© 2026 VibeQA. All rights reserved.</p>
      </div>
    </div>
  </div>
</body>
</html>
  `;
}

/**
 * Generate PDF from HTML using Puppeteer
 */
async function generatePDF(html) {
  let browser;
  try {
    browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });

    const pdf = await page.pdf({
      format: 'A4',
      margin: { top: '0.5in', bottom: '0.5in', left: '0.5in', right: '0.5in' },
      printBackground: true
    });

    return pdf;
  } finally {
    if (browser) await browser.close();
  }
}

/**
 * Helper functions
 */
function getScoreBadge(score) {
  if (score >= 80) return 'excellent';
  if (score >= 60) return 'good';
  if (score >= 40) return 'fair';
  return 'poor';
}

function extractCategories(results) {
  return {
    links: results.broken_links || [],
    mobile: results.mobile || {},
    performance: results.performance || {},
    accessibility: results.accessibility || [],
    seo: results.seo || {},
    security: results.security || []
  };
}

function countBySeverity(results, severity) {
  let count = 0;
  const allIssues = [
    ...(results.broken_links || []),
    ...(results.accessibility || []),
    ...(results.security || [])
  ];
  allIssues.forEach(issue => {
    if (issue.severity === severity) count++;
  });
  return count;
}

function getTopIssues(results, limit = 5) {
  const issues = [
    ...(results.broken_links || []).map(l => ({ title: 'Broken Link', description: l.url, severity: 'high' })),
    ...(results.accessibility || []).map(a => ({ title: 'Accessibility Issue', description: a.type, severity: a.severity })),
    ...(results.security || []).map(s => ({ title: 'Security Issue', description: s.title, severity: s.severity }))
  ];
  return issues.slice(0, limit);
}

function generateRecommendations(results, categories) {
  const quickWins = [];
  const strategic = [];

  if (categories.links.length > 0) {
    quickWins.push('Fix broken links - typically low effort, high impact');
  }
  if (categories.accessibility.length > 10) {
    strategic.push('Conduct accessibility audit - address color contrast and ARIA labels');
  }
  if (categories.security.length > 0) {
    quickWins.push('Review and remediate security findings');
  }
  if (categories.performance.score < 60) {
    strategic.push('Optimize image sizes and implement lazy loading');
  }

  return { quickWins, strategic };
}

function generateMetricsHTML(categories, results) {
  const linkHealthPercent = results.total_links > 0 ? 
    Math.round(((results.total_links - (results.broken_links || []).length) / results.total_links) * 100) : 100;

  return `
    <div class="metric-card">
      <div class="metric-label">Link Health</div>
      <div class="metric-value">${linkHealthPercent}%</div>
      <div class="metric-status">Working links</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Mobile Experience</div>
      <div class="metric-value ${results.mobile?.responsive ? 'status-pass' : 'status-fail'}">${results.mobile?.responsive ? 'Pass' : 'Fail'}</div>
      <div class="metric-status">Mobile responsive</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Performance Score</div>
      <div class="metric-value">${results.performance?.score || 'N/A'}</div>
      <div class="metric-status">Page load optimized</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Accessibility</div>
      <div class="metric-value">${results.accessibility?.score || 'Scan'}</div>
      <div class="metric-status">WCAG compliance</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">SEO Score</div>
      <div class="metric-value">${results.seo?.score || 'Scan'}</div>
      <div class="metric-status">Search optimization</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Security Issues</div>
      <div class="metric-value ${(results.security || []).length > 0 ? 'status-fail' : 'status-pass'}">${(results.security || []).length}</div>
      <div class="metric-status">Found</div>
    </div>
  `;
}

function generateDetailedFindingsHTML(results, categories) {
  let html = '';

  // Links
  if (categories.links.length > 0) {
    html += `
      <div class="page">
        <div class="content">
          <h2 class="section-title">Link Health Analysis</h2>
          <p style="color: #666; margin-bottom: 20px;">
            Found ${categories.links.length} broken or redirecting links out of ${results.total_links || 'N/A'} total links.
          </p>
          ${categories.links.map(link => `
            <div class="issue high">
              <span class="issue-severity high">broken</span>
              <div class="issue-title">${escapeHTML(link.url)}</div>
              <div class="issue-description">Status: ${link.status_code || 'Connection error'}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // Accessibility
  if (categories.accessibility.length > 0) {
    html += `
      <div class="page">
        <div class="content">
          <h2 class="section-title">Accessibility Findings</h2>
          <p style="color: #666; margin-bottom: 20px;">
            ${categories.accessibility.length} accessibility issues found. Improving these increases your reach and SEO.
          </p>
          ${categories.accessibility.map(issue => `
            <div class="issue ${issue.severity || 'medium'}">
              <span class="issue-severity ${issue.severity || 'medium'}">${issue.severity || 'medium'}</span>
              <div class="issue-title">${escapeHTML(issue.type)}</div>
              <div class="issue-description">${escapeHTML(issue.message || 'See WCAG guidelines for recommended fixes')}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // Security
  if (categories.security.length > 0) {
    html += `
      <div class="page">
        <div class="content">
          <h2 class="section-title">Security Assessment</h2>
          <p style="color: #666; margin-bottom: 20px;">
            ${categories.security.length} security concerns identified.
          </p>
          ${categories.security.map(issue => `
            <div class="issue ${issue.severity || 'high'}">
              <span class="issue-severity ${issue.severity || 'high'}">${issue.severity || 'high'}</span>
              <div class="issue-title">${escapeHTML(issue.title)}</div>
              <div class="issue-description">${escapeHTML(issue.description || 'Review security best practices and remediate')}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  return html;
}

function escapeHTML(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

module.exports = router;
