# VibeQA

**Automated testing for vibe coders.**

Find bugs before your users do.

---

## What is this?

Automated testing for indie builders, vibe coders, and small teams. Paste your URL, get a detailed report including:

- 🔗 Broken links detection
- 📱 Mobile responsiveness checks
- ⚡ Performance analysis
- 🛑 Console error detection
- 🔒 Security checks (HTTPS)
- ♿ Accessibility review
- 🤖 AI-powered UX analysis (optional)

## Target Customers

- Cursor / Bolt / v0 / Replit builders
- Indie hackers shipping MVPs
- Small agencies QA'ing client work
- No-code builders (Bubble, Webflow, Framer)

## Quick Start

### Prerequisites

- Node.js 18+
- npm

### Installation

```bash
npm install
```

### Running the Server

```bash
node server.js
```

The server runs on `http://localhost:3847` by default.

### Environment Variables (Optional)

For AI-powered UX analysis, set your OpenAI API key:

```bash
export OPENAI_API_KEY=your_key_here
```

### API Endpoints

#### Start a Scan
```bash
POST /api/scan
Content-Type: application/json

{
  "url": "https://your-site.com"
}

# Returns: { "scanId": "abc123", "status": "scanning" }
```

#### Get Scan Results
```bash
GET /api/scan/:scanId

# Returns scan results including issues, screenshots, and summary
```

### Using the Web UI

1. Run `node server.js`
2. Open `index.html` in your browser (or use a local server)
3. Enter a URL and click "Scan Now"
4. View results including screenshots and issues

## Pricing (Coming Soon)

| Tier | Price | What You Get |
|------|-------|--------------|
| Free | $0 | 1 scan, no signup |
| Pro | $29/mo | 10 scans/month |
| Team | $99/mo | Unlimited scans |

## Files

- `index.html` — Landing page with scanner UI
- `server.js` — Express backend with Puppeteer scanning
- `package.json` — Dependencies

## Status

🟢 **Live** — Landing page at https://munyak.github.io/vibeqa/

## Next Steps

1. Buy domain (vibeqa.com or similar)
2. Deploy backend to Railway/Render
3. Set up Stripe for payments
4. Post in Cursor Discord / r/cursor
5. Get first paying customer
