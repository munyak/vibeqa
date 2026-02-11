# VibeQA — Go-to-Market Plan

## Positioning

**The gap:** Sits between vibe code platforms (Cursor/Bolt/v0) and production.

```
[Cursor/Bolt/v0] → [Build Fast] → [???] → [Production] → [Users]
                                    ↑
                              VibeQA fits here
                         "The last mile before launch"
```

**Tagline options:**
- "You ship fast. We find the bugs."
- "QA for the vibe coding era"
- "The last check before launch"
- "Ship with confidence"

---

## Target Customers (in order of priority)

### Tier 1: Vibe Coders (Immediate)
- Cursor power users
- Bolt.new builders  
- v0.dev → deploy crowd
- Replit deployers
- **Where they are:** Twitter/X, r/cursor, Discord servers, indie hacker forums

### Tier 2: Indie Hackers (Month 2)
- Building SaaS MVPs
- Side project shippers
- **Where they are:** Indie Hackers, r/SideProject, Twitter, Product Hunt

### Tier 3: Small Agencies (Month 3)
- Need to QA client work
- Don't have in-house QA
- **Where they are:** LinkedIn, Clutch, agency Slacks

---

## Launch Strategy

### Week 1-2: Soft Launch (Manual MVP)
1. Create landing page (DONE)
2. Set up Tally/Typeform for intake
3. Recruit 5-10 testers (Upwork, UserTesting referrals)
4. Price: $49 Quick Check only
5. Goal: 5 paying customers

### Week 3-4: Validate & Iterate
1. Collect feedback from first customers
2. Build simple dashboard (Notion or Airtable)
3. Add $149 tier
4. Goal: 15 total customers, $1K revenue

### Month 2: Scale Testers
1. Build tester pool (20-30 reliable testers)
2. Create tester training/guidelines
3. Automate matching
4. Launch on Product Hunt
5. Goal: $3K MRR equivalent

### Month 3: Growth
1. Content marketing (Twitter threads, "bugs we found" series)
2. Affiliate program for satisfied customers
3. Agency tier / white-label option
4. Goal: $5K MRR

---

## Distribution Channels

### Organic (Free)
- **Twitter/X:** Post "bugs we found" threads, vibe coding tips
- **Reddit:** r/cursor, r/webdev, r/SideProject, r/indiehackers
- **Discord:** Cursor Discord, Bolt Discord, indie hacker servers
- **Product Hunt:** Launch with good assets

### Paid (Later)
- Twitter ads targeting "cursor" "bolt.new" "v0" keywords
- Sponsor newsletters (Bytes, TLDR, Ben's Bites)

### Partnerships
- Cursor/Bolt could feature us as "recommended before deploy"
- Vercel/Netlify partnership (pre-deploy hook?)

---

## Competitive Moat

1. **Speed:** 24h turnaround vs 3-5 days elsewhere
2. **Price:** $49 vs $100+ competitors
3. **Focus:** Built FOR vibe coders, not enterprise
4. **Community:** Testers who understand modern web apps
5. **Content:** "Bugs we found" becomes authority content

---

## Revenue Projections (Conservative)

| Month | Customers | Avg Order | Revenue |
|-------|-----------|-----------|---------|
| 1 | 10 | $75 | $750 |
| 2 | 25 | $100 | $2,500 |
| 3 | 50 | $125 | $6,250 |
| 6 | 100 | $150 | $15,000 |
| 12 | 200 | $150 | $30,000 |

**Break-even:** ~$2K/month (tester costs + tools)
**Profitable at:** 20 customers/month at $100 avg

---

## MVP Tech Stack

- **Landing:** Static HTML (done) → deploy to Vercel/Netlify
- **Intake:** Tally or Typeform (free tier)
- **Payments:** Stripe (or Gumroad to start)
- **Tester Management:** Notion database
- **Video Storage:** Loom (testers record) or CloudFlare Stream
- **Delivery:** Email + Notion shared page
- **Later:** Simple Next.js dashboard

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Tester quality varies | Create guidelines, rating system, fire bad testers |
| Low demand | Validate with $49 tier before building more |
| Hard to scale testers | Start building pool early, pay well to retain |
| Competitors copy | Move fast, build community, content moat |

---

## Next Actions

1. [ ] Deploy landing page to vibeqa.com (or similar domain)
2. [ ] Set up Stripe + intake form
3. [ ] Post in r/cursor and Cursor Discord
4. [ ] DM 10 vibe coders offering free first test
5. [ ] Recruit 5 initial testers on Upwork
6. [ ] Get first paying customer within 7 days
