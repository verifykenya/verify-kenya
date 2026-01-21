# AuthentiChain MVP – Complete Build Specification
## Engineering Brief for Development Team

---

## EXECUTIVE SUMMARY
Build a full-stack B2B2C counterfeit verification platform MVP with three integrated components:
1. **Manufacturer Dashboard** (Web): Onboard products, generate QR/NFC codes, monitor scans
2. **Consumer/Seller App** (Web + Mobile): Scan QR codes, verify authenticity, report fakes
3. **Brand Analytics Dashboard** (Web): Real-time scan analytics, counterfeit alerts, cross-platform monitoring

**Timeline:** 12 weeks  
**Target Launch:** 50 pilot manufacturers, 100k monthly users by Month 3

---

## PART 1: TECH STACK & INFRASTRUCTURE

### Backend
- **Runtime:** Node.js 18+ or Python 3.10+
- **API Framework:** Express.js (Node) or FastAPI (Python)
- **Database:** PostgreSQL (relational data: manufacturers, products, scans, users)
- **Cache:** Redis (real-time scan counts, session management)
- **File Storage:** AWS S3 or equivalent (QR/NFC code generation assets, product images)
- **Authentication:** JWT + OAuth 2.0 (Google/GitHub for MVP, allow email sign-up)
- **QR Code Generation:** `qrcode` library (Node) or `qrcode` (Python)

### Frontend
- **Web (Manufacturer + Brand Dashboard):** React 18+ with TypeScript
- **Mobile (Consumer App):** React Native or Flutter (MVP: start with React web + responsive design for mobile)
- **UI Framework:** Tailwind CSS or Material-UI
- **State Management:** Redux Toolkit or Zustand
- **HTTP Client:** Axios or Fetch API

### Real-Time Features
- **WebSocket:** Socket.io (for live scan notifications to brands)
- **Analytics:** Posthog or Mixpanel (user behavior tracking)

### Deployment
- **Hosting:** AWS EC2/ECS or DigitalOcean (backend)
- **Frontend:** Vercel, Netlify, or AWS S3 + CloudFront
- **CI/CD:** GitHub Actions or GitLab CI
- **Monitoring:** Sentry (error tracking), CloudWatch (logs)

### QR/NFC Specifics (MVP)
- **QR Codes Only (Phase 1):** No NFC hardware required for MVP; focus on QR scanning via phone camera
- **Libraries:** `qrcode` (Node) for generation; `jsQR` or `@react-native-camera/camera` for scanning
- **Data Structure in QR:** Unique `product_id:verification_token` encrypted with HMAC-SHA256

---

## PART 2: DATABASE SCHEMA (PostgreSQL)

### Core Tables

```sql
-- Users & Authentication
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR UNIQUE NOT NULL,
  password_hash VARCHAR NOT NULL,
  user_type ENUM ('manufacturer', 'consumer', 'brand_admin'),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Manufacturers
CREATE TABLE manufacturers (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  company_name VARCHAR NOT NULL,
  industry VARCHAR,
  country VARCHAR,
  monthly_subscription_tier ENUM ('free', 'starter', 'pro'),
  status ENUM ('active', 'suspended', 'trial'),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Products
CREATE TABLE products (
  id UUID PRIMARY KEY,
  manufacturer_id UUID REFERENCES manufacturers(id),
  sku VARCHAR NOT NULL,
  product_name VARCHAR NOT NULL,
  category VARCHAR,
  image_url VARCHAR,
  authorized_channels TEXT[], -- e.g., ['Amazon', 'Official Store', 'Target']
  created_at TIMESTAMP DEFAULT NOW()
);

-- Verification Codes (QR/NFC)
CREATE TABLE verification_codes (
  id UUID PRIMARY KEY,
  product_id UUID REFERENCES products(id),
  code_value VARCHAR UNIQUE NOT NULL, -- Encrypted: product_id:token
  batch_number VARCHAR,
  manufacture_date DATE,
  serial_number VARCHAR,
  destination_retailer VARCHAR,
  status ENUM ('active', 'deactivated'),
  created_at TIMESTAMP DEFAULT NOW(),
  deactivated_at TIMESTAMP
);

-- Scan Events
CREATE TABLE scans (
  id UUID PRIMARY KEY,
  verification_code_id UUID REFERENCES verification_codes(id),
  user_id UUID REFERENCES users(id),
  scan_timestamp TIMESTAMP DEFAULT NOW(),
  geolocation POINT, -- lat/long
  device_type VARCHAR, -- 'mobile', 'web'
  ip_address VARCHAR,
  scan_source VARCHAR -- 'app', 'web', 'sms'
);

-- Scan Results Cache (for analytics)
CREATE TABLE scan_results (
  id UUID PRIMARY KEY,
  code_value VARCHAR UNIQUE,
  is_authentic BOOLEAN,
  manufacturer_id UUID REFERENCES manufacturers(id),
  total_scan_count INT DEFAULT 0,
  unique_scanner_count INT DEFAULT 0,
  last_scan_timestamp TIMESTAMP,
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Counterfeit Reports
CREATE TABLE counterfeit_reports (
  id UUID PRIMARY KEY,
  verification_code_id UUID REFERENCES verification_codes(id),
  reporter_id UUID REFERENCES users(id),
  report_reason VARCHAR,
  report_evidence_url VARCHAR,
  platform_listed_on VARCHAR, -- 'Amazon', 'eBay', etc.
  listing_url VARCHAR,
  status ENUM ('pending', 'verified', 'false_positive'),
  created_at TIMESTAMP DEFAULT NOW(),
  resolved_at TIMESTAMP
);

-- Manufacturer Subscription & Billing
CREATE TABLE subscriptions (
  id UUID PRIMARY KEY,
  manufacturer_id UUID REFERENCES manufacturers(id),
  tier ENUM ('free', 'starter', 'pro'),
  monthly_tags_limit INT, -- Free: 10k, Starter: 100k, Pro: unlimited
  monthly_scans_included INT,
  price_usd DECIMAL,
  billing_cycle_start DATE,
  status ENUM ('active', 'canceled', 'past_due'),
  created_at TIMESTAMP DEFAULT NOW()
);

-- API Keys (for manufacturer integrations)
CREATE TABLE api_keys (
  id UUID PRIMARY KEY,
  manufacturer_id UUID REFERENCES manufacturers(id),
  api_key_hash VARCHAR UNIQUE,
  name VARCHAR,
  created_at TIMESTAMP DEFAULT NOW(),
  last_used TIMESTAMP,
  status ENUM ('active', 'revoked')
);
```

### Key Indexes
```sql
CREATE INDEX idx_scans_code ON scans(verification_code_id);
CREATE INDEX idx_scans_timestamp ON scans(scan_timestamp);
CREATE INDEX idx_scans_geolocation ON scans USING GIST(geolocation);
CREATE INDEX idx_products_manufacturer ON products(manufacturer_id);
CREATE INDEX idx_reports_status ON counterfeit_reports(status);
CREATE INDEX idx_codes_product ON verification_codes(product_id);
```

---

## PART 3: API ENDPOINTS (RESTful)

### Authentication
```
POST /auth/signup
POST /auth/login
POST /auth/logout
POST /auth/refresh-token
GET /auth/user (current user)
```

### Manufacturer Onboarding & Management
```
POST /manufacturers (create account)
GET /manufacturers/:id (profile)
PATCH /manufacturers/:id (update)
GET /manufacturers/:id/subscription (billing info)
```

### Product Management
```
POST /products (create product)
GET /manufacturers/:id/products (list all)
GET /products/:id (get details)
PATCH /products/:id (update)
DELETE /products/:id (archive)
```

### QR Code Generation & Bulk Operations
```
POST /products/:id/generate-codes
  {
    "quantity": 1000,
    "batch_number": "BATCH_2024_001",
    "manufacture_date": "2024-01-15",
    "destination_retailer": "Amazon"
  }
  Response: CSV download with codes, QR images ZIP
  
GET /products/:id/codes (list all codes for product)
PATCH /codes/:code_id/deactivate (disable a code)
POST /codes/bulk-deactivate (disable multiple)
```

### Verification & Scanning
```
POST /verify/scan
  {
    "code_value": "product_123:token_abc",
    "geolocation": {"lat": 0.0, "lng": 0.0},
    "device_type": "mobile"
  }
  Response: 
  {
    "is_authentic": true,
    "product_name": "Luxury Watch XYZ",
    "sku": "LW-123",
    "batch": "BATCH_2024_001",
    "scan_count": 45,
    "manufacturer": "BrandName",
    "status": "authentic"
  }

GET /verify/:code_value (public endpoint, no auth required)
```

### Brand Analytics Dashboard
```
GET /manufacturers/:id/analytics
  {
    "total_scans": 50000,
    "scans_this_month": 12000,
    "unique_scanners": 8000,
    "scan_growth_pct": 15,
    "top_products": [...],
    "scan_heatmap": [...], // geolocation data
    "counterfeit_alerts": [...]
  }

GET /manufacturers/:id/analytics/scans (detailed scan logs)
  ?start_date=2024-01-01&end_date=2024-01-31&product_id=xxx&limit=100

GET /manufacturers/:id/analytics/geographic (scan map data)
```

### Counterfeit Reporting
```
POST /reports/create
  {
    "code_value": "product_123:token_abc",
    "reason": "Found on unauthorized marketplace",
    "platform": "eBay",
    "listing_url": "https://...",
    "evidence_image_url": "https://..."
  }

GET /manufacturers/:id/reports (list brand's reports)
GET /reports/:id (detail)
PATCH /reports/:id (update status to 'verified' or 'false_positive')
```

### Seller Verification Report
```
POST /reports/seller-batch
  {
    "codes": ["code1", "code2", "code3"],
    "batch_name": "FBA_Upload_Jan2024"
  }
  Response: PDF report with % verified, unregistered items flagged

GET /reports/seller-batch/:id (retrieve report)
```

### Subscription & Billing
```
GET /subscriptions/:id
POST /subscriptions/upgrade
  { "new_tier": "pro" }
  
POST /subscriptions/cancel
```

### Admin Endpoints (Internal)
```
GET /admin/manufacturers (all manufacturers, filterable)
POST /admin/manufacturers/:id/suspend
POST /admin/reports/:id/escalate (to legal team)
GET /admin/analytics/platform (global counterfeit stats)
```

---

## PART 4: FRONTEND SPECIFICATION

### Manufacturer Dashboard (React Web)

**Page 1: Onboarding / Company Setup**
```
Form Fields:
- Company Name
- Industry (dropdown: Luxury, Skincare, Pet Care, Auto Parts, Other)
- Country
- Email
- Password

After signup:
- Auto-redirect to Product Management
- Show "Welcome" modal with 3-step setup guide
```

**Page 2: Product Management**
```
Features:
- List all products (table: SKU, Name, Codes Generated, Scans, Status)
- "+ Add Product" button → modal form (SKU, Name, Category, Image Upload)
- Click product row → Product Detail Page

Product Detail Page:
- Product info (editable)
- Generate Codes section:
  - Input: Quantity, Batch Number, Manufacture Date, Destination Retailer
  - Button: "Generate & Download QR Codes"
  - Output: CSV + ZIP with PNG images (300x300px)
  - Show: "Generated 1,000 codes in Batch_2024_001"
- Codes List (table: Code ID, Status, Generated Date, Scan Count)
  - Deactivate button per code
- Bulk Deactivate (select multiple codes)
```

**Page 3: Brand Analytics Dashboard**
```
Real-Time Metrics (top of page):
- Total Scans (this month vs. last month, % change)
- Unique Scanners
- Counterfeit Alerts
- Avg. Scans/Product

Charts & Visualizations:
1. Scan Trend (line chart: scans over 30 days)
2. Geographic Heatmap (where scans are happening)
3. Top 5 Products (bar chart: scans/product)
4. Scan Source Breakdown (pie: app vs. web vs. sms)

Filters:
- Date range picker
- Product filter (dropdown)
- Geographic filter (country/region)

Detailed Scan Logs (expandable section):
- Table: Timestamp, Product, Scanner Location, Device Type, Authenticity
- Export to CSV button
```

**Page 4: Counterfeit Reports**
```
Table:
- Date Reported
- Product SKU
- Platform (Amazon, eBay, etc.)
- Listing URL
- Status (Pending, Verified, False Positive)
- Actions (View, Mark Verified, Dismiss)

Click row → Modal:
- Show report details
- Evidence image (if provided)
- Mark as "Verified Counterfeit" (→ create takedown ticket)
- Mark as "False Positive"
```

**Page 5: Settings**
```
- Company info (editable)
- Subscription tier + billing
- API Keys (view, generate, revoke)
- Team members (add/remove collaborators)
- Notifications (toggle alerts)
```

**Page 6: Navigation & Auth**
```
Header:
- Logo + Brand name
- User menu (Profile, Settings, Logout)
- Bell icon (notifications)

Sidebar:
- Dashboard (analytics)
- Products
- Generate Codes
- Reports
- Settings
- Help/Docs
```

---

### Consumer/Seller Verification App (React Web + Responsive Mobile)

**Page 1: Scan QR Code**
```
Full-screen camera interface:
- QR scanner (jsQR library)
- "Tap to scan" UI hint
- Upload image as fallback (tap gallery icon)
- Flashlight toggle

On successful scan:
- Instant redirect to Results Page
- Loading spinner while fetching data
```

**Page 2: Verification Results**
```
If Authentic:
- ✓ Green checkmark icon
- "Authentic Product Verified"
- Product details:
  - Product name
  - SKU
  - Batch number
  - Manufacture date
  - Expected retailer
  - Total scan count (social proof: "Scanned 2,340 times")
- "Share This Verification" button (generate shareable link)
- "Scan Another" button

If Counterfeit / Unverified:
- ✗ Red warning icon
- "Warning: Unregistered Product"
- Message: "This product code is not registered. It could be counterfeit."
- "Report This Product" button → Modal
- "Scan Another" button

If Already Flagged as Counterfeit:
- ⚠️ Red icon
- "Counterfeit Detected"
- "This product has been reported as counterfeit X times"
- "Report This Seller" button
- "Scan Another" button
```

**Page 3: Report a Fake (Modal)**
```
Form:
- Where did you find it? (dropdown: Amazon, eBay, Marketplace, Store, Other)
- Listing URL (text field)
- Add photos (upload 1-3 images)
- What's wrong? (text area, placeholder: "e.g., Wrong packaging, different formula")

Submit button → "Thank you! Report submitted."
Show: "Your report helps protect other buyers."
```

**Page 4: Seller Protection Report (For Resellers)**
```
Entry: "Bulk Verify My Inventory"
- Upload CSV or paste codes (one per line)
- Show progress bar as codes are verified
- Generate "Authenticity Certificate"
  - Timestamp
  - % of codes verified
  - List of unregistered/suspicious codes
  - "Download as PDF" button

PDF includes:
- AuthentiChain branding
- Timestamp
- Seller name (if logged in)
- Verification breakdown
- "This report can be submitted to e-commerce platforms for dispute resolution"
```

**Page 5: Home / Navigation**
```
Simple tab navigation:
- Scan (camera icon) - default
- History (clock icon) - past scans
- Reports (flag icon) - my reports
- Profile (user icon) - settings

Home screen (before scanning):
- Large "Tap to Scan" button
- Recent scan history (if logged in)
- "How to Use" collapsible section
- "Share with a Friend" button

Dark mode toggle (bottom right)
```

---

## PART 5: KEY WORKFLOWS & USER FLOWS

### Workflow 1: Manufacturer Generates & Distributes Codes
```
1. Manufacturer logs in → Products page
2. Click "Add Product" → Fill form → Create
3. Click product → "Generate Codes" section
4. Enter: Quantity (1,000), Batch_2024_001, Mfg Date, Retailer
5. Click "Generate & Download"
6. Download CSV (1,000 codes) + PNG files ZIP
7. Send CSV to label printer or manufacturing partner
8. Print on product labels or packaging
9. Ship products to retailers
10. Monitor scans in real-time via Dashboard
```

### Workflow 2: Consumer Verifies Product at Point of Purchase
```
1. Consumer opens AuthentiChain app
2. Tap "Scan" → Camera opens
3. Point at QR code on product packaging
4. App scans → Calls /verify/scan endpoint
5. Backend checks verification_codes table
6. Returns: is_authentic, product_details, scan_count
7. App displays results (✓ Authentic or ✗ Counterfeit)
8. Consumer shares verification link (optional)
```

### Workflow 3: Consumer Reports a Fake
```
1. Consumer scans suspicious product
2. Results show ✗ Unregistered / Counterfeit
3. Click "Report This Product"
4. Modal opens → Fill form (where found, platform, photos)
5. Submit → Report logged in counterfeit_reports table
6. Manufacturer notified via Dashboard
7. Manufacturer marks "Verified Counterfeit" → creates takedown
```

### Workflow 4: Seller Bulk Verifies Inventory Before FBA Upload
```
1. Seller logs in as 'consumer' or 'seller' role
2. Tap "Bulk Verify" section
3. Upload CSV with product codes (or paste codes)
4. App validates each code → Calls /verify/scan for each
5. Shows progress: "Verifying 100 codes... 45/100 complete"
6. Once done, generates Authenticity Report PDF
7. Seller downloads PDF → Submits to Amazon/eBay in dispute
8. Report includes timestamp, % verified, unregistered items flagged
```

---

## PART 6: SECURITY & COMPLIANCE

### Authentication
- JWT tokens (24-hour expiry)
- Refresh tokens (30-day expiry, stored in HttpOnly cookies)
- Password hashing: bcrypt (10 rounds minimum)
- CORS: Whitelist frontend domain

### QR Code Encryption
- Store: `HMAC-SHA256(product_id + timestamp + secret_key)`
- On scan: Verify HMAC before returning product info
- Prevent: Reverse-engineering by adding timestamp to QR data

### Rate Limiting
- Per IP: 100 requests/minute (general)
- Per IP: 1,000 scans/minute (prevent scanning farm exploits)
- Alert: Flag >100 scans of same code in <1 minute as suspicious

### Data Privacy
- GDPR Compliance: PII deletion (user request)
- Geolocation data: Anonymize after 90 days (keep only country-level)
- No storage: Credit card details (use Stripe for payments)
- Audit logs: All manufacturer actions logged

### Fraud Prevention
- Email verification: Confirm email before manufacturer signup
- KYC for manufacturers: Name + address (Phase 2, required for >10k codes/month)
- Dispute resolution: Manual review for Brand Disputes, False Reports

---

## PART 7: MVP FEATURE PRIORITY & PHASING

### Week 1–2: Backend Foundation
- Set up DB (PostgreSQL)
- User auth (JWT + signup/login)
- Manufacturer CRUD endpoints
- Product CRUD endpoints
- QR code generation library integration

### Week 3–4: Core Scan Functionality
- Verification code generation & storage
- /verify/scan endpoint (return product info + scan count)
- Scan event logging (geolocation, device type, IP)
- Real-time scan count updates (Redis cache)

### Week 5–6: Manufacturer Dashboard UI
- React setup, authentication flow
- Product management page (list, create, edit)
- QR code generation & download (CSV + PNG ZIP)
- Basic analytics dashboard (total scans, trend chart)

### Week 7–8: Consumer App UI
- QR scanner (jsQR library)
- Verification results page (authentic/counterfeit/unregistered)
- Report fake modal
- Mobile responsiveness

### Week 9–10: Integration & Features
- WebSocket setup for real-time notifications (optional for MVP, can be polling)
- Counterfeit reports workflow
- Seller bulk verification & PDF generation
- Subscription tier enforcement (free vs. paid tag limits)

### Week 11–12: Testing, Launch Prep & Refinement
- E2E testing (Cypress or Playwright)
- Security audit (OWASP Top 10)
- Load testing (50k scans/day simulation)
- Documentation & API spec (Swagger)
- Pilot manufacturer onboarding
- Final bug fixes & polishing

---

## PART 8: DEPLOYMENT & LAUNCH CHECKLIST

### Pre-Launch (Week 12)
- [ ] All 3 core endpoints tested (auth, verify, products)
- [ ] Database backups automated (daily)
- [ ] Frontend deployed & accessible
- [ ] SSL/TLS enabled (HTTPS everywhere)
- [ ] Error logging (Sentry) integrated
- [ ] Analytics (Mixpanel) tracking enabled
- [ ] Terms of Service & Privacy Policy published
- [ ] Support email set up (support@authenchain.io)
- [ ] 5–10 pilot manufacturers onboarded & testing
- [ ] 100% uptime SLA target confirmed (99.9% acceptable for MVP)

### Launch Day
- [ ] Announce to pilot manufacturers
- [ ] Monitor error logs & database performance
- [ ] Have on-call support team ready
- [ ] Post-launch survey sent to early users

### Post-Launch (Week 13+)
- [ ] Weekly feature updates (based on user feedback)
- [ ] Monthly security patches
- [ ] Quarterly load & performance testing
- [ ] Competitive monitoring (Blockchain solutions, platform tools)

---

## PART 9: SUCCESS CRITERIA (12 WEEKS POST-LAUNCH)

### Technical
- ✓ 99.9% uptime
- ✓ Scan verification <2 seconds
- ✓ 50k scans/day capacity without degradation
- ✓ Zero security breaches / data leaks
- ✓ <1% false positive rate (authentic flagged as counterfeit)

### Business
- ✓ 50+ manufacturers onboarded
- ✓ 100k+ consumer app downloads/users
- ✓ 1M+ scans generated (cumulative)
- ✓ 500+ counterfeit reports (enabling takedowns)
- ✓ 3+ pilot e-commerce platform integration conversations initiated

### User Experience
- ✓ 45+ NPS (manufacturer feedback)
- ✓ 25%+ retention (30-day consumer app)
- ✓ <5 min average manufacturer onboarding time
- ✓ 0 critical bugs (production)

---

## PART 10: COMMON MISTAKES TO AVOID

### ❌ Architecture
- **Mistake:** Using NoSQL (MongoDB) for relational data (users, products, codes).
  - **Fix:** Use PostgreSQL; relational integrity matters here.

- **Mistake:** Storing QR code images in database as BLOBs.
  - **Fix:** Generate on-the-fly or store in S3; serve from CDN.

- **Mistake:** No geolocation indexing; analytics queries timeout.
  - **Fix:** Use PostGIS for PostgreSQL; index POINT columns.

### ❌ Security
- **Mistake:** Storing API keys in plaintext.
  - **Fix:** Hash API keys (bcrypt); only show once at creation.

- **Mistake:** QR codes not encrypted; counterfeiters clone codes.
  - **Fix:** HMAC-SHA256 signature in QR; verify before responding.

- **Mistake:** No rate limiting; botfarm scans legitimate codes 10k times/min.
  - **Fix:** Rate limit by IP (1k scans/min max); flag suspicious patterns.

### ❌ Product
- **Mistake:** Launching with only unregistered product codes show "Counterfeit."
  - **Fix:** Show "Unregistered (Brand not yet on AuthentiChain)" to avoid user confusion.

- **Mistake:** No manufacturer onboarding guide; users lost.
  - **Fix:** In-app 3-step wizard (company info → add product → generate codes).

- **Mistake:** Bulk code download as plain text; users can't print with QR images.
  - **Fix:** Provide CSV + PNG ZIP; show sample label layout.

### ❌ Scaling
- **Mistake:** Calculating scan counts in real-time (SELECT COUNT(*) every scan).
  - **Fix:** Cache in Redis; increment atomically; sync to DB every minute.

- **Mistake:** Uploading all QR images to S3 at once; timeout.
  - **Fix:** Generate QR images asynchronously; queue with Bull or Celery.

- **Mistake:** Analytics dashboard queries scan_events table directly; slow.
  - **Fix:** Maintain scan_results cache table; pre-aggregate (hourly).

### ❌ UX
- **Mistake:** Scanner requires perfect QR alignment; user frustration.
  - **Fix:** Use jsQR with high tolerance; show "Move closer/steadier" hints.

- **Mistake:** No fallback if camera permission denied.
  - **Fix:** Allow image upload as alternative method.

- **Mistake:** Report a fake form loses data on page refresh.
  - **Fix:** Auto-save form data to localStorage; clear on successful submit.

---

## PART 11: TECH TEAM CHECKLIST

### Before You Start Coding
- [ ] Agree on Node.js vs. Python (recommend Node.js for speed, Python for data science later)
- [ ] Set up GitHub repo with `.gitignore`, branch protection
- [ ] Create Docker setup for local dev (Dockerfile, docker-compose.yml)
- [ ] Define API response schema (JSON format, error codes)
- [ ] Create Figma design for all pages (link here: ___)
- [ ] Set up Slack/Discord for team comms
- [ ] Reserve domain + SSL cert

### Backend Dev Checklist
- [ ] PostgreSQL schema + migrations (Flyway or Alembic)
- [ ] Redis connection pool
- [ ] JWT middleware
- [ ] QR code generation library (test with sample codes)
- [ ] File upload to S3 (test with sample images)
- [ ] Email service (SendGrid/Mailgun for transactional emails)
- [ ] Logging (Winston or Python logging)
- [ ] Unit tests (Jest for Node, pytest for Python) - aim for 70%+ coverage
- [ ] API documentation (Swagger/OpenAPI)

### Frontend Dev Checklist
- [ ] React project setup (Create React App or Vite)
- [ ] Routing (React Router v6+)
- [ ] State management (Redux Toolkit or Zustand)
- [ ] UI component library (Tailwind CSS, Material-UI, or Shadcn)
- [ ] QR scanner library (jsQR or react-qr-reader)
- [ ] Chart library (Recharts for analytics)
- [ ] Mobile responsiveness (test on iPhone, Android)
- [ ] Accessibility (WCAG 2.1 AA standard)
- [ ] Unit & integration tests (React Testing Library) - aim for 60%+ coverage

### DevOps Checklist
- [ ] AWS account setup (EC2, S3, RDS, CloudFront)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Database backups (automated daily)
- [ ] Error tracking (Sentry)
- [ ] Monitoring & alerting (CloudWatch, DataDog)
- [ ] DNS & SSL (Let's Encrypt or AWS Certificate Manager)
- [ ] Load testing setup (k6 or JMeter)

---

## SUMMARY: BUILD EXACTLY THIS, NOT MORE

**Build:**
1. Manufacturer dashboard (products, code generation, analytics)
2. Consumer app (QR scanner, verify results, report fakes)
3. Brand analytics (scan data, heatmaps, counterfeit alerts)
4. Seller bulk verification (batch scan → PDF report)

**Don't Build:**
- ❌ NFC scanning (QR only for MVP)
- ❌ Blockchain integration (Phase 3)
- ❌ Platform APIs (eBay, Amazon) (Phase 2)
- ❌ Subscription payment processing (Phase 2; use Stripe later)
- ❌ Complex supply chain transparency (Phase 3)
- ❌ Mobile native apps (Phase 2; React web + responsive is fine)
- ❌ AI counterfeit detection (Phase 2)

**Ship in 12 weeks. Iterate based on user feedback.**
