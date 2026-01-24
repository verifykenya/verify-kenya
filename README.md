# AuthentiChain

**Anti-Counterfeit Product Verification Platform**

> Scan a QR code. Verify authenticity instantly. Protect your supply chain.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-green.svg)](https://www.python.org/)
[![Django](https://img.shields.io/badge/django-4.2-darkgreen.svg)](https://www.djangoproject.com/)
[![PostgreSQL](https://img.shields.io/badge/postgresql-15+-blue.svg)](https://www.postgresql.org/)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)](#production-readiness)

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Architecture](#architecture)
4. [API Documentation](#api-documentation)
5. [Security & Compliance](#security--compliance)
6. [Installation](#installation)
7. [Configuration](#configuration)
8. [Usage](#usage)
9. [Testing](#testing)
10. [Deployment](#deployment)
11. [Troubleshooting](#troubleshooting)
12. [Contributing](#contributing)
13. [License](#license)

---

## Overview

### What is AuthentiChain?

AuthentiChain is a **B2B2C (Business-to-Business-to-Consumer) product verification platform** that enables manufacturers to combat counterfeit goods by embedding secure QR codes into products. Consumers and sellers can instantly verify authenticity by scanning the code.

### Key Features

- **Instant Verification**: Scan QR → Get authenticity result in <2 seconds
- **Manufacturer Dashboard**: Manage products, generate codes, track scans, monitor counterfeits
- **Consumer App**: Simple, frictionless verification (no signup required)
- **Counterfeit Reporting**: Report fakes, enable takedowns, prevent sales
- **Real-Time Analytics**: Heatmaps, scan trends, counterfeit patterns
- **Enterprise Security**: OWASP Top 10 compliant, GDPR/CCPA ready, AES-256 encryption
- **Scalable Infrastructure**: 100k+ scans/day, Redis caching, async task processing

### Use Cases

✅ **Luxury Goods** (watches, bags, jewelry)  
✅ **Pharmaceuticals** (medications, supplements)  
✅ **Electronics** (processors, memory chips)  
✅ **Beauty & Personal Care** (skincare, cosmetics)  
✅ **Apparel** (designer clothing, sneakers)

---

## Quick Start

### For Consumers (Verification Only)

```bash
# 1. Visit web app
https://app.authenchain.io

# 2. Open camera
Click "Scan Product"

# 3. Point at QR code
Auto-scans (no manual input needed)

# 4. Get result
Authentic ✓ | Counterfeit ✗ | Unregistered ?
```

**Time to verify**: <30 seconds  
**No signup required** ✓

### For Manufacturers (Dashboard)

```bash
# 1. Sign up at
https://authenchain.io/signup

# 2. Add your products
Name, SKU, category, image

# 3. Generate QR codes
Bulk generate → Download CSV + PNG files

# 4. Print on packaging
Integrate into manufacturing workflow

# 5. Monitor scans
Real-time dashboard, analytics, counterfeit alerts
```

**Time to setup**: <15 minutes  
**No technical expertise required** ✓

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     AuthentiChain MVP                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐         ┌──────────────┐                 │
│  │  Consumer    │         │ Manufacturer │                 │
│  │  Web App     │         │   Dashboard  │                 │
│  │  (React)     │         │   (React)    │                 │
│  └──────┬───────┘         └──────┬───────┘                 │
│         │                        │                          │
│         └────────────┬───────────┘                          │
│                      │                                      │
│                      ▼                                      │
│         ┌────────────────────────┐                         │
│         │   REST API (DRF)       │                         │
│         │   /api/verify/scan     │                         │
│         │   /api/products        │                         │
│         │   /api/reports         │                         │
│         │   /api/analytics       │                         │
│         └────────┬───────────────┘                         │
│                  │                                         │
│         ┌────────┴──────────────────────┐                 │
│         │                               │                 │
│    ┌────▼────────┐          ┌──────────▼──────┐           │
│    │  PostgreSQL │          │  Redis Cache    │           │
│    │  Database   │          │  (Sessions)     │           │
│    └─────────────┘          └─────────────────┘           │
│                                                             │
│    ┌─────────────────────────────────────────┐            │
│    │  Celery Task Queue (Async Processing)   │            │
│    │  - Code generation                      │            │
│    │  - Notifications (email)                │            │
│    │  - Scan aggregation                     │            │
│    └─────────────────────────────────────────┘            │
│                                                             │
│    ┌─────────────────────────────────────────┐            │
│    │  AWS S3 (File Storage)                  │            │
│    │  - Product images                       │            │
│    │  - QR code downloads                    │            │
│    │  - Evidence uploads                     │            │
│    └─────────────────────────────────────────┘            │
│                                                             │
│    ┌─────────────────────────────────────────┐            │
│    │  Third-Party Services                   │            │
│    │  - Sentry (error tracking)              │            │
│    │  - SendGrid (email)                     │            │
│    │  - Stripe (payments, future)            │            │
│    └─────────────────────────────────────────┘            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| **Backend Framework** | Django | 4.2.8 |
| **API** | Django REST Framework | 3.14.0 |
| **Database** | PostgreSQL | 15+ |
| **Cache** | Redis | 7.0+ |
| **Task Queue** | Celery | 5.3.4 |
| **File Storage** | AWS S3 | Latest |
| **Frontend** | React 18 | 18.2+ |
| **QR Code** | qrcode-python | 7.4.2 |
| **Security** | cryptography | 41.0.7 |
| **Error Tracking** | Sentry | 1.39.1 |
| **Email** | SendGrid | Latest |

### Database Schema

```
Users
├── id (UUID)
├── email (unique)
├── password_hash
├── user_type (manufacturer | consumer | brand_admin)
├── email_verified
├── marketing_consent
└── created_at

Manufacturers
├── id (UUID)
├── user_id (FK → Users)
├── company_name
├── industry
├── country
├── subscription_tier (free | starter | pro)
└── status (active | suspended | trial)

Products
├── id (UUID)
├── manufacturer_id (FK → Manufacturers)
├── sku (unique per manufacturer)
├── name
├── category
├── image_url
└── authorized_channels (JSON array)

VerificationCodes
├── id (UUID)
├── product_id (FK → Products)
├── code_value (unique, encrypted)
├── batch_number (encrypted)
├── serial_number
├── manufacture_date
├── destination_retailer
├── status (active | deactivated)
└── created_at

Scans
├── id (UUID)
├── code_id (FK → VerificationCodes)
├── user_id (FK → Users, nullable)
├── scan_timestamp
├── geolocation_hash (privacy-preserving)
├── device_type (mobile | web)
├── ip_address
└── scan_source (app | web | sms)

CounterfeitReports
├── id (UUID)
├── code_id (FK → VerificationCodes)
├── reporter_id (FK → Users)
├── report_reason
├── report_evidence_url
├── platform_listed_on
├── listing_url
├── status (pending | verified | false_positive | takedown_initiated)
└── created_at

AuditLogs
├── id (UUID)
├── user_id (FK → Users, nullable)
├── action
├── entity_type
├── entity_id
├── old_values (JSON)
├── new_values (JSON)
├── ip_address
└── timestamp
```

---

## API Documentation

### Authentication

All protected endpoints require JWT bearer token:

```bash
Authorization: Bearer <access_token>
```

### Core Endpoints

#### 1. User Registration

```http
POST /api/auth/signup
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "user_type": "manufacturer",
  "company_name": "My Brand" (optional, for manufacturers)
}

Response (201 Created):
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "user_type": "manufacturer"
}
```

#### 2. User Login

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

Response (200 OK):
{
  "access": "eyJhbGc...",
  "refresh": "eyJhbGc...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com"
  }
}
```

#### 3. Verify Product (Core Feature)

```http
POST /api/verify/scan
Content-Type: application/json

{
  "code_value": "product-id:timestamp:signature",
  "latitude": 0.3149,
  "longitude": 51.5290,
  "device_type": "mobile"
}

Response (200 OK):
{
  "is_authentic": true,
  "status": "verified",
  "product": {
    "name": "Luxury Watch Pro",
    "sku": "LW-PRO-001",
    "category": "Luxury Goods"
  },
  "batch": "BATCH-2024-001",
  "manufacturer": "Acme Luxury Brands",
  "scan_count": 1250
}

OR

{
  "is_authentic": false,
  "status": "counterfeit",
  "reason": "This QR code has been marked as counterfeit"
}

OR

{
  "is_authentic": false,
  "status": "unregistered",
  "reason": "This product is not registered in our system"
}
```

#### 4. Create Product (Manufacturer)

```http
POST /api/products/
Authorization: Bearer <token>
Content-Type: application/json

{
  "manufacturer": "550e8400-e29b-41d4-a716-446655440000",
  "sku": "LW-PRO-001",
  "name": "Luxury Watch Pro",
  "category": "Watches",
  "description": "Premium Swiss movement",
  "authorized_channels": ["Amazon", "Official Store", "Authorized Retailers"]
}

Response (201 Created):
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "sku": "LW-PRO-001",
  "name": "Luxury Watch Pro",
  ...
}
```

#### 5. Generate QR Codes (Manufacturer)

```http
POST /api/products/{product_id}/generate-codes/
Authorization: Bearer <token>
Content-Type: application/json

{
  "quantity": 1000,
  "batch_number": "BATCH-2024-001",
  "manufacture_date": "2024-01-15",
  "destination_retailer": "Amazon"
}

Response (202 Accepted):
{
  "success": true,
  "job_id": "550e8400-e29b-41d4-a716-446655440002",
  "status": "queued",
  "estimated_wait_seconds": 60,
  "message": "Code generation queued. Check status with job_id."
}
```

#### 6. Report Counterfeit

```http
POST /api/reports/create/
Content-Type: application/json

{
  "code": "550e8400-e29b-41d4-a716-446655440001",
  "report_reason": "Product appears to be counterfeit based on packaging quality",
  "platform_listed_on": "Amazon",
  "listing_url": "https://amazon.com/...",
  "report_evidence_url": "https://s3.amazonaws.com/..." (optional)
}

Response (201 Created):
{
  "id": "550e8400-e29b-41d4-a716-446655440003",
  "code": "550e8400-e29b-41d4-a716-446655440001",
  "status": "pending",
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### 7. Analytics Dashboard (Manufacturer)

```http
GET /api/manufacturers/{manufacturer_id}/analytics/
Authorization: Bearer <token>

Response (200 OK):
{
  "total_scans": 50000,
  "scans_this_month": 12000,
  "unique_scanners": 8000,
  "growth_percent": 15,
  "counterfeits_reported": 45,
  "counterfeits_verified": 38,
  "top_products": [
    {
      "id": "550e8400...",
      "name": "Luxury Watch Pro",
      "scan_count": 5000
    }
  ],
  "geographic_distribution": [
    {
      "latitude": 51.5074,
      "longitude": -0.1278,
      "scan_count": 150,
      "city": "London"
    }
  ]
}
```

### Rate Limiting

| Endpoint | Limit |
|----------|-------|
| `/api/verify/scan` | 2,000 requests/minute |
| `auth/login` | 5 attempts/15 minutes |
| `/api/reports/create` | 10 reports/hour |
| Other endpoints | 100 requests/minute |

---

## Security & Compliance

### OWASP Top 10 Compliance

✅ **A01:2021 – Broken Access Control**
- RBAC on all endpoints
- Object-level permissions (ownership checks)
- Cannot access other manufacturers' data

✅ **A02:2021 – Cryptographic Failures**
- AES-256-GCM encryption for batch secrets
- HMAC-SHA256 signatures for QR codes
- TLS 1.3 for all traffic
- Encrypted database columns for sensitive data

✅ **A03:2021 – Injection**
- Parameterized queries (Django ORM)
- Input validation on all endpoints
- No raw SQL or command execution

✅ **A07:2021 – Identification and Authentication Failures**
- JWT tokens with 24h expiry + 30d refresh
- Token blacklist on logout
- Strong password policy (8+ chars, uppercase, number, special)
- Brute force protection (5 attempts/15 min)

✅ **A09:2021 – Logging and Monitoring**
- Structured JSON logging
- Audit logs for all material actions
- No PII in logs (redacted before Sentry)

### GDPR Compliance

✅ **Article 32 – Security**
- Data encryption at rest & in transit
- Geolocation privacy (hashing, not coordinates)
- Access control & authentication
- Regular security testing

✅ **Article 17 – Right to Erasure**
- User deletion endpoint
- Soft delete with 30-day grace period
- Data anonymization

✅ **Article 33-34 – Breach Notification**
- Incident response plan
- 72-hour notification mechanism
- Breach impact assessment

### CCPA Compliance

✅ **Consumer Rights**
- Right to access personal data
- Right to delete personal data
- Right to opt-out of data sales
- Do Not Sell My Data link (footer)

✅ **Service Provider Agreements**
- AWS, SendGrid, Stripe have CCPA addendums

### Data Retention Policy

| Data Type | Retention | Auto-Delete |
|-----------|-----------|------------|
| Geolocation scans | 90 days | Yes |
| Scan events | 1 year | Manual review |
| User audit logs | 2 years | Yes |
| Account data | Until deletion request | User-initiated |

---

## Installation

### Prerequisites

- **Python 3.11+**
- **PostgreSQL 15+**
- **Redis 7.0+**
- **Node.js 18+** (for frontend)
- **Git**

### Backend Setup

```bash
# 1. Clone repository
git clone https://github.com/authenchain/backend.git
cd backend

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment file
cp .env.example .env
# Edit .env with your secrets

# 5. Run migrations
python manage.py migrate

# 6. Create superuser
python manage.py createsuperuser

# 7. Collect static files
python manage.py collectstatic --noinput

# 8. Run tests
python manage.py test

# 9. Start development server
python manage.py runserver

# 10. In separate terminal, start Celery worker
celery -A config worker -l info
```

### Frontend Setup

```bash
# 1. Clone repository
git clone https://github.com/authenchain/frontend.git
cd frontend

# 2. Install dependencies
npm install

# 3. Create .env file
cp .env.example .env
# Edit with API endpoint: REACT_APP_API_URL=http://localhost:8000/api

# 4. Start development server
npm start
# Opens at http://localhost:3000
```

### Docker Setup (Recommended for Production)

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# Run migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Verify running
docker-compose ps
```

---

## Configuration

### Environment Variables

Create `.env` file in project root:

```bash
# Django
DJANGO_SECRET_KEY=your-secret-key-min-50-chars
DEBUG=False
ALLOWED_HOSTS=authenchain.io,api.authenchain.io
ENVIRONMENT=production

# Database
DB_ENGINE=django.db.backends.postgresql
DB_NAME=authenchain_prod
DB_USER=authenchain_user
DB_PASSWORD=your-db-password
DB_HOST=postgres.example.com
DB_PORT=5432

# Redis
REDIS_URL=redis://:password@redis.example.com:6379/0

# AWS S3
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_STORAGE_BUCKET_NAME=authenchain-prod
AWS_S3_REGION_NAME=us-east-1

# JWT & Security
JWT_SECRET=your-jwt-secret-min-50-chars
HMAC_SECRET=your-hmac-secret-min-50-chars
ENCRYPTION_KEY=your-fernet-key

# Email
SENDGRID_API_KEY=SG.xxxxxxxxxxxxx
SENDER_EMAIL=noreply@authenchain.io

# Error Tracking
SENTRY_DSN=https://xxxxx@sentry.io/12345

# Frontend
FRONTEND_URL=https://app.authenchain.io
CORS_ALLOWED_ORIGINS=https://app.authenchain.io

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/authenchain/app.log
```

### Celery Configuration

```python
# config/celery.py

import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('authenchain')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
```

---

## Usage

### For Manufacturers

#### 1. Register & Setup

```bash
# Visit https://authenchain.io/signup
# Enter: email, password, company name, industry, country
```

#### 2. Add Products

```bash
# Dashboard → Products → Add Product
# Fill in: SKU, name, category, description, image, authorized channels
```

#### 3. Generate QR Codes

```bash
# Products → [Your Product] → Generate Codes
# Enter: quantity, batch number, manufacture date, destination retailer
# Download CSV + PNG files
# Integrate into production (print on packaging, labels, etc.)
```

#### 4. Monitor Scans

```bash
# Dashboard → Analytics
# View: Daily scans, scan locations, counterfeit reports
# Set alerts for unusual patterns
```

#### 5. Handle Counterfeits

```bash
# Reports → Verified Counterfeits
# Review evidence, confirm counterfeit status
# Initiate takedown requests (Amazon, eBay, etc.)
```

### For Consumers

#### 1. Scan Product

```bash
# Open https://app.authenchain.io
# Click "Scan Product"
# Point camera at QR code
# Auto-scans in <2 seconds
```

#### 2. View Result

```bash
# Get instant result: Authentic ✓ | Counterfeit ✗ | Unregistered ?
# See product details, manufacturer, scan count
```

#### 3. Report Issue

```bash
# If result seems wrong: Click "Report a Problem"
# Describe issue, provide evidence
# Helps improve our database
```

#### 4. Share Verification

```bash
# Click "Share Verification"
# Get shareable link (proof of authenticity for disputes)
```

---

## Testing

### Unit Tests

```bash
# Run all tests
python manage.py test

# Run specific test class
python manage.py test authenchain.tests.VerificationTestCase

# Run with coverage
coverage run --source='authenchain' manage.py test
coverage report
coverage html  # Generate HTML report
```

### Test Examples

```python
# authenchain/tests.py

from django.test import TestCase, Client
from .models import User, Product, VerificationCode
from .security import QRCodeGenerator

class VerificationTestCase(TestCase):
    
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecurePass123!'
        )
    
    def test_qr_generation(self):
        """Test QR code generation"""
        qr_data = QRCodeGenerator.generate_qr_data('test-product')
        self.assertIsNotNone(qr_data)
    
    def test_qr_tamper_detection(self):
        """Test tampered QR codes rejected"""
        qr_data = QRCodeGenerator.generate_qr_data('test-product')
        tampered = qr_data[:-5] + 'xxxxx'
        self.assertFalse(QRCodeGenerator.verify_qr_data(tampered)['valid'])
    
    def test_login_rate_limiting(self):
        """Test brute force protection"""
        for i in range(10):
            self.client.post('/api/auth/login', {
                'email': 'test@example.com',
                'password': 'wrong'
            })
        # After 5 attempts, rate limit kicks in
        response = self.client.post('/api/auth/login', {...})
        self.assertGreaterEqual(response.status_code, 429)
```

### Load Testing

```bash
# Using k6 (https://k6.io)

# Create test script: load-test.js
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: 100,  // 100 virtual users
  duration: '30s',
};

export default function () {
  const res = http.post('http://localhost:8000/api/verify/scan', {
    code_value: 'test-code',
    latitude: 0.0,
    longitude: 0.0,
  });
  
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
}

# Run test
k6 run load-test.js
```

---

## Deployment

### AWS EC2 Deployment

```bash
# 1. Launch EC2 instance
# - Type: t3.medium
# - OS: Ubuntu 22.04 LTS
# - Storage: 30GB

# 2. SSH into instance
ssh -i key.pem ubuntu@ec2-instance.amazonaws.com

# 3. Install dependencies
sudo apt update && sudo apt install -y python3.11 python3.11-venv postgresql postgresql-contrib redis-server nginx

# 4. Clone repository
git clone https://github.com/authenchain/backend.git
cd backend

# 5. Setup virtual environment
python3.11 -m venv venv
source venv/bin/activate

# 6. Install Python dependencies
pip install -r requirements.txt

# 7. Configure environment
sudo nano /etc/environment
# Add: DB_PASSWORD, JWT_SECRET, AWS_KEYS, etc.

# 8. Run migrations
python manage.py migrate

# 9. Collect static files
python manage.py collectstatic --noinput

# 10. Create systemd service
sudo nano /etc/systemd/system/authenchain.service

[Unit]
Description=AuthentiChain Django Application
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/backend
Environment="PATH=/home/ubuntu/backend/venv/bin"
ExecStart=/home/ubuntu/backend/venv/bin/gunicorn config.wsgi:application --bind 0.0.0.0:8000
Restart=always

[Install]
WantedBy=multi-user.target

# 11. Start service
sudo systemctl daemon-reload
sudo systemctl enable authenchain
sudo systemctl start authenchain

# 12. Configure Nginx
sudo nano /etc/nginx/sites-available/authenchain

upstream authenchain {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name api.authenchain.io;

    location / {
        proxy_pass http://authenchain;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

# 13. Enable Nginx
sudo ln -s /etc/nginx/sites-available/authenchain /etc/nginx/sites-enabled/
sudo systemctl restart nginx

# 14. Enable SSL (Let's Encrypt)
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d api.authenchain.io
```

### Docker Deployment

```bash
# Build production image
docker build -t authenchain:latest .

# Push to registry
docker tag authenchain:latest 123456789.dkr.ecr.us-east-1.amazonaws.com/authenchain:latest
docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/authenchain:latest

# Deploy to ECS
aws ecs update-service --cluster authenchain-prod --service authenchain-web --force-new-deployment
```

### Kubernetes Deployment

```bash
# Create namespace
kubectl create namespace authenchain

# Deploy Django app
kubectl apply -f k8s/django-deployment.yaml -n authenchain

# Deploy PostgreSQL
kubectl apply -f k8s/postgres-deployment.yaml -n authenchain

# Deploy Redis
kubectl apply -f k8s/redis-deployment.yaml -n authenchain

# Check status
kubectl get pods -n authenchain
kubectl logs -f deployment/authenchain-web -n authenchain
```

---

## Troubleshooting

### Common Issues

#### Issue: "Database connection refused"

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Connect to verify
psql -h localhost -U authenchain_user -d authenchain_prod

# If connection fails, check .env variables
grep DB_ .env
```

#### Issue: "Redis connection timeout"

```bash
# Check Redis is running
redis-cli ping
# Should return: PONG

# If not running
sudo systemctl start redis-server

# Check configuration
redis-cli CONFIG GET "*"
```

#### Issue: "QR code generation fails"

```bash
# Check image processing library
python -c "import qrcode; print(qrcode.__version__)"

# Reinstall if needed
pip install --upgrade qrcode[pil]
```

#### Issue: "Email not sending"

```bash
# Verify SendGrid API key
grep SENDGRID .env

# Test email sending
python manage.py shell
>>> from django.core.mail import send_mail
>>> send_mail('Test', 'Body', 'from@example.com', ['to@example.com'])

# Check Sentry for errors
# Dashboard → Issues → Email errors
```

#### Issue: "S3 uploads failing"

```bash
# Verify AWS credentials
grep AWS .env

# Test S3 connection
python manage.py shell
>>> import boto3
>>> s3 = boto3.client('s3')
>>> s3.head_bucket(Bucket='authenchain-prod')

# Check bucket permissions
aws s3api get-bucket-policy --bucket authenchain-prod
```

### Performance Optimization

```python
# Enable query optimization
DATABASES = {
    'default': {
        ...
        'CONN_MAX_AGE': 600,  # Connection pooling
        'OPTIONS': {
            'connect_timeout': 10,
        }
    }
}

# Use select_related for JOINs
codes = VerificationCode.objects.select_related('product__manufacturer')

# Use only() to reduce fields
users = User.objects.only('email', 'id')

# Add database indexes
class Meta:
    indexes = [
        models.Index(fields=['code_value']),
        models.Index(fields=['status', 'created_at']),
    ]
```

---

## Contributing

### Getting Started

```bash
# 1. Fork repository
# 2. Create feature branch
git checkout -b feature/my-feature

# 3. Make changes
# 4. Run tests
python manage.py test

# 5. Lint code
flake8 authenchain/
black authenchain/

# 6. Commit
git commit -m "feat: add my feature"

# 7. Push & create PR
git push origin feature/my-feature
```

### Code Style

- **Python:** PEP 8 (enforced with Black, Flake8)
- **SQL:** No raw SQL (use Django ORM)
- **Git Commits:** Conventional Commits (feat:, fix:, docs:, etc.)
- **Documentation:** Docstrings on all functions/classes

### Pull Request Process

1. Update `CHANGELOG.md`
2. Add tests for new features
3. Ensure all tests pass: `python manage.py test`
4. Update documentation
5. Get code review approval
6. Merge to main

### Reporting Bugs

```bash
# Security vulnerabilities: security@authenchain.io
# Other issues: GitHub Issues with template

## Describe the bug
[Description]

## Reproduce
[Steps to reproduce]

## Expected behavior
[What should happen]

## Environment
- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.11.0]
- Django: [e.g., 4.2.8]
```

---

## Production Readiness Checklist

Before launching to production, verify:

### Security
- [ ] All secrets in environment variables (no hardcoding)
- [ ] HTTPS enabled (TLS 1.3)
- [ ] CORS configured for specific domains only
- [ ] Rate limiting enabled
- [ ] Input validation on all endpoints
- [ ] OWASP Top 10 audit completed
- [ ] Penetration testing completed
- [ ] Secrets scanning enabled (git-secrets, Snyk)

### Compliance
- [ ] Privacy Policy published
- [ ] Terms of Service published
- [ ] GDPR Data Processing Agreement signed (if EU users)
- [ ] CCPA Do Not Sell link visible
- [ ] Legal disclaimer on verification results
- [ ] Incident response plan documented
- [ ] Data retention policy implemented

### Performance
- [ ] Database indexes created
- [ ] Connection pooling configured
- [ ] Redis caching enabled
- [ ] Celery workers scaled
- [ ] CDN configured for static files
- [ ] Load testing passed (100k+ requests/hour)
- [ ] Database backup automated (daily)

### Operations
- [ ] Monitoring configured (CloudWatch, DataDog, New Relic)
- [ ] Alerting configured (email, Slack, PagerDuty)
- [ ] Logging centralized (ELK, Splunk, Sumo Logic)
- [ ] Error tracking enabled (Sentry)
- [ ] Runbooks documented
- [ ] On-call rotation established
- [ ] Disaster recovery plan tested

### Quality
- [ ] Test coverage >80%
- [ ] Code reviewed
- [ ] Staging environment mirrors production
- [ ] Rollback procedure documented
- [ ] Blue-green deployment tested
- [ ] Database migration tested

---

## Support & Resources

### Documentation
- **API Docs:** https://docs.authenchain.io/api
- **Architecture Guide:** https://docs.authenchain.io/architecture
- **Security:** https://docs.authenchain.io/security
- **Deployment:** https://docs.authenchain.io/deployment

### Community
- **GitHub:** https://github.com/authenchain
- **Issues:** https://github.com/authenchain/backend/issues
- **Discussions:** https://github.com/authenchain/backend/discussions
- **Security:** security@authenchain.io

### Professional Support
- **Email:** support@authenchain.io
- **Response SLA:** 24 hours
- **Enterprise SLA:** 1 hour (with contract)

---

## Roadmap

### Phase 1: MVP (Current)
✅ Core verification  
✅ Manufacturer dashboard  
✅ Counterfeit reporting  
✅ Basic analytics  

### Phase 2: Q2 2024
🔄 Blockchain integration (Ethereum)  
🔄 Mobile native apps (iOS/Android)  
🔄 API key authentication (B2B integrations)  
🔄 Advanced fraud detection (ML)  

### Phase 3: Q3 2024
🔄 Supply chain transparency module  
🔄 Integration with major e-commerce platforms  
🔄 Automated takedown requests  
🔄 Premium reporting features  

### Phase 4: Q4 2024
🔄 International expansion (APAC, EU, LATAM)  
🔄 Regulatory compliance (pharma, auto, electronics)  
🔄 Enterprise SLA support  

---

## License

MIT License - see [LICENSE](LICENSE) for details.

```
Copyright (c) 2024 AuthentiChain Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## Acknowledgments

Built with ❤️ by the AuthentiChain team.

**Special thanks to:**
- Django & DRF communities
- OWASP for security guidance
- Our beta manufacturers & users

---

## Questions?

📧 Email: support@authenchain.io  
🐛 Issues: GitHub Issues  
💬 Discussions: GitHub Discussions  
🔒 Security: security@authenchain.io

---

**Last Updated:** January 2024  
**Version:** 1.0.0  
**Status:** Production Ready ✓
