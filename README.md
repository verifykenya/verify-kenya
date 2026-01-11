# WEEK 1: SETUP GUIDE & VALIDATION

## STEP 1: Environment Setup 

### 1.1 Create Project Structure
```bash
mkdir trust-app && cd trust-app
mkdir -p app/{domains/{users,merchants,products,transactions,idempotency,disputes},security,integrations,middleware,utils,email_templates}
mkdir -p migrations/versions
mkdir -p tests/{unit,integration}
mkdir -p docker
touch .env .env.example .gitignore requirements.txt
```

### 1.2 Create `.env.example` (COMMIT THIS, NOT .env)
```bash
# Database (AWS RDS or local PostgreSQL)
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/trust_app

# Security - GENERATE THESE SECURELY
JWT_SECRET=your-super-secret-key-min-32-chars-change-this
MASTER_ENCRYPTION_KEY=paste-32-byte-hex-here

# Paystack (from your merchant account)
PAYSTACK_SECRET_KEY=sk_test_xxxxx
PAYSTACK_PUBLIC_KEY=pk_test_xxxxx

# Environment
ENV=development
DEBUG=True
```

### 1.3 Generate Secure Keys
```python
# Run this ONCE to generate keys
import secrets
import os

# JWT Secret (min 32 bytes)
jwt_secret = secrets.token_urlsafe(32)
print(f"JWT_SECRET={jwt_secret}")

# Master encryption key (32 bytes for AES-256)
encryption_key = secrets.token_hex(16)  # 32 hex chars = 16 bytes (256 bits)
print(f"MASTER_ENCRYPTION_KEY={encryption_key}")
```

### 1.4 Install Dependencies
```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 1.5 Setup Local PostgreSQL
```bash
# On macOS (if using Homebrew)
brew install postgresql@15
brew services start postgresql@15

# Create database
createdb trust_app

# Create user (optional)
createuser -P trust_user
# Password: trust_password

# Connect and verify
psql -U postgres -d trust_app
\dt  # Should show empty (no tables yet)
\q   # Exit
```

---

## STEP 2: Initialize FastAPI App 
### 2.1 Create `app/main.py`
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from app.db import init_db, close_db
from app.config import get_settings

settings = get_settings()

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    logger.info("Initializing database...")
    await init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Closing database connections...")
    await close_db()
    logger.info("Goodbye")

app = FastAPI(
    title="Trust Layer Payment App",
    version="0.1.0",
    lifespan=lifespan
)

# CORS for development only
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend dev server
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}

# Routes will be imported here in Week 2
```

### 2.2 Create `app/__init__.py`
```python
__version__ = "0.1.0"
```

### 2.3 Test the app
```bash
cd trust-app
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Visit: `http://localhost:8000/health`
Expected response: `{"status":"ok","version":"0.1.0"}`

---

## STEP 3: Database Validation (Day 3)

### 3.1 Create Database from Models
```python
# File: create_tables.py
import asyncio
from app.db import init_db

async def main():
    await init_db()
    print("✅ Database tables created!")

if __name__ == "__main__":
    asyncio.run(main())
```

Run it:
```bash
python create_tables.py
```

### 3.2 Verify Tables Were Created
```bash
psql -d trust_app
\dt  # List tables

# Expected output:
# Schema |           Name            | Type  | Owner
# --------+---------------------------+-------+-------
#  public | users                     | table | user
#  public | merchant_profiles         | table | user
#  public | products                  | table | user
#  public | transactions              | table | user
#  public | idempotency_keys          | table | user
```

### 3.3 Verify Constraints & Indexes
```sql
-- Check constraints on transactions
\d transactions

-- Check indexes
SELECT indexname FROM pg_indexes WHERE tablename='transactions';

-- Expected indexes:
-- idx_transactions_merchant_id
-- idx_transactions_customer_id
-- idx_transactions_status
-- idx_transactions_status_date
-- idx_customer_merchant
```

### 3.4 Test ACID Properties
```python
# File: test_acid.py
import asyncio
from sqlalchemy import select
from app.db import async_session_maker
from app.domains.users.models import User
from app.security.password import PasswordSecurity

async def test_transaction_atomicity():
    """
    Test: If error occurs mid-transaction, entire transaction rolls back.
    """
    async with async_session_maker() as session:
        try:
            # Create user
            user1 = User(
                phone_number="+254712345678",
                email="test@example.com",
                password_hash=PasswordSecurity.hash_password("test123"),
                full_name="Test User",
            )
            session.add(user1)
            
            # Simulate error
            raise Exception("Network error!")
            
            await session.commit()
        except Exception as e:
            await session.rollback()
            print(f"❌ Transaction rolled back: {e}")
        
        # Verify user was NOT created (atomicity works)
        result = await session.execute(
            select(User).where(User.email == "test@example.com")
        )
        user = result.scalars().first()
        assert user is None, "User should not exist after rollback"
        print("✅ ACID atomicity works!")

if __name__ == "__main__":
    asyncio.run(test_transaction_atomicity())
```

Run it:
```bash
python test_acid.py
```

---

## STEP 4: Security Validation (Day 4)

### 4.1 Test Password Hashing
```python
# File: test_security.py
from app.security.password import PasswordSecurity

def test_password_hashing():
    password = "super_secret_123!"
    hashed = PasswordSecurity.hash_password(password)
    
    # Verify correct password works
    assert PasswordSecurity.verify_password(password, hashed)
    print("✅ Correct password verified")
    
    # Verify wrong password fails
    assert not PasswordSecurity.verify_password("wrong_password", hashed)
    print("✅ Wrong password rejected")
    
    # Verify hash is not plaintext
    assert password not in hashed
    print("✅ Password not stored in plaintext")

if __name__ == "__main__":
    test_password_hashing()
```

### 4.2 Test Encryption
```python
# File: test_encryption.py
from app.security.encryption import DataEncryption
from app.config import get_settings
import binascii

settings = get_settings()

def test_encryption():
    # Convert hex string to bytes
    master_key = binascii.unhexlify(settings.MASTER_ENCRYPTION_KEY)
    encryptor = DataEncryption(master_key)
    
    # Encrypt phone number
    phone = "+254712345678"
    user_id = "user123"
    encrypted = encryptor.encrypt_field(phone, user_id)
    print(f"Original: {phone}")
    print(f"Encrypted: {encrypted}")
    
    # Decrypt
    decrypted = encryptor.decrypt_field(encrypted, user_id)
    assert decrypted == phone
    print("✅ Encryption/decryption works")
    
    # Test tampering detection
    try:
        # Modify the ciphertext (simulating tampering)
        tampered = "wrong_nonce:wrong_cipher"
        encryptor.decrypt_field(tampered, user_id)
        assert False, "Should have failed"
    except Exception:
        print("✅ Tampering detected and rejected")

if __name__ == "__main__":
    test_encryption()
```

---

## STEP 5: Database Audit Logging (Optional - Phase 2)

For Phase 1, we're NOT using triggers. But here's what Week 2 will add:

```sql
-- Phase 2: Audit Schema
CREATE SCHEMA audit;

-- Audit table to track all changes
CREATE TABLE audit.logged_actions (
    event_id BIGSERIAL PRIMARY KEY,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    action TEXT NOT NULL,
    row_data JSONB,
    changed_fields JSONB,
    action_tstamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    user_name TEXT,
    transaction_id BIGINT,
    CHECK (action IN ('INSERT', 'UPDATE', 'DELETE'))
);

-- Trigger function to log changes
CREATE OR REPLACE FUNCTION audit.log_changes() RETURNS TRIGGER AS $audit$
BEGIN
    INSERT INTO audit.logged_actions (
        schema_name, table_name, action, row_data, user_name
    ) VALUES (
        TG_TABLE_SCHEMA,
        TG_TABLE_NAME,
        TG_OP,
        CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END,
        CURRENT_USER
    );
    RETURN NEW;
END;
$audit$ LANGUAGE plpgsql;

-- Attach trigger to transactions table
CREATE TRIGGER transactions_audit
AFTER INSERT OR UPDATE OR DELETE ON transactions
FOR EACH ROW EXECUTE FUNCTION audit.log_changes();
```

---

## CHECKLIST: Week 1 Complete When...

- [ ] `.env` file created with secure keys
- [ ] `requirements.txt` installed
- [ ] PostgreSQL running locally
- [ ] `python create_tables.py` runs without errors
- [ ] `\dt` in psql shows all 5 tables
- [ ] Health endpoint returns 200
- [ ] ACID test passes (rollback works)
- [ ] Password hashing test passes
- [ ] Encryption test passes
- [ ] All models follow constraints (CHECK constraints working)
- [ ] No PII logged anywhere
- [ ] `git commit` (except `.env`)

---

## CRITICAL POINTS FOR NEXT WEEK

1. **Schema is IMMUTABLE** - Never update production schema without migration
2. **Idempotency Keys** - Must check before creating any transaction
3. **Encryption Keys** - Must never log or expose
4. **Foreign Keys** - ON DELETE CASCADE means deleting user deletes all their data (intentional for GDPR compliance)
5. **Audit Trail** - We'll add triggers in Week 2 to auto-log all changes

---

## TROUBLESHOOTING

**Issue: `psql: error: FATAL: role "user" does not exist`**
Solution:
```bash
createuser -P trust_user
# When prompted for password: trust_password
# Update .env: DATABASE_URL=postgresql+asyncpg://trust_user:trust_password@localhost/trust_app
```

**Issue: `asyncpg.exceptions.InterfaceError: cannot connect to database`**
Solution:
```bash
# Check if PostgreSQL is running
brew services list | grep postgres

# Start it
brew services start postgresql@15
```

**Issue: `IntegrityError: duplicate key value violates unique constraint`**
Solution:
```bash
# Drop and recreate database
dropdb trust_app
createdb trust_app
python create_tables.py
```

---

## NEXT STEPS 

- [ ] Authentication endpoints (register, login)
- [ ] JWT token generation
- [ ] Role-based access control (RBAC)
- [ ] Merchant onboarding flow
- [ ] Paystack integration (test mode)
- [ ] Transaction creation endpoint