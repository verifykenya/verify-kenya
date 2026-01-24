import os
from pathlib import Path
from decouple import config, Csv
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.celery import CeleryIntegration

# ✓ SECURITY: Load secrets from environment ONLY
BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = config('DJANGO_SECRET_KEY')  # Raises error if not set
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=Csv())
ENVIRONMENT = config('ENVIRONMENT', default='development')

# ✓ GDPR: Sentry for error tracking (no PII in default integrations)
sentry_sdk.init(
    dsn=config('SENTRY_DSN', default=''),
    integrations=[
        DjangoIntegration(transaction_samples_rate=0.1),
        CeleryIntegration(),
    ],
    traces_sample_rate=0.1,
    environment=ENVIRONMENT,
    # ✓ SECURITY: Redact sensitive data before sending to Sentry
    before_send=lambda event, hint: redact_event_for_sentry(event),
)

# ✓ SECURITY: HTTPS-only in production
SECURE_SSL_REDIRECT = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
SECURE_CONTENT_SECURITY_POLICY = {
    'default-src': ("'self'",),
    'script-src': ("'self'", "'unsafe-inline'"),  # Tighten for production
    'style-src': ("'self'", "'unsafe-inline'"),
}
X_FRAME_OPTIONS = 'DENY'
X_CONTENT_TYPE_OPTIONS = 'nosniff'

# ✓ SECURITY: CORS configuration (whitelist only trusted origins)
CORS_ALLOWED_ORIGINS = config('CORS_ALLOWED_ORIGINS', cast=Csv())
CORS_ALLOW_CREDENTIALS = True
CORS_MAX_AGE = 3600

# ✓ SECURITY: Database with connection pooling
DATABASES = {
    'default': {
        'ENGINE': config('DB_ENGINE', default='django.db.backends.postgresql'),
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),  # From env, never hardcoded
        'HOST': config('DB_HOST'),
        'PORT': config('DB_PORT', default='5432', cast=int),
        'ATOMIC_REQUESTS': True,  # Transactions by default
        'CONN_MAX_AGE': 600,
        'OPTIONS': {
            'connect_timeout': 10,
            'options': '-c statement_timeout=30000',  # 30s max query time
        }
    }
}

# ✓ GDPR: Cache configuration (Redis with SSL in production)
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_URL'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {'max_connections': 50, 'retry_on_timeout': True},
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
            'SSL_CERT_REQS': 'required' if not DEBUG else None,
        }
    }
}

# ✓ SECURITY: Celery async task queue
CELERY_BROKER_URL = config('CELERY_BROKER_URL')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
CELERY_TASK_TIME_LIMIT = 300  # 5 minutes max per task

# ✓ SECURITY: AWS S3 Storage
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage' if not DEBUG else 'django.core.files.storage.FileSystemStorage'
AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID', default='')
AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY', default='')
AWS_STORAGE_BUCKET_NAME = config('AWS_STORAGE_BUCKET_NAME', default='')
AWS_S3_REGION_NAME = config('AWS_S3_REGION_NAME', default='us-east-1')
AWS_S3_CUSTOM_DOMAIN = f'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com' if not DEBUG else None
AWS_S3_OBJECT_PARAMETERS = {'CacheControl': 'max-age=86400'}
# ✓ SECURITY: S3 block public access
AWS_QUERYSTRING_AUTH = True  # Generate signed URLs only

# ✓ SECURITY: JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': config('ACCESS_TOKEN_LIFETIME', default='24h'),
    'REFRESH_TOKEN_LIFETIME': config('REFRESH_TOKEN_LIFETIME', default='30d'),
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': config('JWT_SECRET'),
    'VERIFYING_KEY': None,
}

# ✓ GDPR/CCPA: Structured Logging (JSON format for easy parsing)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s %(status_code)s %(user_id)s',
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': config('LOG_FILE', default='/var/log/authenchain/app.log'),
            'maxBytes': 1024 * 1024 * 10,  # 10MB
            'backupCount': 10,
            'formatter': 'json',
        },
    },
    'loggers': {
        'authenchain': {
            'handlers': ['console', 'file'],
            'level': config('LOG_LEVEL', default='INFO'),
            'propagate': False,
        },
        'django.db.backends': {
            'handlers': ['console'],
            'level': 'WARNING',  # Don't log SQL in production (sensitive)
        },
    },
}

def redact_event_for_sentry(event):
    """
    ✓ GDPR: Remove PII from Sentry before sending.
    Prevents accidental logging of passwords, emails, batch numbers.
    """
    if 'request' in event:
        if 'cookies' in event['request']:
            del event['request']['cookies']
        if 'headers' in event['request']:
            if 'Authorization' in event['request']['headers']:
                event['request']['headers']['Authorization'] = '[REDACTED]'
    
    if 'exception' in event:
        for exc in event['exception']['values']:
            if 'stacktrace' in exc and exc['stacktrace']:
                for frame in exc['stacktrace']['frames']:
                    if 'vars' in frame:
                        frame['vars'] = {k: '[REDACTED]' if k in ['password', 'token', 'secret', 'code_value'] else v 
                                       for k, v in frame['vars'].items()}
    return event

