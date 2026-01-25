"""
AuthentiChain – Production-Ready Serializers & Views

Two files:
1. authenchain/serializers.py - Data serialization with validation
2. authenchain/views.py - REST API endpoints

Author: Senior Backend Engineer
Standards: OWASP Top 10, DRF Best Practices, GDPR Compliance
"""

# ============================================================================
# FILE 1: authenchain/serializers.py
# ============================================================================

import re
import logging
from datetime import timedelta
from decimal import Decimal

from rest_framework import serializers
from rest_framework.validators import UniqueValidator, UniqueTogetherValidator
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from django.urls import reverse
from django.conf import settings

from .models import (
    User, Manufacturer, Subscription, Product, AuthorizedChannel,
    VerificationCode, Scan, ScanResult, CounterfeitReport, AuditLog, APIKey
)

logger = logging.getLogger(__name__)


# ============================================================================
# USER SERIALIZERS
# ============================================================================


class UserSignUpSerializer(serializers.ModelSerializer):
    """
    ✓ SECURITY: User registration with strong password validation
    """
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        max_length=128,
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        min_length=8,
        max_length=128,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = User
        fields = ['id', 'email', 'password', 'password_confirm', 'first_name', 'last_name', 'user_type']
        read_only_fields = ['id']
        extra_kwargs = {
            'email': {
                'validators': [
                    UniqueValidator(
                        queryset=User.objects.all(),
                        message='Email already registered'
                    )
                ]
            },
            'first_name': {'required': False},
            'last_name': {'required': False},
        }
    
    def validate_email(self, value):
        """✓ SECURITY: Validate email format"""
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            raise serializers.ValidationError("Invalid email format")
        return value.lower()
    
    def validate_password(self, value):
        """✓ SECURITY: Enforce strong password policy"""
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters")
        
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain uppercase letter")
        
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain lowercase letter")
        
        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError("Password must contain number")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain special character (!@#$%^&*)")
        
        return value
    
    def validate(self, data):
        """✓ VALIDATION: Passwords match"""
        password = data.get('password')
        password_confirm = data.pop('password_confirm', None)
        
        if password != password_confirm:
            raise serializers.ValidationError({'password': 'Passwords do not match'})
        
        return data
    
    def create(self, validated_data):
        """✓ SECURITY: Create user with hashed password"""
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            user_type=validated_data.get('user_type', 'consumer'),
            username=validated_data['email']  # Use email as username
        )
        
        logger.info(
            f"User registered: {user.id}",
            extra={'user_id': str(user.id), 'email': user.email, 'user_type': user.user_type}
        )
        
        return user


class UserLoginSerializer(serializers.Serializer):
    """✓ SECURITY: User login validation"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})


class UserSerializer(serializers.ModelSerializer):
    """✓ PROFILE: User profile (read-only)"""
    user_type_display = serializers.CharField(source='get_user_type_display', read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'user_type', 'user_type_display', 'email_verified', 'created_at']
        read_only_fields = ['id', 'created_at', 'email_verified']


# ============================================================================
# MANUFACTURER SERIALIZERS
# ============================================================================


class SubscriptionSerializer(serializers.ModelSerializer):
    """✓ BILLING: Subscription details with usage metrics"""
    tier_display = serializers.CharField(source='get_tier_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    remaining_codes = serializers.SerializerMethodField()
    usage_percentage = serializers.SerializerMethodField()
    is_over_limit = serializers.SerializerMethodField()
    
    class Meta:
        model = Subscription
        fields = [
            'id', 'tier', 'tier_display', 'monthly_tags_limit', 'monthly_scans_included',
            'price_usd', 'status', 'status_display', 'remaining_codes', 'usage_percentage',
            'is_over_limit', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_remaining_codes(self, obj):
        """Get codes remaining this month"""
        return obj.get_remaining_codes()
    
    def get_usage_percentage(self, obj):
        """Get usage as percentage"""
        return round(obj.usage_percent, 2)
    
    def get_is_over_limit(self, obj):
        """Check if limit exceeded"""
        return obj.is_over_limit


class ManufacturerSerializer(serializers.ModelSerializer):
    """✓ PROFILE: Manufacturer profile with subscription"""
    user = UserSerializer(read_only=True)
    subscription = SubscriptionSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    industry_display = serializers.CharField(source='get_industry_display', read_only=True)
    is_trial_expired = serializers.SerializerMethodField()
    days_until_trial_expires = serializers.SerializerMethodField()
    
    class Meta:
        model = Manufacturer
        fields = [
            'id', 'user', 'company_name', 'industry', 'industry_display', 'country',
            'logo_url', 'website_url', 'subscription_tier', 'status', 'status_display',
            'trial_ends_at', 'is_trial_expired', 'days_until_trial_expires',
            'subscription', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_is_trial_expired(self, obj):
        """Check if trial has expired"""
        return obj.is_trial_expired
    
    def get_days_until_trial_expires(self, obj):
        """Days remaining in trial"""
        return obj.days_until_trial_expires


class ManufacturerCreateSerializer(serializers.ModelSerializer):
    """✓ CREATION: Create manufacturer profile"""
    user_id = serializers.UUIDField(read_only=True)
    
    class Meta:
        model = Manufacturer
        fields = ['id', 'user_id', 'company_name', 'industry', 'country', 'logo_url', 'website_url']
        read_only_fields = ['id', 'user_id']
    
    def validate_company_name(self, value):
        """Validate company name"""
        if not re.match(r'^[a-zA-Z0-9\s\-\.,&]{2,255}$', value):
            raise serializers.ValidationError("Invalid company name format")
        return value
    
    def create(self, validated_data):
        """Create manufacturer"""
        user = self.context['request'].user
        manufacturer = Manufacturer.objects.create(
            user=user,
            **validated_data
        )
        
        logger.info(
            f"Manufacturer created: {manufacturer.id}",
            extra={'manufacturer_id': str(manufacturer.id), 'company': manufacturer.company_name}
        )
        
        return manufacturer


# ============================================================================
# PRODUCT SERIALIZERS
# ============================================================================


class AuthorizedChannelSerializer(serializers.ModelSerializer):
    """✓ CHANNELS: Authorized sales channels"""
    channel_display = serializers.CharField(source='get_channel_display', read_only=True)
    
    class Meta:
        model = AuthorizedChannel
        fields = ['id', 'channel', 'channel_display', 'created_at']
        read_only_fields = ['id', 'created_at']


class ProductSerializer(serializers.ModelSerializer):
    """✓ PRODUCTS: Full product details with channels"""
    manufacturer_name = serializers.CharField(source='manufacturer.company_name', read_only=True)
    authorized_channels_list = AuthorizedChannelSerializer(many=True, read_only=True)
    category_display = serializers.CharField(source='get_category_display', read_only=True)
    code_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Product
        fields = [
            'id', 'manufacturer', 'manufacturer_name', 'sku', 'name', 'category',
            'category_display', 'description', 'image_url', 'authorized_channels_list',
            'code_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        validators = [
            UniqueTogetherValidator(
                queryset=Product.objects.all(),
                fields=['manufacturer', 'sku'],
                message='SKU already exists for this manufacturer'
            )
        ]
    
    def validate_sku(self, value):
        """✓ VALIDATION: SKU format"""
        if not re.match(r'^[A-Z0-9\-]{3,100}$', value):
            raise serializers.ValidationError(
                "SKU must be 3-100 chars: uppercase letters, numbers, hyphens only"
            )
        return value
    
    def validate_name(self, value):
        """✓ VALIDATION: Product name"""
        if not re.match(r'^[a-zA-Z0-9\s\-\.,&]{2,255}$', value):
            raise serializers.ValidationError("Invalid product name")
        return value
    
    def get_code_count(self, obj):
        """Count active codes for this product"""
        return obj.codes.filter(status='active').count()


class ProductCreateSerializer(serializers.ModelSerializer):
    """✓ CREATION: Create product"""
    authorized_channels = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="List of channel names"
    )
    
    class Meta:
        model = Product
        fields = ['id', 'sku', 'name', 'category', 'description', 'image_url', 'authorized_channels']
        read_only_fields = ['id']
    
    def validate_sku(self, value):
        """✓ VALIDATION: SKU format"""
        if not re.match(r'^[A-Z0-9\-]{3,100}$', value):
            raise serializers.ValidationError(
                "SKU must be 3-100 chars: uppercase letters, numbers, hyphens only"
            )
        return value
    
    def create(self, validated_data):
        """Create product with channels"""
        channels = validated_data.pop('authorized_channels', [])
        manufacturer = self.context['request'].user.manufacturer
        
        product = Product.objects.create(
            manufacturer=manufacturer,
            **validated_data
        )
        
        # Create channels
        for channel in channels:
            AuthorizedChannel.objects.create(product=product, channel=channel)
        
        logger.info(
            f"Product created: {product.id}",
            extra={'product_id': str(product.id), 'sku': product.sku}
        )
        
        return product


# ============================================================================
# VERIFICATION CODE SERIALIZERS
# ============================================================================


class VerificationCodeSerializer(serializers.ModelSerializer):
    """✓ VERIFICATION: Code details (read-only)"""
    product_name = serializers.CharField(source='product.name', read_only=True)
    product_sku = serializers.CharField(source='product.sku', read_only=True)
    manufacturer_name = serializers.CharField(source='product.manufacturer.company_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    scan_count = serializers.SerializerMethodField()
    
    class Meta:
        model = VerificationCode
        fields = [
            'id', 'product', 'product_name', 'product_sku', 'manufacturer_name',
            'code_value', 'batch_number', 'serial_number', 'manufacture_date',
            'destination_retailer', 'status', 'status_display', 'scan_count',
            'created_at', 'deactivated_at'
        ]
        read_only_fields = fields
    
    def get_scan_count(self, obj):
        """Get total scans for this code"""
        return obj.scans.count()


class GenerateCodesSerializer(serializers.Serializer):
    """✓ GENERATION: Parameters for bulk code generation"""
    quantity = serializers.IntegerField(
        min_value=1,
        max_value=100000,
        help_text="Number of codes to generate (1-100,000)"
    )
    batch_number = serializers.CharField(
        max_length=100,
        help_text="Batch identifier"
    )
    manufacture_date = serializers.DateField(
        required=False,
        allow_null=True,
        help_text="Manufacturing date"
    )
    destination_retailer = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        help_text="Intended retailer"
    )
    
    def validate_batch_number(self, value):
        """✓ VALIDATION: Batch number format"""
        if not re.match(r'^[A-Z0-9\-_]{2,100}$', value):
            raise serializers.ValidationError(
                "Batch number: 2-100 chars, uppercase/numbers/hyphens/underscores only"
            )
        return value


class VerifyProductSerializer(serializers.Serializer):
    """✓ VERIFICATION: Scan verification request"""
    code_value = serializers.CharField(
        max_length=500,
        help_text="QR code value"
    )
    latitude = serializers.DecimalField(
        max_digits=10,
        decimal_places=8,
        required=False,
        allow_null=True,
        help_text="Scan location latitude"
    )
    longitude = serializers.DecimalField(
        max_digits=11,
        decimal_places=8,
        required=False,
        allow_null=True,
        help_text="Scan location longitude"
    )
    device_type = serializers.ChoiceField(
        choices=['mobile', 'web', 'api'],
        default='mobile',
        help_text="Device type"
    )


# ============================================================================
# COUNTERFEIT REPORT SERIALIZERS
# ============================================================================


class CounterfeitReportSerializer(serializers.ModelSerializer):
    """✓ REPORTING: Counterfeit report details"""
    code_serial = serializers.CharField(source='code.serial_number', read_only=True)
    reporter_email = serializers.CharField(source='reporter.email', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    platform_display = serializers.CharField(source='get_platform_listed_on_display', read_only=True)
    
    class Meta:
        model = CounterfeitReport
        fields = [
            'id', 'code', 'code_serial', 'report_reason', 'report_evidence_url',
            'platform_listed_on', 'platform_display', 'listing_url', 'status',
            'status_display', 'reporter_email', 'created_at', 'resolved_at'
        ]
        read_only_fields = ['id', 'created_at', 'resolved_at']


class CounterfeitReportCreateSerializer(serializers.ModelSerializer):
    """✓ CREATION: Create counterfeit report"""
    
    class Meta:
        model = CounterfeitReport
        fields = [
            'id', 'code', 'report_reason', 'report_evidence_url',
            'platform_listed_on', 'listing_url'
        ]
        read_only_fields = ['id']
    
    def validate_listing_url(self, value):
        """✓ SECURITY: Validate URL to prevent SSRF"""
        # Prevent internal network access
        blocked_domains = ['localhost', '127.0.0.1', '192.168', '10.0', '172.16']
        for domain in blocked_domains:
            if domain in value:
                raise serializers.ValidationError("Internal URLs not allowed")
        
        return value
    
    def validate_report_reason(self, value):
        """✓ VALIDATION: Report reason length"""
        if len(value) < 10:
            raise serializers.ValidationError("Please provide detailed reason (min 10 chars)")
        if len(value) > 1000:
            raise serializers.ValidationError("Reason too long (max 1000 chars)")
        return value
    
    def create(self, validated_data):
        """Create report with user context"""
        report = CounterfeitReport.objects.create(
            reporter=self.context['request'].user,
            **validated_data
        )
        
        logger.info(
            f"Counterfeit report created: {report.id}",
            extra={'report_id': str(report.id), 'code': validated_data['code'].serial_number}
        )
        
        return report


# ============================================================================
# AUDIT LOG SERIALIZER
# ============================================================================


class AuditLogSerializer(serializers.ModelSerializer):
    """✓ AUDIT: Read-only audit log entries"""
    user_email = serializers.CharField(source='user.email', read_only=True, allow_null=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'user', 'user_email', 'action', 'action_display', 'entity_type',
            'entity_id', 'old_values', 'new_values', 'ip_address', 'timestamp'
        ]
        read_only_fields = fields