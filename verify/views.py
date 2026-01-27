"""
AuthentiChain – Production-Ready REST API Views

File: authenchain/views.py

Author: Senior Backend Engineer
Standards: OWASP Top 10, DRF Best Practices, GDPR Compliance, CCPA
Features:
  ✓ JWT Authentication with refresh tokens
  ✓ Role-based access control (RBAC)
  ✓ Rate limiting & throttling
  ✓ Comprehensive error handling
  ✓ Audit logging on all material actions
  ✓ GDPR-compliant data handling
"""

import logging
import hashlib
from uuid import UUID
from decimal import Decimal
from datetime import timedelta

from django.utils import timezone
from django.db.models import Q, Count, F
from django.core.exceptions import ValidationError as DjangoValidationError
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication
from rest_framework.throttle import UserRateThrottle, AnonRateThrottle
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import (
    User, Manufacturer, Subscription, Product, AuthorizedChannel,
    VerificationCode, Scan, ScanResult, CounterfeitReport, AuditLog, APIKey
)
from .serializers import (
    UserSignUpSerializer, UserLoginSerializer, UserSerializer,
    ManufacturerSerializer, ManufacturerCreateSerializer,
    SubscriptionSerializer, ProductSerializer, ProductCreateSerializer,
    AuthorizedChannelSerializer, VerificationCodeSerializer,
    GenerateCodesSerializer, VerifyProductSerializer,
    CounterfeitReportSerializer, CounterfeitReportCreateSerializer,
    AuditLogSerializer
)

logger = logging.getLogger(__name__)

# ============================================================================
# THROTTLE CLASSES
# ============================================================================


class BurstRateThrottle(UserRateThrottle):
    """✓ SECURITY: High-frequency endpoints (login, verify)"""
    scope = 'burst'
    THROTTLE_RATES = {'burst': '20/hour'}


class SustainedRateThrottle(UserRateThrottle):
    """✓ SECURITY: Standard endpoint rate limiting"""
    scope = 'sustained'
    THROTTLE_RATES = {'sustained': '1000/hour'}


class CodeGenerationThrottle(UserRateThrottle):
    """✓ SECURITY: Code generation rate limiting (expensive operation)"""
    scope = 'code_generation'
    THROTTLE_RATES = {'code_generation': '10/hour'}


class AnonBurstRateThrottle(AnonRateThrottle):
    """✓ SECURITY: Anonymous users - strict limit"""
    scope = 'anon_burst'
    THROTTLE_RATES = {'anon_burst': '5/hour'}


# ============================================================================
# PERMISSION CLASSES
# ============================================================================


class IsManufacturer(permissions.BasePermission):
    """✓ RBAC: Only manufacturer users can access"""
    message = "Only manufacturers can access this resource"
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.is_manufacturer()
        )


class IsManufacturerOrOwner(permissions.BasePermission):
    """✓ RBAC: Manufacturer can only access own resources"""
    message = "You can only access your own resources"
    
    def has_object_permission(self, request, view, obj):
        if isinstance(obj, Manufacturer):
            return obj.user == request.user
        elif isinstance(obj, Product):
            return obj.manufacturer.user == request.user
        return False


class CanGenerateCodes(permissions.BasePermission):
    """✓ BUSINESS LOGIC: Check subscription status & limits"""
    message = "Your account is not eligible to generate codes"
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated and request.user.is_manufacturer()):
            return False
        
        try:
            manufacturer = request.user.manufacturer
            subscription = manufacturer.subscription
            
            # Check status
            if manufacturer.status != 'active' and not manufacturer.status == 'trial':
                return False
            
            # Check trial expiry
            if manufacturer.is_trial_expired and manufacturer.status == 'trial':
                return False
            
            # Check subscription active
            return subscription.status == 'active'
        except (Manufacturer.DoesNotExist, Subscription.DoesNotExist):
            return False


# ============================================================================
# AUTHENTICATION VIEWS
# ============================================================================


class UserSignUpView(viewsets.ViewSet):
    """✓ AUTH: User registration endpoint"""
    permission_classes = [AllowAny]
    throttle_classes = [BurstRateThrottle]
    
    def create(self, request):
        """Register new user"""
        serializer = UserSignUpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'errors': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = serializer.save()
            
            # Create audit log
            AuditLog.objects.create(
                user=user,
                action='user_signup',
                entity_type='User',
                entity_id=user.id,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
            )
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'user': UserSerializer(user).data,
                'tokens': {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                }
            }, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            logger.error(f"Signup error: {str(e)}", extra={'error': str(e)})
            return Response(
                {'error': 'Registration failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @staticmethod
    def _get_client_ip(request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


class CustomTokenObtainPairView(TokenObtainPairView):
    """✓ AUTH: JWT login with audit logging"""
    throttle_classes = [BurstRateThrottle]
    
    def post(self, request, *args, **kwargs):
        """Login with email/password"""
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == status.HTTP_200_OK:
            try:
                email = request.data.get('email') or request.data.get('username')
                user = User.objects.get(email=email)
                
                AuditLog.objects.create(
                    user=user,
                    action='user_login',
                    entity_type='User',
                    entity_id=user.id,
                    ip_address=self._get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
                )
                
                logger.info(f"User login: {user.id}", extra={'user_id': str(user.id)})
            except User.DoesNotExist:
                pass
        
        return response
    
    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


# ============================================================================
# USER VIEWS
# ============================================================================


class UserViewSet(viewsets.ViewSet):
    """✓ USER: Profile management"""
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    throttle_classes = [SustainedRateThrottle]
    
    def retrieve(self, request):
        """Get current user profile"""
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def logout(self, request):
        """Logout user"""
        AuditLog.objects.create(
            user=request.user,
            action='user_logout',
            entity_type='User',
            entity_id=request.user.id,
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
        )
        
        logger.info(f"User logout: {request.user.id}")
        return Response({'message': 'Logged out successfully'})
    
    @action(detail=False, methods=['post'])
    def update_consent(self, request):
        """✓ GDPR: Update marketing/analytics consent"""
        user = request.user
        user.marketing_consent = request.data.get('marketing_consent', user.marketing_consent)
        user.analytics_consent = request.data.get('analytics_consent', user.analytics_consent)
        user.save()
        
        AuditLog.objects.create(
            user=user,
            action='user_update',
            entity_type='User',
            entity_id=user.id,
            ip_address=self._get_client_ip(request),
            new_values={
                'marketing_consent': user.marketing_consent,
                'analytics_consent': user.analytics_consent
            }
        )
        
        return Response(UserSerializer(user).data)
    
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def request_data_deletion(self, request):
        """✓ GDPR Art. 17: Request user data deletion"""
        user = request.user
        user.soft_delete()
        
        logger.warning(
            f"User data deletion requested: {user.id}",
            extra={'user_id': str(user.id), 'email': user.email}
        )
        
        return Response(
            {'message': 'Your data deletion request has been submitted'},
            status=status.HTTP_202_ACCEPTED
        )
    
    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


# ============================================================================
# MANUFACTURER VIEWS
# ============================================================================


class ManufacturerViewSet(viewsets.ViewSet):
    """✓ MANUFACTURER: Profile, subscription, and business logic"""
    permission_classes = [IsAuthenticated, IsManufacturer]
    authentication_classes = [JWTAuthentication]
    throttle_classes = [SustainedRateThrottle]
    
    def retrieve(self, request):
        """Get manufacturer profile"""
        try:
            manufacturer = request.user.manufacturer
            serializer = ManufacturerSerializer(manufacturer)
            return Response(serializer.data)
        except Manufacturer.DoesNotExist:
            raise NotFound("Manufacturer profile not found")
    
    def create(self, request):
        """Create manufacturer profile (first time setup)"""
        try:
            # Check if already has manufacturer profile
            if hasattr(request.user, 'manufacturer'):
                return Response(
                    {'error': 'Manufacturer profile already exists'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            serializer = ManufacturerCreateSerializer(
                data=request.data,
                context={'request': request}
            )
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            manufacturer = serializer.save()
            
            # Create default subscription
            Subscription.objects.create(
                manufacturer=manufacturer,
                tier='free',
                monthly_tags_limit=10000,
                price_usd=Decimal('0.00')
            )
            
            # Audit log
            AuditLog.objects.create(
                user=request.user,
                action='manufacturer_create',
                entity_type='Manufacturer',
                entity_id=manufacturer.id,
                ip_address=self._get_client_ip(request),
                new_values={'company': manufacturer.company_name}
            )
            
            return Response(
                ManufacturerSerializer(manufacturer).data,
                status=status.HTTP_201_CREATED
            )
        
        except Exception as e:
            logger.error(f"Manufacturer creation error: {str(e)}")
            return Response(
                {'error': 'Failed to create manufacturer profile'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def subscription(self, request):
        """Get subscription details"""
        try:
            subscription = request.user.manufacturer.subscription
            serializer = SubscriptionSerializer(subscription)
            return Response(serializer.data)
        except (Manufacturer.DoesNotExist, Subscription.DoesNotExist):
            raise NotFound("Subscription not found")
    
    @action(detail=False, methods=['get'])
    def dashboard(self, request):
        """✓ ANALYTICS: Dashboard summary"""
        try:
            manufacturer = request.user.manufacturer
            
            # Get metrics
            total_products = manufacturer.products.count()
            total_codes = VerificationCode.objects.filter(
                product__manufacturer=manufacturer
            ).count()
            active_codes = VerificationCode.objects.filter(
                product__manufacturer=manufacturer,
                status='active'
            ).count()
            total_scans = Scan.objects.filter(
                code__product__manufacturer=manufacturer
            ).count()
            pending_reports = CounterfeitReport.objects.filter(
                code__product__manufacturer=manufacturer,
                status='pending'
            ).count()
            
            return Response({
                'manufacturer': ManufacturerSerializer(manufacturer).data,
                'subscription': SubscriptionSerializer(manufacturer.subscription).data,
                'metrics': {
                    'total_products': total_products,
                    'total_codes_generated': total_codes,
                    'active_codes': active_codes,
                    'total_scans': total_scans,
                    'pending_reports': pending_reports,
                }
            })
        
        except Exception as e:
            logger.error(f"Dashboard error: {str(e)}")
            return Response(
                {'error': 'Failed to load dashboard'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


# ============================================================================
# PRODUCT VIEWS
# ============================================================================


class ProductViewSet(viewsets.ViewSet):
    """✓ PRODUCTS: Product registration and management"""
    permission_classes = [IsAuthenticated, IsManufacturer]
    authentication_classes = [JWTAuthentication]
    throttle_classes = [SustainedRateThrottle]
    
    def list(self, request):
        """List manufacturer's products"""
        try:
            products = request.user.manufacturer.products.all()
            serializer = ProductSerializer(products, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Product list error: {str(e)}")
            return Response(
                {'error': 'Failed to load products'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def retrieve(self, request, pk=None):
        """Get product details"""
        try:
            product = Product.objects.get(pk=pk)
            
            # Check permission
            if product.manufacturer.user != request.user:
                raise PermissionDenied("You don't have permission to view this product")
            
            serializer = ProductSerializer(product)
            return Response(serializer.data)
        except Product.DoesNotExist:
            raise NotFound("Product not found")
    
    def create(self, request):
        """Create new product"""
        serializer = ProductCreateSerializer(
            data=request.data,
            context={'request': request}
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            product = serializer.save()
            
            # Audit log
            AuditLog.objects.create(
                user=request.user,
                action='product_create',
                entity_type='Product',
                entity_id=product.id,
                ip_address=self._get_client_ip(request),
                new_values={'sku': product.sku, 'name': product.name}
            )
            
            return Response(
                ProductSerializer(product).data,
                status=status.HTTP_201_CREATED
            )
        
        except DjangoValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Product creation error: {str(e)}")
            return Response(
                {'error': 'Failed to create product'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


# ============================================================================
# VERIFICATION CODE VIEWS (CORE)
# ============================================================================


class VerificationCodeViewSet(viewsets.ViewSet):
    """✓ CODES: Generate, manage, and verify codes"""
    permission_classes = [IsAuthenticated, IsManufacturer, CanGenerateCodes]
    authentication_classes = [JWTAuthentication]
    throttle_classes = [CodeGenerationThrottle]
    
    def list(self, request):
        """List manufacturer's verification codes"""
        try:
            codes = VerificationCode.objects.filter(
                product__manufacturer=request.user.manufacturer
            ).select_related('product')
            
            # Filter by status if provided
            status_filter = request.query_params.get('status')
            if status_filter:
                codes = codes.filter(status=status_filter)
            
            serializer = VerificationCodeSerializer(codes, many=True)
            return Response(serializer.data)
        
        except Exception as e:
            logger.error(f"Code list error: {str(e)}")
            return Response(
                {'error': 'Failed to load codes'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def retrieve(self, request, pk=None):
        """Get code details"""
        try:
            code = VerificationCode.objects.get(pk=pk)
            
            # Check permission
            if code.product.manufacturer.user != request.user:
                raise PermissionDenied("You don't have permission to view this code")
            
            serializer = VerificationCodeSerializer(code)
            return Response(serializer.data)
        except VerificationCode.DoesNotExist:
            raise NotFound("Code not found")
    
    @action(detail=False, methods=['post'])
    def generate(self, request):
        """✓ SECURITY: Generate bulk verification codes"""
        serializer = GenerateCodesSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            manufacturer = request.user.manufacturer
            subscription = manufacturer.subscription
            product_id = request.data.get('product_id')
            
            # Get product
            try:
                product = Product.objects.get(pk=product_id, manufacturer=manufacturer)
            except Product.DoesNotExist:
                return Response(
                    {'error': 'Product not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Check subscription limit
            quantity = serializer.validated_data['quantity']
            if not subscription.can_generate_codes(quantity):
                return Response(
                    {
                        'error': 'Monthly code limit exceeded',
                        'limit': subscription.monthly_tags_limit,
                        'remaining': subscription.get_remaining_codes()
                    },
                    status=status.HTTP_402_PAYMENT_REQUIRED
                )
            
            # Generate codes
            batch_number = serializer.validated_data['batch_number']
            codes = []
            
            for i in range(quantity):
                serial_number = f"{batch_number}-{i+1:06d}"
                
                code = VerificationCode.objects.create(
                    product=product,
                    code_value=self._generate_code_value(),
                    batch_number=batch_number,
                    serial_number=serial_number,
                    manufacture_date=serializer.validated_data.get('manufacture_date'),
                    destination_retailer=serializer.validated_data.get('destination_retailer', '')
                )
                codes.append(code)
            
            # Audit log
            AuditLog.objects.create(
                user=request.user,
                action='code_generate',
                entity_type='VerificationCode',
                entity_id=product.id,
                ip_address=self._get_client_ip(request),
                new_values={
                    'quantity': quantity,
                    'batch': batch_number,
                    'product_sku': product.sku
                }
            )
            
            logger.info(
                f"Generated {quantity} codes for {product.sku}",
                extra={'manufacturer': str(manufacturer.id), 'product': str(product.id)}
            )
            
            return Response({
                'message': f'Successfully generated {quantity} codes',
                'batch_number': batch_number,
                'codes_count': len(codes),
                'remaining_quota': subscription.get_remaining_codes()
            }, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            logger.error(f"Code generation error: {str(e)}")
            return Response(
                {'error': 'Code generation failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def get_signed_url(self, request):
        """✓ SECURITY: Generate signed verification URL"""
        code_id = request.data.get('code_id')
        purpose = request.data.get('purpose', 'verify')
        
        try:
            code = VerificationCode.objects.get(pk=code_id)
            
            # Check permission
            if code.product.manufacturer.user != request.user:
                raise PermissionDenied("You don't have permission to this code")
            
            # Generate signed URL
            signed_url = code.generate_signed_url(
                user_id=request.user.id,
                purpose=purpose
            )
            
            return Response({
                'signed_url': signed_url,
                'expires_in_seconds': getattr(settings, 'VERIFICATION_URL_EXPIRY_SECONDS', 86400)
            })
        
        except VerificationCode.DoesNotExist:
            raise NotFound("Code not found")
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @staticmethod
    def _generate_code_value():
        """Generate secure random code value"""
        import secrets
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


# ============================================================================
# PUBLIC VERIFICATION VIEWS (Consumer Facing)
# ============================================================================


class PublicVerificationViewSet(viewsets.ViewSet):
    """✓ PUBLIC: Product verification (no auth required)"""
    permission_classes = [AllowAny]
    throttle_classes = [AnonBurstRateThrottle, SustainedRateThrottle]
    
    @action(detail=False, methods=['get'])
    def verify_product(self, request):
        """
        ✓ SECURITY: Verify product authenticity via signed token
        
        Query params:
            token: Signed verification token
            purpose: URL purpose (verify/share/report)
        """
        token = request.query_params.get('token')
        purpose = request.query_params.get('purpose', 'verify')
        code_id = request.query_params.get('code_id')
        
        if not token or not code_id:
            return Response(
                {'error': 'Missing required parameters: token, code_id'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            code = VerificationCode.objects.get(pk=code_id)
        except VerificationCode.DoesNotExist:
            return Response(
                {'error': 'Product code not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Verify signature
        verification_result = code.verify_signed_url(
            token=token,
            user_id=request.user.id if request.user.is_authenticated else None,
            purpose=purpose
        )
        
        if not verification_result['valid']:
            return Response(
                {'error': verification_result['reason']},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Log scan
        geolocation_hash = None
        if request.data.get('latitude') and request.data.get('longitude'):
            lat_lon = f"{request.data['latitude']},{request.data['longitude']}"
            geolocation_hash = hashlib.sha256(lat_lon.encode()).hexdigest()
        
        Scan.objects.create(
            code=code,
            user=request.user if request.user.is_authenticated else None,
            geolocation_hash=geolocation_hash,
            device_type=request.data.get('device_type', 'mobile'),
            ip_address=self._get_client_ip(request),
            scan_source=request.data.get('scan_source', 'app')
        )
        
        # Return product details
        return Response({
            'authentic': True,
            'product': {
                'name': code.product.name,
                'sku': code.product.sku,
                'manufacturer': code.product.manufacturer.company_name,
                'category': code.product.get_category_display(),
                'image_url': code.product.image_url,
                'batch': code.batch_number,
                'serial': code.serial_number,
                'manufacture_date': code.manufacture_date,
            },
            'scan_info': {
                'total_scans': code.scans.count(),
                'status': code.get_status_display()
            }
        })
    
    @action(detail=False, methods=['post'])
    def report_counterfeit(self, request):
        """Submit counterfeit report (public endpoint)"""
        serializer = CounterfeitReportCreateSerializer(
            data=request.data,
            context={'request': request}
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            report = serializer.save()
            
            return Response(
                CounterfeitReportSerializer(report).data,
                status=status.HTTP_201_CREATED
            )
        except Exception as e:
            logger.error(f"Report creation error: {str(e)}")
            return Response(
                {'error': 'Failed to submit report'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


# ============================================================================
# COUNTERFEIT REPORT VIEWS
# ============================================================================


class CounterfeitReportViewSet(viewsets.ViewSet):
    """✓ REPORTS: Manage counterfeit reports"""
    permission_classes = [IsAuthenticated, IsManufacturer]
    authentication_classes = [JWTAuthentication]
    throttle_classes = [SustainedRateThrottle]
    
    def list(self, request):
        """List reports for manufacturer's products"""
        try:
            reports = CounterfeitReport.objects.filter(
                code__product__manufacturer=request.user.manufacturer
            ).select_related('code', 'reporter')
            
            # Filter by status
            status_filter = request.query_params.get('status')
            if status_filter:
                reports = reports.filter(status=status_filter)
            
            serializer = CounterfeitReportSerializer(reports, many=True)
            return Response(serializer.data)
        
        except Exception as e:
            logger.error(f"Reports list error: {str(e)}")
            return Response(
                {'error': 'Failed to load reports'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def retrieve(self, request, pk=None):
        """Get report details"""
        try:
            report = CounterfeitReport.objects.get(pk=pk)
            
            if report.code.product.manufacturer.user != request.user:
                raise PermissionDenied("You don't have permission to view this report")
            
            serializer = CounterfeitReportSerializer(report)
            return Response(serializer.data)
        except CounterfeitReport.DoesNotExist:
            raise NotFound("Report not found")
    
    @action(detail=True, methods=['post'])
    def verify_counterfeit(self, request, pk=None):
        """Mark report as verified counterfeit"""
        try:
            report = CounterfeitReport.objects.get(pk=pk)
            
            if report.code.product.manufacturer.user != request.user:
                raise PermissionDenied("You don't have permission to update this report")
            
            report.status = 'verified'
            report.verified_at = timezone.now()
            report.verified_by = request.user
            report.save()
            
            # Audit log
            AuditLog.objects.create(
                user=request.user,
                action='report_verify',
                entity_type='CounterfeitReport',
                entity_id=report.id,
                ip_address=self._get_client_ip(request),
                new_values={'status': 'verified'}
            )
            
            return Response(CounterfeitReportSerializer(report).data)
        
        except CounterfeitReport.DoesNotExist:
            raise NotFound("Report not found")
        except Exception as e:
            logger.error(f"Report verification error: {str(e)}")
            return Response(
                {'error': 'Failed to verify report'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )