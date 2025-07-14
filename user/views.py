from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth.models import User as DjangoUser
from django.db import IntegrityError
from .models import User, UserProfile, Vertical, ChainEcosystem
from .serializers import (
    UserSerializer, UserProfileSerializer, WalletLoginSerializer,
    TestLoginSerializer, NonceRequestSerializer, MockWalletLoginSerializer,
    OnboardingSerializer, VerticalSerializer, ChainEcosystemSerializer
)
from .authentication import WalletAuthenticationMixin
import uuid
import time
import secrets

class AuthViewMixin(WalletAuthenticationMixin):
    """Mixin for authentication views"""
    
    def get_tokens_for_user(self, user):
        """Generate JWT tokens for user"""
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

# Test Login for Postman
@api_view(['POST'])
@permission_classes([AllowAny])
def test_login(request):
    """Test login endpoint for Postman testing"""
    serializer = TestLoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        # Try to authenticate with Django's built-in User model first
        django_user = authenticate(username=username, password=password)
        if django_user:
            # Create or get our custom User
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    'email': django_user.email,
                    'first_name': django_user.first_name,
                    'last_name': django_user.last_name,
                }
            )
        else:
            # For testing, create a test user if it doesn't exist
            if username == 'testuser' and password == 'testpass123':
                user, created = User.objects.get_or_create(
                    username=username,
                    defaults={
                        'email': 'test@example.com',
                    }
                )
            else:
                return Response(
                    {'error': 'Invalid credentials'}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
        
        # Generate tokens
        auth_mixin = AuthViewMixin()
        tokens = auth_mixin.get_tokens_for_user(user)
        
        return Response({
            'message': 'Login successful',
            'tokens': tokens,
            'user': UserSerializer(user).data,
            'requires_onboarding': not user.is_onboarded
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Mock Wallet Login for Testing (without real signature verification)
@api_view(['POST'])
@permission_classes([AllowAny])
def mock_wallet_login(request):
    """Mock wallet login for testing purposes - bypasses signature verification"""
    serializer = MockWalletLoginSerializer(data=request.data)
    if serializer.is_valid():
        wallet_address = serializer.validated_data['wallet_address']
        wallet_type = serializer.validated_data.get('wallet_type', 'solana')
        
        # Try to get existing user by wallet address first
        try:
            user = User.objects.get(wallet_address=wallet_address)
            created = False
        except User.DoesNotExist:
            # Create new user with unique username
            created = True
            max_attempts = 5
            attempt = 0
            
            while attempt < max_attempts:
                try:
                    # Generate unique username with random suffix
                    random_suffix = secrets.token_hex(4)
                    username = f'wallet_{wallet_address[-8:]}_{random_suffix}'
                    
                    user = User.objects.create(
                        wallet_address=wallet_address,
                        username=username,
                        email=f'{wallet_address[-8:]}@wallet.zefe.com',
                    )
                    break
                except IntegrityError:
                    attempt += 1
                    if attempt >= max_attempts:
                        return Response({
                            'error': 'Unable to create user. Please try again.'
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Generate tokens
        auth_mixin = AuthViewMixin()
        tokens = auth_mixin.get_tokens_for_user(user)
        
        return Response({
            'message': 'Mock wallet authentication successful',
            'tokens': tokens,
            'user': UserSerializer(user).data,
            'wallet_info': {
                'wallet_address': wallet_address,
                'wallet_type': wallet_type,
                'is_new_user': created
            },
            'requires_onboarding': not user.is_onboarded
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Current User Endpoint
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user(request):
    """Get current authenticated user data with profile"""
    user = request.user
    
    # Prepare user data
    user_data = UserSerializer(user).data
    
    # Check if user has a profile
    profile_data = None
    try:
        profile = user.profile
        profile_data = UserProfileSerializer(profile).data
    except UserProfile.DoesNotExist:
        profile_data = None
    
    # Calculate profile completion percentage
    profile_completion = 0
    if profile_data:
        total_fields = 13  # Total important fields for profile completion
        completed_fields = 0
        
        # Check which fields are completed
        completion_fields = [
            'full_name', 'bio', 'city', 'position', 'project_name',
            'superteam_chapter', 'telegram_username', 'twitter_username',
            'linkedin_url', 'email', 'avatar_url'
        ]
        
        for field in completion_fields:
            if profile_data.get(field):
                completed_fields += 1
        
        # Check verticals and chain_ecosystems
        if profile_data.get('verticals'):
            completed_fields += 1
        if profile_data.get('chain_ecosystems'):
            completed_fields += 1
            
        profile_completion = int((completed_fields / total_fields) * 100)
    
    return Response({
        'user': user_data,
        'profile': profile_data,
        'authentication': {
            'is_authenticated': True,
            'requires_onboarding': not user.is_onboarded,
            'has_profile': profile_data is not None,
        },
        'profile_completion': {
            'percentage': profile_completion,
            'is_complete': profile_completion >= 80,
        },
        'wallet_info': {
            'has_wallet': bool(user.wallet_address),
            'wallet_address': user.wallet_address,
        },
        'account_stats': {
            'created_at': user.date_joined,
            'last_login': user.last_login,
            'is_active': user.is_active,
            'is_staff': user.is_staff,
        }
    })

# Onboarding Endpoints
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def onboarding(request):
    """Complete user onboarding or get current profile"""
    user = request.user
    
    if request.method == 'GET':
        # Get current profile status and data
        try:
            profile = user.profile
            return Response({
                'message': 'Profile found',
                'requires_onboarding': not user.is_onboarded,
                'profile': UserProfileSerializer(profile).data,
                'user': UserSerializer(user).data
            })
        except UserProfile.DoesNotExist:
            return Response({
                'message': 'No profile found',
                'requires_onboarding': True,
                'profile': None,
                'user': UserSerializer(user).data
            })
    
    elif request.method == 'POST':
        # Create new profile (first-time onboarding)
        try:
            profile = user.profile
            return Response({
                'error': 'Profile already exists. Use PUT /api/v1/onboarding/update/ to update.',
                'profile': UserProfileSerializer(profile).data
            }, status=status.HTTP_400_BAD_REQUEST)
        except UserProfile.DoesNotExist:
            # Create new profile
            serializer = OnboardingSerializer(data=request.data, context={'request': request})
            
            if serializer.is_valid():
                profile = serializer.save()
                
                return Response({
                    'message': 'Onboarding completed successfully',
                    'user': UserSerializer(user).data,
                    'profile': UserProfileSerializer(profile).data,
                    'requires_onboarding': False,
                    'onboarding_complete': True
                })
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def onboarding_update(request):
    """Update existing user profile"""
    user = request.user
    
    try:
        profile = user.profile
    except UserProfile.DoesNotExist:
        return Response({
            'error': 'Profile does not exist. Use POST /api/v1/onboarding/ to create first.',
            'requires_onboarding': True
        }, status=status.HTTP_404_NOT_FOUND)
    
    # Update existing profile
    partial = request.method == 'PATCH'
    serializer = OnboardingSerializer(profile, data=request.data, partial=partial, context={'request': request})
    
    if serializer.is_valid():
        profile = serializer.save()
        
        return Response({
            'message': 'Profile updated successfully',
            'user': UserSerializer(user).data,
            'profile': UserProfileSerializer(profile).data,
            'requires_onboarding': False,
            'profile_updated': True
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])
def onboarding_options(request):
    """Get available options for onboarding form"""
    verticals = Vertical.objects.all()
    chain_ecosystems = ChainEcosystem.objects.all()
    
    return Response({
        'verticals': [{'name': v.name, 'display_name': v.get_name_display()} for v in verticals],
        'chain_ecosystems': [{'name': c.name, 'display_name': c.get_name_display()} for c in chain_ecosystems],
        'positions': [{'value': pos[0], 'label': pos[1]} for pos in UserProfile._meta.get_field('position').choices],
        'sample_data': {
            'full_name': 'John Smith',
            'telegram_username': 'johnsmith',
            'city': 'New York',
            'bio': 'Blockchain developer focused on Solana ecosystem.',
            'position': 'DEVELOPER',
            'project_name': 'SolBridge',
            'chain_ecosystems': ['SOLANA', 'ETHEREUM', 'POLKADOT'],
            'verticals': ['DeFi', 'NFT', 'Tokenization'],
            'twitter_username': 'johnsmith_sol',
            'linkedin_url': 'https://linkedin.com/in/johnsmith',
            'email': 'john_unique@example.com',
            'wallet_address': '5KLmDB8iHnPvW6KQs3vKQoEQbCQNJV7as4gV8KvDQ7Ft',
            'superteam_chapter': 'New York',
            'avatar_url': 'https://example.com/profile.jpg',
            'wants_updates': True
        },
        'form_fields': {
            'wants_updates': {
                'type': 'boolean',
                'label': 'I agree to receive updates from Zefe team.',
                'required': False,
                'default': False,
                'description': 'Check this box to receive updates, news, and announcements from the Zefe team.'
            }
        }
    })

# Wallet Authentication Endpoints
@api_view(['POST'])
@permission_classes([AllowAny])
def request_nonce(request):
    """Request nonce for wallet authentication"""
    serializer = NonceRequestSerializer(data=request.data)
    if serializer.is_valid():
        wallet_address = serializer.validated_data['wallet_address']
        wallet_type = serializer.validated_data.get('wallet_type', 'solana')
        
        # Generate nonce
        auth_mixin = AuthViewMixin()
        nonce = auth_mixin.generate_nonce()
        
        # Try to get existing user by wallet address first
        try:
            user = User.objects.get(wallet_address=wallet_address)
            user.nonce = nonce
            user.save()
            created = False
        except User.DoesNotExist:
            # Create new user with unique username
            created = True
            max_attempts = 5
            attempt = 0
            
            while attempt < max_attempts:
                try:
                    # Generate unique username with random suffix
                    random_suffix = secrets.token_hex(4)
                    username = f'wallet_{wallet_address[-8:]}_{random_suffix}'
                    
                    user = User.objects.create(
                        wallet_address=wallet_address,
                        username=username,
                        email=f'{wallet_address[-8:]}@wallet.zefe.com',
                        nonce=nonce,
                    )
                    break
                except IntegrityError:
                    attempt += 1
                    if attempt >= max_attempts:
                        return Response({
                            'error': 'Unable to create user. Please try again.'
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Create sign message
        message = auth_mixin.create_sign_message(nonce, wallet_address)
        
        return Response({
            'message': message,
            'nonce': nonce,
            'wallet_address': wallet_address,
            'wallet_type': wallet_type,
            'expires_at': int(time.time()) + 300,  # 5 minutes from now
            'instructions': {
                'step1': 'Copy the message above',
                'step2': 'Sign it with your wallet',
                'step3': 'Send the signature to /api/v1/auth/wallet-login/',
                'note': 'This nonce expires in 5 minutes'
            }
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def wallet_login(request):
    """Wallet login with signature verification"""
    serializer = WalletLoginSerializer(data=request.data)
    if serializer.is_valid():
        wallet_address = serializer.validated_data['wallet_address']
        signature = serializer.validated_data['signature']
        message = serializer.validated_data['message']
        
        try:
            user = User.objects.get(wallet_address=wallet_address)
        except User.DoesNotExist:
            return Response(
                {'error': 'Wallet not found. Please request nonce first.'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Verify signature (simplified for demo)
        auth_mixin = AuthViewMixin()
        if auth_mixin.verify_signature(message, signature, wallet_address):
            # Clear nonce after successful verification
            user.nonce = None
            user.save()
            
            # Generate tokens
            tokens = auth_mixin.get_tokens_for_user(user)
            
            return Response({
                'message': 'Wallet authentication successful',
                'tokens': tokens,
                'user': UserSerializer(user).data,
                'requires_onboarding': not user.is_onboarded
            })
        else:
            return Response(
                {'error': 'Invalid signature'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# API Information endpoint
@api_view(['GET'])
@permission_classes([AllowAny])
def api_info(request):
    """Get API information and available endpoints"""
    return Response({
        'api_version': '1.0',
        'service': 'ZEFE Solana Mobile Backend',
        'endpoints': {
            'authentication': {
                'test_login': '/api/v1/auth/test-login/',
                'mock_wallet_login': '/api/v1/auth/mock-wallet-login/',
                'request_nonce': '/api/v1/auth/request-nonce/',
                'wallet_login': '/api/v1/auth/wallet-login/',
                'token_refresh': '/api/v1/auth/token-refresh/',
            },
            'user': {
                'current_user': '/api/v1/current-user/',
                'profile': '/api/v1/profile/',
                'protected_test': '/api/v1/auth/protected-test/',
            },
            'onboarding': {
                'create_get': '/api/v1/onboarding/ (GET, POST)',
                'update': '/api/v1/onboarding/update/ (PUT, PATCH)',
                'options': '/api/v1/onboarding/options/',
            },
        },
        'test_credentials': {
            'regular_login': {
                'username': 'testuser',
                'password': 'testpass123'
            },
            'mock_wallet': {
                'wallet_address': '5KLmDB8iHnPvW6KQs3vKQoEQbCQNJV7as4gV8KvDQ7Ft',
                'wallet_type': 'solana'
            }
        },
        'important_note': 'Always include trailing slashes in your requests!'
    })

# Profile Management
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile(request):
    """Get or create user profile"""
    if request.method == 'GET':
        try:
            profile = UserProfile.objects.get(user=request.user)
            serializer = UserProfileSerializer(profile)
            return Response(serializer.data)
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'Profile not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
    
    elif request.method == 'POST':
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protected_test(request):
    """Test endpoint to verify JWT authentication"""
    return Response({
        'message': 'This is a protected endpoint',
        'user': UserSerializer(request.user).data,
        'authenticated': True,
        'requires_onboarding': not request.user.is_onboarded,
        'wallet_info': {
            'has_wallet': bool(request.user.wallet_address),
            'wallet_address': request.user.wallet_address,
        }
    })