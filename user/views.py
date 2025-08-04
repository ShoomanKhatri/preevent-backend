from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth.models import User as DjangoUser
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.db.models import Q
from .models import (
    User, UserProfile, Vertical, ChainEcosystem, ConnectionRequest, Connection, 
    SpamReport, UserSpamScore, CollaborationPost, Comment, Notification, Wallet, 
    POSITIONS, VERTICALS, CHAIN_ECOSYSTEMS, CITIES, COMMUNITIES
)
from .serializers import (
    UserSerializer, OnboardingSerializer, UserProfileSerializer, 
    VerticalSerializer, ChainEcosystemSerializer, AttendeesSerializer,
    ConnectionRequestSerializer, ConnectionSerializer, SpamReportSerializer,
    SendConnectionRequestSerializer, RespondToConnectionRequestSerializer,
    TestLoginSerializer, MockWalletLoginSerializer, NonceRequestSerializer,
    WalletLoginSerializer, ReportSpamSerializer,
    # Collaboration serializers
    CollaborationPostSerializer, CreateCollaborationPostSerializer, CommentSerializer,
    CreateCommentSerializer, NotificationSerializer, UserSearchSerializer
)
from .auth.clerk_auth import ClerkJWTAuthentication
from .authentication import WalletAuthenticationMixin
import uuid
import time
import secrets
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .auth.clerk_auth import ClerkJWTAuthentication

@api_view(["GET"])
@authentication_classes([ClerkJWTAuthentication])
@permission_classes([IsAuthenticated])
def auth_response(request):
    user = request.user
    return Response({
        "message": "Login verified by backend",
        "user": {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
        }
    })

class AuthViewMixin(WalletAuthenticationMixin):
    """Mixin for authentication views"""
    
    def get_tokens_for_user(self, user):
        """Generate JWT tokens for user"""
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    
User = get_user_model()

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]  # Allow public access for login
    authentication_classes = [ClerkJWTAuthentication]  # Use Clerk JWT verification

    def post(self, request):
        token = request.data.get('access_token')
        if not token:
            return Response({'error': 'No token provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Token is verified by ClerkJWTAuthentication
            user = request.user  # User is set by ClerkJWTAuthentication
            tokens = self.get_tokens_for_user(user)
            return Response({
                'refresh': tokens['refresh'],
                'access': tokens['access'],
                'user': {
                    'email': user.email,
                    'name': user.first_name,
                    'username': user.username,
                },
                'requires_onboarding': not user.is_onboarded
            })
        except Exception as e:
            return Response({'error': f'Authentication failed: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

class MockWalletLoginView(AuthViewMixin, APIView):
    """Mock wallet login for testing purposes - bypasses signature verification"""
    
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Handle mock wallet login POST request"""
        serializer = MockWalletLoginSerializer(data=request.data)
        if serializer.is_valid():
            wallet_address = serializer.validated_data['wallet_address']
            wallet_type = serializer.validated_data.get('wallet_type', 'solana')
            
            # Find wallet, or create user and wallet
            wallet = Wallet.objects.filter(address=wallet_address).first()
            if wallet:
                user = wallet.user
                created = False
            else:
                # Create new user
                random_suffix = secrets.token_hex(4)
                username = f'wallet_{wallet_address[-8:]}_{random_suffix}'
                user = User.objects.create(
                    username=username,
                    email=f'{wallet_address[-8:]}@wallet.zefe.com',
                )
                Wallet.objects.create(user=user, address=wallet_address, wallet_type=wallet_type)
                created = True

            tokens = self.get_tokens_for_user(user)
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

class TestLoginView(AuthViewMixin, APIView):
    """Test login endpoint for Postman testing"""
    
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Handle test login POST request"""
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
            tokens = self.get_tokens_for_user(user)
            
            return Response({
                'message': 'Login successful',
                'tokens': tokens,
                'user': UserSerializer(user).data,
                'requires_onboarding': not user.is_onboarded
            })
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Wallet Authentication Endpoints
@api_view(['POST'])
@permission_classes([AllowAny])
def request_nonce(request):
    """Request nonce for wallet authentication"""
    serializer = NonceRequestSerializer(data=request.data)
    if serializer.is_valid():
        wallet_address = serializer.validated_data['wallet_address']
        wallet_type = serializer.validated_data.get('wallet_type', 'solana')
        auth_mixin = AuthViewMixin()
        nonce = auth_mixin.generate_nonce()

        wallet = Wallet.objects.filter(address=wallet_address).first()
        if wallet:
            user = wallet.user
            user.nonce = nonce
            user.save()
            created = False
        else:
            random_suffix = secrets.token_hex(4)
            username = f'wallet_{wallet_address[-8:]}_{random_suffix}'
            user = User.objects.create(
                username=username,
                email=f'{wallet_address[-8:]}@wallet.zefe.com',
                nonce=nonce,
            )
            Wallet.objects.create(user=user, address=wallet_address, wallet_type=wallet_type)
            created = True

        message = auth_mixin.create_sign_message(nonce, wallet_address)
        return Response({
            'message': message,
            'nonce': nonce,
            'wallet_address': wallet_address,
            'wallet_type': wallet_type,
            'expires_at': int(time.time()) + 300,
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
    """WalletConnect login: associate wallet with user"""
    serializer = WalletLoginSerializer(data=request.data)
    if serializer.is_valid():
        wallet_address = serializer.validated_data['wallet_address']
        wallet_type = serializer.validated_data.get('wallet_type', 'solana')
        signature = serializer.validated_data.get('signature')
        message = serializer.validated_data.get('message')

        # Find wallet by address
        wallet = Wallet.objects.filter(address=wallet_address).first()
        if not wallet:
            return Response({'error': 'Wallet not found. Please request nonce first.'}, status=404)
        user = wallet.user

        # Verify signature (your logic here)
        auth_mixin = AuthViewMixin()
        if auth_mixin.verify_signature(message, signature, wallet_address):
            # Generate tokens
            tokens = auth_mixin.get_tokens_for_user(user)
            return Response({
                'message': 'Wallet authentication successful',
                'tokens': tokens,
                'user': UserSerializer(user).data,
                'wallet_info': {
                    'wallet_address': wallet.address,
                    'wallet_type': wallet.wallet_type,
                },
                'requires_onboarding': not user.is_onboarded
            })
        else:
            return Response({'error': 'Invalid signature'}, status=401)
    return Response(serializer.errors, status=400)

class CurrentUserView(APIView):
    """Get current authenticated user data with profile"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_data = UserSerializer(user).data
        profile_data = None
        is_onboarding_completed = False
        
        try:
            profile = user.profile
            profile_data = UserProfileSerializer(profile).data
            is_onboarding_completed = profile.is_onboarding_completed
        except UserProfile.DoesNotExist:
            profile_data = None
            is_onboarding_completed = False

        # Get all wallets for the user
        wallets = Wallet.objects.filter(user=user)
        wallet_list = [{'address': w.address, 'type': w.wallet_type} for w in wallets]

        return Response({
            'user': user_data,
            'profile': profile_data,
            'wallets': wallet_list,
            'authentication': {
                'is_authenticated': True,
                'requires_onboarding': not user.is_onboarded,
                'has_profile': profile_data is not None,
                'is_onboarding_completed': is_onboarding_completed,
            }
        })

class OnboardingView(APIView):
    """Complete user onboarding or get current profile"""
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get current profile status and data"""
        user = request.user
        
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
    
    def post(self, request):
        """Create new profile (first-time onboarding)"""
        user = request.user
        
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
                    'onboarding_complete': True,
                    'is_onboarding_completed': profile.is_onboarding_completed
                })
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OnboardingUpdateView(APIView):
    """Update existing user profile"""
    
    permission_classes = [IsAuthenticated]
    
    def put(self, request):
        """Full update of existing profile"""
        return self._update_profile(request, partial=False)
    
    def patch(self, request):
        """Partial update of existing profile"""
        return self._update_profile(request, partial=True)
    
    def _update_profile(self, request, partial=False):
        """Internal method to handle profile updates"""
        user = request.user
        
        try:
            profile = user.profile
        except UserProfile.DoesNotExist:
            return Response({
                'error': 'Profile does not exist. Use POST /api/v1/onboarding/ to create first.',
                'requires_onboarding': True
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Update existing profile
        serializer = OnboardingSerializer(profile, data=request.data, partial=partial, context={'request': request})
        
        if serializer.is_valid():
            profile = serializer.save()
            
            return Response({
                'message': 'Profile updated successfully',
                'user': UserSerializer(user).data,
                'profile': UserProfileSerializer(profile).data,
                'requires_onboarding': False,
                'profile_updated': True,
                'is_onboarding_completed': profile.is_onboarding_completed
            })
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OnboardingOptionsView(APIView):
    """Get available options for onboarding form"""
    
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Get available form options and sample data"""
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

class APIInfoView(APIView):
    """Get API information and available endpoints"""
    
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Get API documentation and available endpoints"""
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
                'attendees': {
                    'list': '/api/v1/attendees/ (with filtering)',
                    'detail': '/api/v1/attendees/{user_id}/',
                    'stats': '/api/v1/attendees/stats/',
                },
                'connections': {
                    'send_request': '/api/v1/connections/send-request/ (POST)',
                    'respond_to_request': '/api/v1/connections/respond/ (POST)',
                    'my_requests': '/api/v1/connections/my-requests/ (GET)',
                    'my_connections': '/api/v1/connections/my-connections/ (GET)',
                    'status': '/api/v1/connections/status/ (GET)',
                    'report_spam': '/api/v1/report-spam/ (POST)',
                },
                'collaboration': {
                    'posts': '/api/v1/collaboration/posts/ (GET, POST)',
                    'post_detail': '/api/v1/collaboration/posts/{post_id}/ (GET, PUT, PATCH, DELETE)',
                    'post_comments': '/api/v1/collaboration/posts/{post_id}/comments/ (GET, POST)',
                    'user_search': '/api/v1/collaboration/user-search/ (GET)',
                    'connection_check': '/api/v1/collaboration/connection-check/ (GET)',
                    'notify_connection_accepted': '/api/v1/collaboration/notify-connection-accepted/ (POST)',
                },
                'notifications': {
                    'count': '/api/v1/notifications/count/ (GET)',
                    'list': '/api/v1/notifications/ (GET)',
                    'mark_read': '/api/v1/notifications/{notification_id}/read/ (POST)',
                    'mark_all_read': '/api/v1/notifications/mark-all-read/ (POST)',
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

class ProfileView(APIView):
    """Get or create user profile"""
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get user profile"""
        try:
            profile = UserProfile.objects.get(user=request.user)
            serializer = UserProfileSerializer(profile)
            return Response(serializer.data)
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'Profile not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
    
    def post(self, request):
        """Create or update user profile"""
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProtectedTestView(APIView):
    """Test endpoint to verify JWT authentication"""
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Test authenticated access"""
        wallets = Wallet.objects.filter(user=request.user)
        wallet_list = [{'address': w.address, 'type': w.wallet_type} for w in wallets]
        return Response({
            'message': 'This is a protected endpoint',
            'user': UserSerializer(request.user).data,
            'authenticated': True,
            'requires_onboarding': not request.user.is_onboarded,
            'wallets': wallet_list,
        })

class AttendeesView(APIView):
    """List attendees with filtering capabilities"""
    
    permission_classes = []
    
    def get(self, request):
        """Get list of attendees with optional filtering"""
        # Start with all onboarded users who have profiles
        queryset = UserProfile.objects.filter(user__is_onboarded=True).select_related('user').prefetch_related('verticals', 'chain_ecosystems')
        
        # Get filter parameters
        position = request.GET.get('position')
        vertical = request.GET.get('vertical')
        chain_ecosystem = request.GET.get('chain_ecosystem')
        city = request.GET.get('city')
        search = request.GET.get('search')
        
        # Apply filters
        if position:
            queryset = queryset.filter(position__iexact=position)
        
        if vertical:
            queryset = queryset.filter(verticals__name__iexact=vertical)
        
        if chain_ecosystem:
            queryset = queryset.filter(chain_ecosystems__name__iexact=chain_ecosystem)
        
        if city:
            queryset = queryset.filter(city__icontains=city)
        
        if search:
            queryset = queryset.filter(
                Q(full_name__icontains=search) |
                Q(bio__icontains=search) |
                Q(project_name__icontains=search) |
                Q(user__username__icontains=search)
            )
        
        # Get unique profiles (in case of multiple filter matches)
        queryset = queryset.distinct()
        
        # Pagination
        page_size = int(request.GET.get('page_size', 20))
        page = int(request.GET.get('page', 1))
        start = (page - 1) * page_size
        end = start + page_size
        
        total_count = queryset.count()
        profiles = queryset[start:end]
        
        # Serialize the data
        attendees_data = []
        for profile in profiles:
            wallets = Wallet.objects.filter(user=profile.user)
            attendee_data = {
                'id': str(profile.user.id),
                'full_name': profile.full_name,
                'bio': profile.bio,
                'city': profile.city,
                'position': profile.position,
                'project_name': profile.project_name,
                'superteam_chapter': profile.superteam_chapter,
                'verticals': [v.name for v in profile.verticals.all()],
                'chain_ecosystems': [c.name for c in profile.chain_ecosystems.all()],
                'avatar_url': profile.avatar_url,
                'email':profile.user.email,
                'social_links': {
                    'telegram_username': profile.telegram_username,
                    'twitter_username': profile.twitter_username,
                    'linkedin_url': profile.linkedin_url,
                },
                'created_at': profile.created_at,
                'wallets': [{'address': w.address, 'type': w.wallet_type} for w in wallets],
            }
            attendees_data.append(attendee_data)
        
        # Calculate pagination info
        total_pages = (total_count + page_size - 1) // page_size
        has_next = page < total_pages
        has_previous = page > 1
        
        return Response({
            'attendees': attendees_data,
            'pagination': {
                'current_page': page,
                'page_size': page_size,
                'total_count': total_count,
                'total_pages': total_pages,
                'has_next': has_next,
                'has_previous': has_previous,
            },
            'filters_applied': {
                'position': position,
                'vertical': vertical,
                'chain_ecosystem': chain_ecosystem,
                'city': city,
                'search': search,
            },
            'available_filters': self._get_available_filters()
        })
    
    def _get_available_filters(self):
        """Return all static filter options for attendees with display names"""
        return {
            'positions': [display for _, display in POSITIONS],
            'verticals': [display for _, display in VERTICALS], 
            'chain_ecosystems': [display for _, display in CHAIN_ECOSYSTEMS],
            'cities': [display for _, display in CITIES],
            'communities': [display for _, display in COMMUNITIES],
        }

class AttendeeDetailView(APIView):
    """Get detailed information about a specific attendee"""
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request, user_id):
        """Get detailed attendee information"""
        try:
            user = User.objects.get(id=user_id, is_onboarded=True)
            profile = user.profile
            
            wallets = Wallet.objects.filter(user=user)
            
            attendee_data = {
                'id': str(user.id),
                'user': {
                    'username': user.username,
                    'email': user.email,
                    'date_joined': user.date_joined,
                    'wallets': [{'address': w.address, 'type': w.wallet_type} for w in wallets],
                },
                'profile': UserProfileSerializer(profile).data,
                'social_links': {
                    'telegram_username': profile.telegram_username,
                    'twitter_username': profile.twitter_username,
                    'linkedin_url': profile.linkedin_url,
                },
                'professional_info': {
                    'position': profile.position,
                    'project_name': profile.project_name,
                    'superteam_chapter': profile.superteam_chapter,
                    'verticals': [v.name for v in profile.verticals.all()],
                    'chain_ecosystems': [c.name for c in profile.chain_ecosystems.all()],
                },
                'contact_preferences': {
                    'wants_updates': profile.wants_updates,
                }
            }
            
            return Response(attendee_data)
            
        except User.DoesNotExist:
            return Response({
                'error': 'Attendee not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except UserProfile.DoesNotExist:
            return Response({
                'error': 'Attendee profile not found'
            }, status=status.HTTP_404_NOT_FOUND)

class AttendeesStatsView(APIView):
    """Get statistics about attendees"""
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get attendee statistics and aggregated data"""
        total_attendees = UserProfile.objects.filter(user__is_onboarded=True).count()
        
        # Position distribution
        position_stats = {}
        for position_code, position_label in POSITIONS:
            count = UserProfile.objects.filter(
                user__is_onboarded=True,
                position=position_code
            ).count()
            if count > 0:
                position_stats[position_label] = count
        
        # Vertical distribution
        vertical_stats = {}
        for vertical in Vertical.objects.all():
            count = vertical.userprofile_set.filter(user__is_onboarded=True).count()
            if count > 0:
                vertical_stats[vertical.name] = count
        
        # Chain ecosystem distribution
        chain_stats = {}
        for chain in ChainEcosystem.objects.all():
            count = chain.userprofile_set.filter(user__is_onboarded=True).count()
            if count > 0:
                chain_stats[chain.name] = count
        
        # City distribution (top 10)
        city_stats = {}
        cities = UserProfile.objects.filter(
            user__is_onboarded=True,
            city__isnull=False
        ).exclude(city='').values_list('city', flat=True)
        
        from collections import Counter
        city_counter = Counter(cities)
        city_stats = dict(city_counter.most_common(10))
        
        return Response({
            'total_attendees': total_attendees,
            'statistics': {
                'by_position': position_stats,
                'by_vertical': vertical_stats,
                'by_chain_ecosystem': chain_stats,
                'by_city': city_stats,
            },
            'summary': {
                'most_common_position': max(position_stats, key=position_stats.get) if position_stats else None,
                'most_popular_vertical': max(vertical_stats, key=vertical_stats.get) if vertical_stats else None,
                'most_popular_chain': max(chain_stats, key=chain_stats.get) if chain_stats else None,
                'most_popular_city': max(city_stats, key=city_stats.get) if city_stats else None,
            }
        })

# Connection System Views
class ConnectionRequestView(APIView):
    """Handle connection requests"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Send a connection request"""
        from .serializers import ConnectionRequestSerializer
        from .models import ConnectionRequest, UserSpamScore
        
        serializer = ConnectionRequestSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            receiver_id = serializer.validated_data['receiver_id']
            receiver = User.objects.get(id=receiver_id)
            
            # Create connection request
            connection_request = ConnectionRequest.objects.create(
                sender=request.user,
                receiver=receiver,
                note_content=serializer.validated_data.get('note_content', ''),
                status='PENDING'
            )
            
            # Return the created request
            response_serializer = ConnectionRequestSerializer(connection_request)
            return Response({
                'success': True,
                'message': 'Connection request sent successfully',
                'connection_request': response_serializer.data
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        """Get connection requests (sent and received)"""
        from .serializers import ConnectionRequestSerializer
        
        # Get sent requests
        sent_requests = ConnectionRequest.objects.filter(sender=request.user).order_by('-created_at')
        
        # Get received requests
        received_requests = ConnectionRequest.objects.filter(receiver=request.user).order_by('-created_at')
        
        sent_serializer = ConnectionRequestSerializer(sent_requests, many=True)
        received_serializer = ConnectionRequestSerializer(received_requests, many=True)
        
        return Response({
            'sent_requests': sent_serializer.data,
            'received_requests': received_serializer.data,
            'counts': {
                'sent': sent_requests.count(),
                'received': received_requests.count(),
                'pending_received': received_requests.filter(status='PENDING').count()
            }
        })

class ConnectionRequestResponseView(APIView):
    """Handle responses to connection requests"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, request_id):
        """Respond to a connection request"""
        from .serializers import ConnectionRequestResponseSerializer
        from .models import ConnectionRequest, Connection, SpamReport, UserSpamScore
        from django.utils import timezone
        
        try:
            connection_request = ConnectionRequest.objects.get(
                id=request_id, 
                receiver=request.user,
                status='PENDING'
            )
        except ConnectionRequest.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Connection request not found or already processed'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = ConnectionRequestResponseSerializer(data=request.data)
        if serializer.is_valid():
            action = serializer.validated_data['action']
            reason = serializer.validated_data.get('reason', '')
            
            if action == 'accept':
                # Accept the request - create connection
                connection_request.status = 'ACCEPTED'
                connection_request.save()
                
                # Create bidirectional connection
                connection = Connection.objects.create(
                    user1=connection_request.sender,
                    user2=connection_request.receiver,
                    connection_request=connection_request
                )
                
                # Get user profiles for telegram exchange
                sender_profile = getattr(connection_request.sender, 'profile', None)
                receiver_profile = getattr(connection_request.receiver, 'profile', None)
                
                return Response({
                    'success': True,
                    'message': 'Connection request accepted! You are now connected.',
                    'connection': {
                        'id': connection.id,
                        'connected_user': {
                            'id': connection_request.sender.id,
                            'username': connection_request.sender.username,
                            'wallet_address': connection_request.sender.wallet_address,
                            'full_name': sender_profile.full_name if sender_profile else '',
                            'telegram_username': sender_profile.telegram_username if sender_profile else ''
                        },
                        'your_telegram': receiver_profile.telegram_username if receiver_profile else '',
                        'created_at': connection.created_at
                    }
                })
            
            elif action == 'reject':
                # Reject the request
                connection_request.status = 'REJECTED'
                connection_request.save()
                
                return Response({
                    'success': True,
                    'message': 'Connection request rejected'
                })
            
            elif action == 'spam':
                # Mark as spam and increase spam score
                connection_request.status = 'SPAM'
                connection_request.save()
                
                # Create spam report
                spam_report = SpamReport.objects.create(
                    reported_user=connection_request.sender,
                    reported_by=connection_request.receiver,
                    connection_request=connection_request,
                    reason=reason
                )
                
                # Increase spam score
                spam_record, created = UserSpamScore.objects.get_or_create(
                    user=connection_request.sender
                )
                was_banned = spam_record.increase_spam_score()
                
                return Response({
                    'success': True,
                    'message': 'User reported as spam',
                    'spam_report': {
                        'reported_user': connection_request.sender.username,
                        'new_spam_score': spam_record.spam_score,
                        'is_banned': was_banned,
                        'reason': reason
                    }
                })
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class ConnectionsView(APIView):
    """Handle user connections"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get user's connections"""
        from .serializers import ConnectionSerializer, UserWithConnectionStatusSerializer
        
        # Get all connections for the user
        connections = Connection.objects.filter(
            Q(user1=request.user) | Q(user2=request.user)
        ).select_related('user1', 'user2', 'user1__profile', 'user2__profile')
        
        # Format connections data
        connections_data = []
        for connection in connections:
            other_user = connection.get_other_user(request.user)
            other_profile = getattr(other_user, 'profile', None)
            
            connections_data.append({
                'connection_id': connection.id,
                'connected_user': {
                    'id': other_user.id,
                    'username': other_user.username,
                    'wallets': [{'address': w.address, 'type': w.wallet_type} for w in Wallet.objects.filter(user=other_user)],
                    'full_name': other_profile.full_name if other_profile else '',
                    'bio': other_profile.bio if other_profile else '',
                    'city': other_profile.city if other_profile else '',
                    'position': other_profile.position if other_profile else '',
                    'project_name': other_profile.project_name if other_profile else '',
                    'telegram_username': other_profile.telegram_username if other_profile else '',
                    'twitter_username': other_profile.twitter_username if other_profile else '',
                    'linkedin_url': other_profile.linkedin_url if other_profile else '',
                    'avatar_url': other_profile.avatar_url if other_profile else '',
                },
                'connected_at': connection.created_at
            })
        
        return Response({
            'connections': connections_data,
            'total_connections': len(connections_data)
        })

class ExploreUsersView(APIView):
    """Enhanced explore users view with connection status"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get users for explore page with connection status"""
        from .serializers import UserWithConnectionStatusSerializer
        
        # Get all onboarded users except current user
        users = User.objects.filter(
            is_onboarded=True
        ).exclude(
            id=request.user.id
        ).select_related('profile').prefetch_related(
            'profile__verticals',
            'profile__chain_ecosystems'
        )
        
        # Apply filters
        position = request.query_params.get('position')
        vertical = request.query_params.get('vertical')
        chain_ecosystem = request.query_params.get('chain_ecosystem')
        city = request.query_params.get('city')
        search = request.query_params.get('search')
        
        if position:
            users = users.filter(profile__position=position)
        
        if vertical:
            users = users.filter(profile__verticals__name=vertical)
        
        if chain_ecosystem:
            users = users.filter(profile__chain_ecosystems__name=chain_ecosystem)
        
        if city:
            users = users.filter(profile__city__icontains=city)
        
        if search:
            users = users.filter(
                Q(profile__full_name__icontains=search) |
                Q(profile__bio__icontains=search) |
                Q(profile__project_name__icontains=search) |
                Q(username__icontains=search)
            )
        
        # Pagination
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        
        total_users = users.count()
        paginated_users = users[start_index:end_index]
        
        serializer = UserWithConnectionStatusSerializer(
            paginated_users, 
            many=True, 
            context={'request': request}
        )
        
        return Response({
            'users': serializer.data,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': (total_users + page_size - 1) // page_size,
                'total_users': total_users,
                'has_next': end_index < total_users,
                'has_previous': page > 1
            }
        })

class UserSpamScoreView(APIView):
    """View user spam scores (admin only)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get spam scores for all users"""
        from .serializers import UserSpamScoreSerializer
        from .models import UserSpamScore
        
        # Only allow superusers to view spam scores
        if not request.user.is_superuser:
            return Response({
                'success': False,
                'message': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        spam_scores = UserSpamScore.objects.select_related('user').order_by('-spam_score')
        serializer = UserSpamScoreSerializer(spam_scores, many=True)
        
        return Response({
            'spam_scores': serializer.data,
            'total_users': spam_scores.count(),
            'banned_users': spam_scores.filter(is_banned=True).count()
        })

class SendConnectionRequestView(APIView):
    """Send a connection request to another user"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Send connection request"""
        serializer = SendConnectionRequestSerializer(data=request.data)
        
        if serializer.is_valid():
            receiver_id = serializer.validated_data['receiver_id']
            message = serializer.validated_data.get('message', '')
            sender = request.user
            
            try:
                receiver = User.objects.get(id=receiver_id)
                
                # Check if sender is trying to connect to themselves
                if sender.id == receiver_id:
                    return Response(
                        {'error': 'Cannot send connection request to yourself'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Check if they are already connected
                existing_connection = Connection.objects.filter(
                    (Q(user1=sender) & Q(user2=receiver)) |
                    (Q(user1=receiver) & Q(user2=sender))
                ).exists()
                
                if existing_connection:
                    return Response(
                        {'error': 'Users are already connected'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Check if there's already a pending request
                existing_request = ConnectionRequest.objects.filter(
                    sender=sender,
                    receiver=receiver,
                    status='PENDING'
                ).exists()
                
                if existing_request:
                    return Response(
                        {'error': 'Connection request already sent'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Check spam score
                sender_spam_score, _ = UserSpamScore.objects.get_or_create(user=sender)
                
                if sender_spam_score.is_banned_user():
                    return Response(
                        {'error': 'You are temporarily banned from sending connection requests'},
                        status=status.HTTP_403_FORBIDDEN
                    )
                
                # Create connection request
                connection_request = ConnectionRequest.objects.create(
                    sender=sender,
                    receiver=receiver,
                    note_content=serializer.validated_data.get('note_content', '')
                )
                
                # Create notification for the receiver
                Notification.objects.create(
                    user=receiver,
                    type='CONNECTION_REQUEST',
                    title='New connection request',
                    # message=f'{sender.username} sent you a connection request',
                    related_connection_request=connection_request,
                    related_user=sender
                )
                
                serializer = ConnectionRequestSerializer(connection_request)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
                
            except User.DoesNotExist:
                return Response(
                    {'error': 'Receiver user not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RespondToConnectionRequestView(APIView):
    """Respond to a connection request"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Respond to connection request"""
        serializer = RespondToConnectionRequestSerializer(data=request.data)
        
        if serializer.is_valid():
            request_id = serializer.validated_data['request_id']
            response = serializer.validated_data['response']
            
            try:
                # First, check if the connection request exists at all
                connection_request = ConnectionRequest.objects.get(id=request_id)
                
                # Check if current user is the receiver
                if connection_request.receiver != request.user:
                    return Response({
                        'error': 'You are not authorized to respond to this connection request',
                        'debug_info': {
                            'current_user_id': str(request.user.id),
                            'receiver_id': str(connection_request.receiver.id),
                            'sender_id': str(connection_request.sender.id)
                        }
                    }, status=status.HTTP_403_FORBIDDEN)
                
                # Check if request is still pending
                if connection_request.status != 'PENDING':
                    return Response({
                        'error': f'Connection request already processed with status: {connection_request.status}',
                        'debug_info': {
                            'current_status': connection_request.status,
                            'created_at': connection_request.created_at,
                            'updated_at': connection_request.updated_at
                        }
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Remove the connection request notification for the receiver
                # since they have now responded to it
                Notification.objects.filter(
                    user=connection_request.receiver,
                    type='CONNECTION_REQUEST',
                    related_connection_request=connection_request
                ).delete()
                
                if response == 'interested':
                    # Create connection
                    Connection.objects.create(
                        user1=connection_request.sender,
                        user2=connection_request.receiver,
                        connection_request=connection_request
                    )
                    connection_request.status = 'ACCEPTED'
                    connection_request.save()
                    
                    # Create notification for the sender that their request was accepted
                    Notification.objects.create(
                        user=connection_request.sender,
                        type='CONNECTION_ACCEPTED',
                        title='Connection request accepted',
                        # message=f'{connection_request.receiver.username} accepted your connection request',
                        related_connection_request=connection_request,
                        related_user=connection_request.receiver
                    )
                    
                    return Response(
                        {'message': 'Connection request accepted'},
                        status=status.HTTP_200_OK
                    )
                
                elif response == 'not_interested':
                    connection_request.status = 'REJECTED'
                    connection_request.save()
                    
                    return Response(
                        {'message': 'Connection request rejected'},
                        status=status.HTTP_200_OK
                    )
                
                elif response == 'spam':
                    connection_request.status = 'SPAM'
                    connection_request.save()
                    
                    # Create spam report
                    SpamReport.objects.create(
                        reported_by=request.user,
                        reported_user=connection_request.sender,
                        connection_request=connection_request,
                        reason='Connection request marked as spam'
                    )
                    
                    # Update spam score
                    sender_spam_score, _ = UserSpamScore.objects.get_or_create(
                        user=connection_request.sender
                    )
                    sender_spam_score.increase_spam_score()
                    
                    return Response(
                        {'message': 'Connection request marked as spam'},
                        status=status.HTTP_200_OK
                    )
                
            except ConnectionRequest.DoesNotExist:
                return Response({
                    'error': 'Connection request does not exist',
                    'debug_info': {
                        'request_id': str(request_id),
                        'current_user_id': str(request.user.id)
                    }
                }, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MyConnectionRequestsView(APIView):
    """Get user's connection requests (sent and received)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get connection requests"""
        request_type = request.query_params.get('type', 'all')
        
        if request_type == 'sent':
            requests = ConnectionRequest.objects.filter(sender=request.user)
        elif request_type == 'received':
            requests = ConnectionRequest.objects.filter(receiver=request.user)
        else:
            requests = ConnectionRequest.objects.filter(
                Q(sender=request.user) | Q(receiver=request.user)
            )
        
        requests = requests.order_by('-created_at')
        serializer = ConnectionRequestSerializer(requests, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)

class MyConnectionsView(APIView):
    """Get user's connections with filtering capabilities"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get user's connections with optional filtering"""
        # Start with base connections query
        connections = Connection.objects.filter(
            Q(user1=request.user) | Q(user2=request.user)
        ).select_related(
            'user1', 'user2', 'connection_request',
            'user1__profile', 'user2__profile'
        ).prefetch_related(
            'user1__profile__verticals',
            'user1__profile__chain_ecosystems',
            'user2__profile__verticals', 
            'user2__profile__chain_ecosystems'
        )
        
        # Get filter parameters
        position = request.GET.get('position')
        vertical = request.GET.get('vertical')
        chain_ecosystem = request.GET.get('chain_ecosystem')
        city = request.GET.get('city')
        search = request.GET.get('search')
        
        # Apply filters to the connected users
        filtered_connections = []
        
        for connection in connections:
            # Get the other user (not the current user)
            other_user = connection.user2 if connection.user1 == request.user else connection.user1
            
            # Check if other user has a profile
            try:
                other_profile = other_user.profile
            except UserProfile.DoesNotExist:
                continue
            
            # Apply filters
            should_include = True
            
            if position and other_profile.position != position:
                should_include = False
            
            if vertical and not other_profile.verticals.filter(name__iexact=vertical).exists():
                should_include = False
            
            if chain_ecosystem and not other_profile.chain_ecosystems.filter(name__iexact=chain_ecosystem).exists():
                should_include = False
            
            if city and city.lower() not in other_profile.city.lower():
                should_include = False
            
            if search:
                search_lower = search.lower()
                if not any([
                    search_lower in other_profile.full_name.lower(),
                    search_lower in other_profile.bio.lower(),
                    search_lower in other_profile.project_name.lower(),
                    search_lower in other_user.username.lower()
                ]):
                    should_include = False
            
            if should_include:
                filtered_connections.append(connection)
        
        # Pagination
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 20))
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        
        total_connections = len(filtered_connections)
        paginated_connections = filtered_connections[start_index:end_index]
        
        # Format connections data with full profile information
        connections_data = []
        for connection in paginated_connections:
            other_user = connection.user2 if connection.user1 == request.user else connection.user1
            other_profile = getattr(other_user, 'profile', None)
            
            connection_data = {
                'connection_id': str(connection.id),
                'connected_user': {
                    'id': str(other_user.id),
                    'username': other_user.username,
                    'wallets': [{'address': w.address, 'type': w.wallet_type} for w in Wallet.objects.filter(user=other_user)],
                    'full_name': other_profile.full_name if other_profile else '',
                    'bio': other_profile.bio if other_profile else '',
                    'city': other_profile.city if other_profile else '',
                    'position': other_profile.position if other_profile else '',
                    'project_name': other_profile.project_name if other_profile else '',
                    'superteam_chapter': other_profile.superteam_chapter if other_profile else '',
                    'verticals': [v.name for v in other_profile.verticals.all()] if other_profile else [],
                    'chain_ecosystems': [c.name for c in other_profile.chain_ecosystems.all()] if other_profile else [],
                    'social_links': {
                        'telegram_username': other_profile.telegram_username if other_profile else '',
                        'twitter_username': other_profile.twitter_username if other_profile else '',
                        'linkedin_url': other_profile.linkedin_url if other_profile else '',
                    },
                    'avatar_url': other_profile.avatar_url if other_profile else '',
                },
                'connection_request': {
                    'id': str(connection.connection_request.id),
                    'note_content': connection.connection_request.note_content,
                    'status': connection.connection_request.status,
                    'created_at': connection.connection_request.created_at,
                },
                'connected_at': connection.created_at
            }
            connections_data.append(connection_data)
        
        # Calculate pagination info
        total_pages = (total_connections + page_size - 1) // page_size
        has_next = page < total_pages
        has_previous = page > 1
        
        return Response({
            'connections': connections_data,
            'pagination': {
                'current_page': page,
                'page_size': page_size,
                'total_count': total_connections,
                'total_pages': total_pages,
                'has_next': has_next,
                'has_previous': has_previous,
            },
            'filters_applied': {
                'position': position,
                'vertical': vertical,
                'chain_ecosystem': chain_ecosystem,
                'city': city,
                'search': search,
            },
            'available_filters': self._get_available_filters(request),
            'message': f'Found {total_connections} connections'
        }, status=status.HTTP_200_OK)
    
    def _get_available_filters(self, request):
        """Get available filter options based on connected users with display names"""
        user = request.user
        
        connections = Connection.objects.filter(
            Q(user1=user) | Q(user2=user)
        ).select_related('user1', 'user2', 'user1__profile', 'user2__profile')
        
        positions = set()
        cities = set()
        verticals = set()
        chain_ecosystems = set()
        
        for connection in connections:
            # Get the other user (not the current user)
            other_user = connection.user2 if connection.user1 == user else connection.user1
            
            try:
                other_profile = other_user.profile
                
                if other_profile.position:
                    positions.add(other_profile.position)
                if other_profile.city:
                    cities.add(other_profile.city)
                
                # Get verticals and chain ecosystems
                for vertical in other_profile.verticals.all():
                    verticals.add(vertical.name)
                for ecosystem in other_profile.chain_ecosystems.all():
                    chain_ecosystems.add(ecosystem.name)
                    
            except UserProfile.DoesNotExist:
                continue
        
        return {
            'positions': sorted(convert_choices_to_display_names(list(positions), POSITIONS)),
            'cities': sorted(convert_choices_to_display_names(list(cities), CITIES)),
            'verticals': sorted(convert_choices_to_display_names(list(verticals), VERTICALS)),
            'chain_ecosystems': sorted(convert_choices_to_display_names(list(chain_ecosystems), CHAIN_ECOSYSTEMS)),
        }

class ReportSpamView(APIView):
    """Report a user as spam"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Report user as spam"""
        from .serializers import ReportSpamSerializer
        
        serializer = ReportSpamSerializer(data=request.data)
        
        if serializer.is_valid():
            reported_user_id = serializer.validated_data['reported_user_id']
            reason = serializer.validated_data.get('reason', 'Spam behavior')
            
            try:
                reported_user = User.objects.get(id=reported_user_id)
                
                # Check if user is trying to report themselves
                if request.user.id == reported_user_id:
                    return Response(
                        {'error': 'Cannot report yourself'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Check if already reported
                existing_report = SpamReport.objects.filter(
                    reported_by=request.user,
                    reported_user=reported_user
                ).exists()
                
                if existing_report:
                    return Response(
                        {'message': 'User already reported'},
                        status=status.HTTP_200_OK
                    )
                
                # Create spam report
                SpamReport.objects.create(
                    reported_by=request.user,
                    reported_user=reported_user,
                    reason=reason
                )
                
                # Update spam score
                spam_score, _ = UserSpamScore.objects.get_or_create(user=reported_user)
                spam_score.increase_spam_score()
                
                return Response(
                    {'message': 'User reported successfully'},
                    status=status.HTTP_201_CREATED
                )
                
            except User.DoesNotExist:
                return Response(
                    {'error': 'User not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ConnectionStatusView(APIView):
    """Check connection status between two users"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Check connection status with another user"""
        other_user_id = request.query_params.get('user_id')
        
        if not other_user_id:
            return Response(
                {'error': 'user_id parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            other_user = User.objects.get(id=other_user_id)
            
            # Check if connected
            connection = Connection.objects.filter(
                (Q(user1=request.user) & Q(user2=other_user)) |
                (Q(user1=other_user) & Q(user2=request.user))
            ).first()
            
            if connection:
                return Response({
                    'status': 'connected',
                    'connection_date': connection.created_at
                })
            
            # Check for pending requests
            sent_request = ConnectionRequest.objects.filter(
                sender=request.user,
                receiver=other_user,
                status='PENDING'
            ).first()
            
            if sent_request:
                return Response({
                    'status': 'request_sent',
                    'request_date': sent_request.created_at
                })
            
            received_request = ConnectionRequest.objects.filter(
                sender=other_user,
                receiver=request.user,
                status='PENDING'
            ).first()
            
            if received_request:
                return Response({
                    'status': 'request_received',
                    'request_date': received_request.created_at,
                    'request_id': received_request.id
                })
            
            return Response({'status': 'not_connected'})
            
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class NotificationsCountView(APIView):
    """Get notification counts for the user"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get notification counts"""
        user = request.user
        
        # Count pending connection requests received
        pending_requests = ConnectionRequest.objects.filter(
            receiver=user,
            status='PENDING'
        ).count()
        
        # Count unread collaboration notifications
        unread_notifications = Notification.objects.filter(
            user=user,
            is_read=False
        ).count()
        
        # Count unread spam reports (if user is admin)
        spam_reports = SpamReport.objects.filter(
            reported_user=user
        ).count()
        
        # Total notification count
        total_notifications = pending_requests + unread_notifications
        
        return Response({
            'pending_connection_requests': pending_requests,
            'unread_collaboration_notifications': unread_notifications,
            'spam_reports_about_me': spam_reports,
            'total_notifications': total_notifications
        }, status=status.HTTP_200_OK)

class NotificationsListView(APIView):
    """Get detailed notifications for the user"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get detailed notifications list"""
        user = request.user
        
        # Get collaboration notifications with related objects
        collaboration_notifications = Notification.objects.filter(
            user=user
        ).select_related(
            'related_user',
            'related_user__profile',
            'related_connection_request',
            'related_post',
            'related_comment'
        ).order_by('-created_at')
        
        notifications = []
        
        # Process each notification and add enhanced data
        for notif in collaboration_notifications:
            notification_data = {
                'type': notif.type,
                'id': str(notif.id),
                'title': notif.title,
                'is_read': notif.is_read,
                'created_at': notif.created_at,
                'related_post_id': str(notif.related_post.id) if notif.related_post else None,
                'related_comment_id': str(notif.related_comment.id) if notif.related_comment else None,
                'related_connection_request_id': str(notif.related_connection_request.id) if notif.related_connection_request else None,
                'related_user_id': str(notif.related_user.id) if notif.related_user else None,
            }
            
            # Add enhanced data based on notification type
            if notif.type == 'CONNECTION_REQUEST' and notif.related_connection_request:
                connection_request = notif.related_connection_request
                sender_profile = None
                try:
                    sender_profile = connection_request.sender.profile
                except:
                    pass
                
                notification_data.update({
                    'note_content': connection_request.note_content,
                    'status': connection_request.status,
                    'full_name': sender_profile.full_name if sender_profile else connection_request.sender.username,
                    'sender_username': connection_request.sender.username,
                })
            
            elif notif.type == 'CONNECTION_ACCEPTED' and notif.related_connection_request:
                connection_request = notif.related_connection_request
                user_profile = None
                try:
                    user_profile = notif.related_user.profile
                except:
                    pass
                
                notification_data.update({
                    'status': connection_request.status,
                    'full_name': user_profile.full_name if user_profile else notif.related_user.username,
                    'username': notif.related_user.username,
                })
            
            elif notif.related_user:
                # For other notification types, include basic user info
                user_profile = None
                try:
                    user_profile = notif.related_user.profile
                except:
                    pass
                
                notification_data.update({
                    'full_name': user_profile.full_name if user_profile else notif.related_user.username,
                    'username': notif.related_user.username,
                })
            
            # Add the complete notification data
            notification_data['data'] = {
                'id': str(notif.id),
                'type': notif.type,
                'title': notif.title,
                'is_read': notif.is_read,
                'created_at': notif.created_at,
                'related_post_id': str(notif.related_post.id) if notif.related_post else None,
                'related_comment_id': str(notif.related_comment.id) if notif.related_comment else None,
                'related_connection_request_id': str(notif.related_connection_request.id) if notif.related_connection_request else None,
                'related_user_id': str(notif.related_user.id) if notif.related_user else None,
            }
            
            notifications.append(notification_data)
        
        return Response({
            'count': len(notifications),
            'notifications': notifications,
            'unread_count': len([n for n in notifications if not n.get('is_read', True)])
        }, status=status.HTTP_200_OK)

class MarkNotificationReadView(APIView):
    """Mark notification as read"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, notification_id):
        """Mark a specific notification as read"""
        try:
            notification = Notification.objects.get(
                id=notification_id,
                user=request.user
            )
            
            notification.is_read = True
            notification.save()
            
            return Response({
                'message': 'Notification marked as read'
            }, status=status.HTTP_200_OK)
            
        except Notification.DoesNotExist:
            return Response({
                'error': 'Notification not found'
            }, status=status.HTTP_404_NOT_FOUND)

class MarkAllNotificationsReadView(APIView):
    """Mark all notifications as read"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Mark all notifications as read for the current user"""
        updated_count = Notification.objects.filter(
            user=request.user,
            is_read=False
        ).update(is_read=True)
        
        return Response({
            'message': f'{updated_count} notifications marked as read'
        }, status=status.HTTP_200_OK)

# ================================
# COLLABORATION SYSTEM VIEWS  
# ================================

class CollaborationPostsView(APIView):
    """List and create collaboration posts"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get all collaboration posts with pagination and filtering"""
        posts = CollaborationPost.objects.filter(is_active=True).select_related(
            'creator', 'creator__profile'
        ).prefetch_related('comments')
        
        # Apply filters
        tag_filter = request.query_params.get('tag')
        search = request.query_params.get('search')
        creator_filter = request.query_params.get('creator')
        
        if tag_filter:
            posts = posts.filter(tags__icontains=tag_filter)
        
        if search:
            posts = posts.filter(
                Q(title__icontains=search) | 
                Q(brief__icontains=search) |
                Q(tags__icontains=search)
            )
        
        if creator_filter:
            posts = posts.filter(creator__username__icontains=creator_filter)
        
        # Pagination
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 10))
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        
        total_posts = posts.count()
        paginated_posts = posts[start_index:end_index]
        
        serializer = CollaborationPostSerializer(
            paginated_posts, 
            many=True, 
            context={'request': request}
        )
        
        return Response({
            'posts': serializer.data,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': (total_posts + page_size - 1) // page_size,
                'total_posts': total_posts,
                'has_next': end_index < total_posts,
                'has_previous': page > 1
            },
            'filters_applied': {
                'tag': tag_filter,
                'search': search,
                'creator': creator_filter
            }
        })
    
    def post(self, request):
        """Create a new collaboration post"""
        serializer = CreateCollaborationPostSerializer(data=request.data)
        
        if serializer.is_valid():
            post = serializer.save(creator=request.user)
            response_serializer = CollaborationPostSerializer(
                post, 
                context={'request': request}
            )
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CollaborationPostDetailView(APIView):
    """Get, update, or delete a specific collaboration post"""
    permission_classes = [IsAuthenticated]
    
    def get_object(self, post_id, user=None):
        """Get post object with permission check for edit/delete"""
        try:
            post = CollaborationPost.objects.select_related('creator').get(
                id=post_id, 
                is_active=True
            )
            if user and post.creator != user:
                return None  # Not authorized for edit/delete
            return post
        except CollaborationPost.DoesNotExist:
            return None
    
    def get(self, request, post_id):
        """Get post details with comments"""
        post = self.get_object(post_id)
        if not post:
            return Response({
                'error': 'Post not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Get comments
        comments = Comment.objects.filter(post=post).select_related(
            'commenter', 'commenter__profile'
        ).prefetch_related('mentioned_users')
        
        post_serializer = CollaborationPostSerializer(
            post, 
            context={'request': request}
        )
        comments_serializer = CommentSerializer(comments, many=True, context={'request': request})
        
        return Response({
            'post': post_serializer.data,
            'comments': comments_serializer.data
        })
    
    def put(self, request, post_id):
        """Update collaboration post (creator only)"""
        post = self.get_object(post_id, request.user)
        if not post:
            return Response({
                'error': 'Post not found or you are not authorized to edit this post'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = CreateCollaborationPostSerializer(
            post, 
            data=request.data, 
            partial=False
        )
        
        if serializer.is_valid():
            updated_post = serializer.save()
            response_serializer = CollaborationPostSerializer(
                updated_post, 
                context={'request': request}
            )
            return Response(response_serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, post_id):
        """Partially update collaboration post (creator only)"""
        post = self.get_object(post_id, request.user)
        if not post:
            return Response({
                'error': 'Post not found or you are not authorized to edit this post'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = CreateCollaborationPostSerializer(
            post, 
            data=request.data, 
            partial=True
        )
        
        if serializer.is_valid():
            updated_post = serializer.save()
            response_serializer = CollaborationPostSerializer(
                updated_post, 
                context={'request': request}
            )
            return Response(response_serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, post_id):
        """Delete collaboration post (creator only)"""
        post = self.get_object(post_id, request.user)
        if not post:
            return Response({
                'error': 'Post not found or you are not authorized to delete this post'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Soft delete
        post.is_active = False
        post.save()
        
        return Response({
            'message': 'Post deleted successfully'
        }, status=status.HTTP_200_OK)

class PostCommentsView(APIView):
    """Handle comments on collaboration posts"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, post_id):
        """Get all top-level comments for a post (replies are included in comments)"""
        try:
            post = CollaborationPost.objects.get(id=post_id, is_active=True)
        except CollaborationPost.DoesNotExist:
            return Response({
                'error': 'Post not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Get only top-level comments (parent_comment is None)
        comments = Comment.objects.filter(
            post=post, 
            parent_comment=None
        ).select_related(
            'commenter', 'commenter__profile'
        ).prefetch_related('mentioned_users', 'replies__commenter__profile')
        
        serializer = CommentSerializer(comments, many=True, context={'request': request})
        return Response({
            'comments': serializer.data,
            'total_comments': Comment.objects.filter(post=post).count(),  # Total including replies
            'top_level_comments': comments.count()
        })
    
    def post(self, request, post_id):
        """Add a comment or reply to a post"""
        try:
            post = CollaborationPost.objects.get(id=post_id, is_active=True)
        except CollaborationPost.DoesNotExist:
            return Response({
                'error': 'Post not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = CreateCommentSerializer(data=request.data)
        
        if serializer.is_valid():
            # Validate parent comment belongs to the same post
            parent_comment = serializer.validated_data.get('parent_comment_id')
            if parent_comment and parent_comment.post != post:
                return Response({
                    'error': 'Parent comment does not belong to this post'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            comment = serializer.save(
                post=post,
                commenter=request.user
            )
            
            # Create notification logic
            if comment.parent_comment:
                # This is a reply - notification is handled in the model save method
                pass
            else:
                # This is a top-level comment - notify post creator
                if post.creator != request.user:
                    Notification.objects.create(
                        user=post.creator,
                        type='POST_COMMENT',
                        title=f'{request.user.username} commented on your post',
                        # message=f'{request.user.username} commented on "{post.title}"',
                        related_post=post,
                        related_comment=comment,
                        related_user=request.user
                    )
            
            response_serializer = CommentSerializer(comment, context={'request': request})
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ================================
# REPLY SYSTEM SPECIFIC APIS  
# ================================

class CommentRepliesView(APIView):
    """Get all replies for a specific comment"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, comment_id):
        """Get all replies for a specific comment"""
        try:
            # Get the parent comment
            parent_comment = Comment.objects.get(id=comment_id)
        except Comment.DoesNotExist:
            return Response({
                'error': 'Comment not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Get all replies to this comment
        replies = Comment.objects.filter(
            parent_comment=parent_comment
        ).select_related(
            'commenter', 'commenter__profile'
        ).prefetch_related('mentioned_users').order_by('created_at')
        
        # Pagination for replies
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 10))
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        
        total_replies = replies.count()
        paginated_replies = replies[start_index:end_index]
        
        serializer = CommentSerializer(paginated_replies, many=True, context={'request': request})
        
        return Response({
            'parent_comment': {
                'id': str(parent_comment.id),
                'content': parent_comment.content,
                'commenter': parent_comment.commenter.username,
                'created_at': parent_comment.created_at
            },
            'replies': serializer.data,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': (total_replies + page_size - 1) // page_size,
                'total_replies': total_replies,
                'has_next': end_index < total_replies,
                'has_previous': page > 1
            }
        })

class TopLevelCommentsView(APIView):
    """Get only top-level comments (no replies) for a post"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, post_id):
        """Get only top-level comments for a post"""
        try:
            post = CollaborationPost.objects.get(id=post_id, is_active=True)
        except CollaborationPost.DoesNotExist:
            return Response({
                'error': 'Post not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Get only top-level comments (no parent_comment)
        comments = Comment.objects.filter(
            post=post,
            parent_comment=None  # Only top-level comments
        ).select_related(
            'commenter', 'commenter__profile'
        ).prefetch_related('mentioned_users').order_by('created_at')
        
        # Pagination
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 10))
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        
        total_comments = comments.count()
        paginated_comments = comments[start_index:end_index]
        
        serializer = CommentSerializer(paginated_comments, many=True, context={'request': request})
        
        return Response({
            'comments': serializer.data,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': (total_comments + page_size - 1) // page_size,
                'total_comments': total_comments,
                'total_replies': Comment.objects.filter(post=post, parent_comment__isnull=False).count(),
                'has_next': end_index < total_comments,
                'has_previous': page > 1
            }
        })

class CommentThreadView(APIView):
    """Get a complete comment thread (comment + all its replies)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, comment_id):
        """Get a comment and all its replies in a threaded format"""
        try:
            # Get the main comment (must be top-level)
            main_comment = Comment.objects.get(id=comment_id, parent_comment=None)
        except Comment.DoesNotExist:
            return Response({
                'error': 'Top-level comment not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Get all replies
        replies = Comment.objects.filter(
            parent_comment=main_comment
        ).select_related(
            'commenter', 'commenter__profile'
        ).prefetch_related('mentioned_users').order_by('created_at')
        
        # Serialize main comment and replies
        main_comment_serializer = CommentSerializer(main_comment, context={'request': request})
        replies_serializer = CommentSerializer(replies, many=True, context={'request': request})
        
        return Response({
            'thread': {
                'main_comment': main_comment_serializer.data,
                'replies': replies_serializer.data,
                'total_replies': replies.count(),
                'last_reply_at': replies.last().created_at if replies.exists() else None
            }
        })

class UserCommentsView(APIView):
    """Get all comments and replies by a specific user"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, user_id=None):
        """Get all comments by user (defaults to current user)"""
        if user_id:
            try:
                target_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({
                    'error': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)
        else:
            target_user = request.user
        
        # Get all comments by user
        comments = Comment.objects.filter(
            commenter=target_user
        ).select_related(
            'post', 'commenter__profile', 'parent_comment'
        ).prefetch_related('mentioned_users').order_by('-created_at')
        
        # Filter by type if requested
        comment_type = request.query_params.get('type')  # 'comments', 'replies', or 'all'
        if comment_type == 'comments':
            comments = comments.filter(parent_comment=None)
        elif comment_type == 'replies':
            comments = comments.filter(parent_comment__isnull=False)
        
        # Pagination
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        
        total_comments = comments.count()
        paginated_comments = comments[start_index:end_index]
        
        # Enhanced serializer data
        comments_data = []
        for comment in paginated_comments:
            comment_data = CommentSerializer(comment, context={'request': request}).data
            comment_data['post_info'] = {
                'id': str(comment.post.id),
                'title': comment.post.title,
                'creator': comment.post.creator.username
            }
            comments_data.append(comment_data)
        
        return Response({
            'user': {
                'id': str(target_user.id),
                'username': target_user.username,
                'is_current_user': target_user == request.user
            },
            'comments': comments_data,
            'statistics': {
                'total_comments': Comment.objects.filter(commenter=target_user, parent_comment=None).count(),
                'total_replies': Comment.objects.filter(commenter=target_user, parent_comment__isnull=False).count(),
                'total_mentions': target_user.mentions.count()
            },
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': (total_comments + page_size - 1) // page_size,
                'total_items': total_comments,
                'has_next': end_index < total_comments,
                'has_previous': page > 1
            }

        })

class CommentDetailView(APIView):
    """Get detailed information about a specific comment"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, comment_id):
        """Get detailed comment information with context"""
        try:
            comment = Comment.objects.select_related(
                'commenter__profile', 'post', 'parent_comment__commenter'
            ).prefetch_related('mentioned_users').get(id=comment_id)
        except Comment.DoesNotExist:
            return Response({
                'error': 'Comment not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Serialize comment
        comment_serializer = CommentSerializer(comment, context={'request': request})
        
        # Add additional context
        response_data = comment_serializer.data
        response_data['context'] = {
            'post': {
                'id': str(comment.post.id),
                'title': comment.post.title,
                'creator': comment.post.creator.username
            },
            'engagement': {
                'reply_count': comment.replies.count(),
                'mention_count': comment.mentioned_users.count(),
                'can_reply': True,  # Could add permission logic here
                'can_edit': comment.commenter == request.user,
                'can_delete': comment.commenter == request.user or comment.post.creator == request.user
            }
        }
        
        # If this is a reply, add parent context
        if comment.parent_comment:
            response_data['context']['parent_comment'] = {
                'id': str(comment.parent_comment.id),
                'commenter': comment.parent_comment.commenter.username,
                'content_preview': comment.parent_comment.content[:100] + '...' if len(comment.parent_comment.content) > 100 else comment.parent_comment.content
            }
        
        return Response(response_data)

