from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    # API Info
    path('', views.APIInfoView.as_view(), name='api_info'),
    
    # Test authentication
    path('auth/test-login/', views.TestLoginView.as_view(), name='test_login'),
    path('auth/protected-test/', views.ProtectedTestView.as_view(), name='protected_test'),
    
    # Mock wallet authentication for testing
    path('auth/mock-wallet-login/', views.MockWalletLoginView.as_view(), name='mock_wallet_login'),
    
    # Real wallet authentication
    path('auth/request-nonce/', views.request_nonce, name='request_nonce'),
    path('auth/wallet-login/', views.wallet_login, name='wallet_login'),
    
    # JWT token refresh
    path('auth/token-refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # User endpoints
    path('current-user/', views.CurrentUserView.as_view(), name='current_user'),
    
    # Attendees endpoints
    path('attendees/', views.AttendeesView.as_view(), name='attendees'),
    path('attendees/stats/', views.AttendeesStatsView.as_view(), name='attendees_stats'),
    path('attendees/<uuid:user_id>/', views.AttendeeDetailView.as_view(), name='attendee_detail'),
    
    # Onboarding endpoints
    path('onboarding/', views.OnboardingView.as_view(), name='onboarding'),                    # GET, POST
    path('onboarding/update/', views.OnboardingUpdateView.as_view(), name='onboarding_update'), # PUT, PATCH
    path('onboarding/options/', views.OnboardingOptionsView.as_view(), name='onboarding_options'),
    
    # Profile management
    path('profile/', views.ProfileView.as_view(), name='profile'),
]