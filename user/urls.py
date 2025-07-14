from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    # API Info
    path('', views.api_info, name='api_info'),
    
    # Test authentication
    path('auth/test-login/', views.test_login, name='test_login'),
    path('auth/protected-test/', views.protected_test, name='protected_test'),
    
    # Mock wallet authentication for testing
    path('auth/mock-wallet-login/', views.mock_wallet_login, name='mock_wallet_login'),
    
    # Real wallet authentication
    path('auth/request-nonce/', views.request_nonce, name='request_nonce'),
    path('auth/wallet-login/', views.wallet_login, name='wallet_login'),
    
    # JWT token refresh
    path('auth/token-refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # User endpoints
    path('current-user/', views.current_user, name='current_user'),
    
    # Onboarding endpoints
    path('onboarding/', views.onboarding, name='onboarding'),                    # GET, POST
    path('onboarding/update/', views.onboarding_update, name='onboarding_update'), # PUT, PATCH
    path('onboarding/options/', views.onboarding_options, name='onboarding_options'),
    
    # Profile management
    path('profile/', views.profile, name='profile'),
]