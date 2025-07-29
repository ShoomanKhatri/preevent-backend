from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from . import collaboration_views
from .views import (
    TestLoginView, MockWalletLoginView, ProtectedTestView,
    CurrentUserView, OnboardingView, OnboardingUpdateView, OnboardingOptionsView, AttendeesView,
    AttendeeDetailView, AttendeesStatsView,
    SendConnectionRequestView, RespondToConnectionRequestView, MyConnectionRequestsView,
    MyConnectionsView, ReportSpamView, ConnectionStatusView, NotificationsCountView,
    NotificationsListView, MarkNotificationReadView, MarkAllNotificationsReadView,
    CollaborationPostsView, CollaborationPostDetailView, PostCommentsView,
    CommentRepliesView, CommentThreadView, CommentDetailView, TopLevelCommentsView,
    UserCommentsView, ProfileView, GoogleLoginView
)
from .collaboration_views import (
    UserSearchView, CollaborationNotificationsView, MessageButtonView
)

urlpatterns = [
    # API Info
    path('', views.APIInfoView.as_view(), name='api_info'),

     path('google-login/', GoogleLoginView.as_view(), name='google_login'),
    
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
    
    # Connection system endpoints
    path('connections/send-request/', SendConnectionRequestView.as_view(), name='send_connection_request'),
    path('connections/respond/', RespondToConnectionRequestView.as_view(), name='respond_connection_request'),
    path('connections/my-requests/', MyConnectionRequestsView.as_view(), name='my_connection_requests'),
    path('connections/my-connections/', MyConnectionsView.as_view(), name='my_connections'),
    path('connections/status/', ConnectionStatusView.as_view(), name='connection_status'),
    path('report-spam/', ReportSpamView.as_view(), name='report_spam'),
    
    # Notification endpoints
    path('notifications/count/', NotificationsCountView.as_view(), name='notifications_count'),
    path('notifications/', NotificationsListView.as_view(), name='notifications_list'),
    
    # Collaboration System endpoints
    path('collaborations/', views.CollaborationPostsView.as_view(), name='collaboration_posts'),
    path('collaborations/<uuid:post_id>/', views.CollaborationPostDetailView.as_view(), name='collaboration_post_detail'),
    path('collaborations/<uuid:post_id>/comments/', views.PostCommentsView.as_view(), name='post_comments'),
    path('users/search/', UserSearchView.as_view(), name='user_search'),
    path('collaborations/notifications/', CollaborationNotificationsView.as_view(), name='collaboration_notifications'),
    path('message-button/', MessageButtonView.as_view(), name='message_button'),
    path('notifications/<uuid:notification_id>/read/', views.MarkNotificationReadView.as_view(), name='mark_notification_read'),
    path('notifications/mark-all-read/', views.MarkAllNotificationsReadView.as_view(), name='mark_all_notifications_read'),
    
    # Reply System Specific APIs
    path('comments/<uuid:comment_id>/replies/', views.CommentRepliesView.as_view(), name='comment_replies'),
    path('comments/<uuid:comment_id>/thread/', views.CommentThreadView.as_view(), name='comment_thread'),
    path('comments/<uuid:comment_id>/detail/', views.CommentDetailView.as_view(), name='comment_detail'),
    path('collaborations/<uuid:post_id>/top-comments/', views.TopLevelCommentsView.as_view(), name='top_level_comments'),
    path('users/<uuid:user_id>/comments/', views.UserCommentsView.as_view(), name='user_comments'),
    path('my-comments/', views.UserCommentsView.as_view(), name='my_comments'),
    
    # Collaboration System endpoints
    path('collaboration/posts/', views.CollaborationPostsView.as_view(), name='collaboration_posts'),
    path('collaboration/posts/<uuid:post_id>/', views.CollaborationPostDetailView.as_view(), name='collaboration_post_detail'),
    path('collaboration/posts/<uuid:post_id>/comments/', views.PostCommentsView.as_view(), name='post_comments'),
    path('collaboration/user-search/', UserSearchView.as_view(), name='collaboration_user_search'),
    path('collaboration/notifications/', CollaborationNotificationsView.as_view(), name='collaboration_notifications_detailed'),
    
    # Onboarding endpoints
    path('onboarding/', views.OnboardingView.as_view(), name='onboarding'),                    # GET, POST
    path('onboarding/update/', views.OnboardingUpdateView.as_view(), name='onboarding_update'), # PUT, PATCH
    path('onboarding/options/', views.OnboardingOptionsView.as_view(), name='onboarding_options'),
    
    # Profile management
    path('profile/', views.ProfileView.as_view(), name='profile'),
]