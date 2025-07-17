# Collaboration System Views
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Q
from .models import (
    User, UserProfile, CollaborationPost, Comment, Notification, 
    Connection, ConnectionRequest
)
from .serializers import (
    CollaborationPostSerializer, CreateCollaborationPostSerializer, CommentSerializer,
    CreateCommentSerializer, NotificationSerializer, UserSearchSerializer
)

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
            posts = posts.filter(tags__contains=[tag_filter])
        
        if search:
            posts = posts.filter(
                Q(title__icontains=search) | 
                Q(brief__icontains=search) |
                Q(tags__contains=[search])
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
        comments_serializer = CommentSerializer(comments, many=True)
        
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
        """Get all comments for a post"""
        try:
            post = CollaborationPost.objects.get(id=post_id, is_active=True)
        except CollaborationPost.DoesNotExist:
            return Response({
                'error': 'Post not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        comments = Comment.objects.filter(post=post).select_related(
            'commenter', 'commenter__profile'
        ).prefetch_related('mentioned_users')
        
        serializer = CommentSerializer(comments, many=True)
        return Response({
            'comments': serializer.data,
            'total_comments': comments.count()
        })
    
    def post(self, request, post_id):
        """Add a comment to a post"""
        try:
            post = CollaborationPost.objects.get(id=post_id, is_active=True)
        except CollaborationPost.DoesNotExist:
            return Response({
                'error': 'Post not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        serializer = CreateCommentSerializer(data=request.data)
        
        if serializer.is_valid():
            comment = serializer.save(
                post=post,
                commenter=request.user
            )
            
            # Create notification for post creator (if not commenting on own post)
            if post.creator != request.user:
                Notification.objects.create(
                    user=post.creator,
                    type='POST_COMMENT',
                    title=f'New comment on your post',
                    message=f'{request.user.username} commented on "{post.title}"',
                    related_post=post,
                    related_comment=comment,
                    related_user=request.user
                )
            
            response_serializer = CommentSerializer(comment)
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserSearchView(APIView):
    """Search users for mentions/tagging"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Search users by username or name for autocomplete"""
        query = request.query_params.get('q', '').strip()
        
        if len(query) < 2:
            return Response({
                'users': [],
                'message': 'Query must be at least 2 characters'
            })
        
        # Search by username and profile full_name
        users = User.objects.filter(
            Q(username__icontains=query) |
            Q(profile__full_name__icontains=query),
            is_active=True,
            is_onboarded=True
        ).exclude(
            id=request.user.id  # Exclude current user
        ).select_related('profile')[:10]  # Limit to 10 results
        
        serializer = UserSearchSerializer(users, many=True)
        return Response({
            'users': serializer.data
        })

class CollaborationNotificationsView(APIView):
    """Handle collaboration notifications"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get user notifications"""
        notifications = Notification.objects.filter(
            user=request.user
        ).select_related(
            'related_user', 'related_post', 'related_comment'
        ).order_by('-created_at')
        
        # Pagination
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        
        total_notifications = notifications.count()
        unread_count = notifications.filter(is_read=False).count()
        paginated_notifications = notifications[start_index:end_index]
        
        serializer = NotificationSerializer(paginated_notifications, many=True)
        
        return Response({
            'notifications': serializer.data,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_pages': (total_notifications + page_size - 1) // page_size,
                'total_notifications': total_notifications,
                'unread_count': unread_count,
                'has_next': end_index < total_notifications,
                'has_previous': page > 1
            }
        })
    
    def patch(self, request):
        """Mark notifications as read"""
        notification_ids = request.data.get('notification_ids', [])
        
        if notification_ids:
            # Mark specific notifications as read
            updated = Notification.objects.filter(
                id__in=notification_ids,
                user=request.user
            ).update(is_read=True)
            
            return Response({
                'message': f'{updated} notifications marked as read'
            })
        else:
            # Mark all notifications as read
            updated = Notification.objects.filter(
                user=request.user,
                is_read=False
            ).update(is_read=True)
            
            return Response({
                'message': f'All {updated} notifications marked as read'
            })

class MessageButtonView(APIView):
    """Check connection status for message button functionality"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Check if users are connected and get appropriate action"""
        other_user_id = request.query_params.get('user_id')
        
        if not other_user_id:
            return Response({
                'error': 'user_id parameter is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            other_user = User.objects.get(id=other_user_id)
        except User.DoesNotExist:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check if connected
        connection = Connection.objects.filter(
            (Q(user1=request.user) & Q(user2=other_user)) |
            (Q(user1=other_user) & Q(user2=request.user))
        ).first()
        
        if connection:
            # Users are connected - get Telegram info
            try:
                other_profile = other_user.profile
                telegram_username = other_profile.telegram_username
                
                if telegram_username:
                    telegram_url = f"https://t.me/{telegram_username}"
                    return Response({
                        'status': 'connected',
                        'action': 'open_telegram',
                        'telegram_url': telegram_url,
                        'telegram_username': telegram_username,
                        'message': f'Message {other_user.username} on Telegram'
                    })
                else:
                    return Response({
                        'status': 'connected',
                        'action': 'no_telegram',
                        'message': f'{other_user.username} has not provided Telegram username'
                    })
            except:
                return Response({
                    'status': 'connected',
                    'action': 'no_telegram',
                    'message': f'{other_user.username} has not completed profile'
                })
        else:
            # Check if there's a pending request
            existing_request = ConnectionRequest.objects.filter(
                Q(sender=request.user, receiver=other_user) |
                Q(sender=other_user, receiver=request.user),
                status='PENDING'
            ).first()
            
            if existing_request:
                if existing_request.sender == request.user:
                    return Response({
                        'status': 'request_sent',
                        'action': 'wait',
                        'message': 'Connection request already sent'
                    })
                else:
                    return Response({
                        'status': 'request_received',
                        'action': 'respond',
                        'message': 'You have a pending connection request from this user',
                        'request_id': existing_request.id
                    })
            else:
                return Response({
                    'status': 'not_connected',
                    'action': 'send_request',
                    'message': f'Send connection request to {other_user.username}'
                })
