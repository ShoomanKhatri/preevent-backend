from rest_framework import serializers
from django.contrib.auth import authenticate
from django.db import IntegrityError
from django.db import models
from django.utils import timezone
import re
from .models import (
    User, UserProfile, Vertical, ChainEcosystem, ConnectionRequest, Connection, 
    SpamReport, UserSpamScore, CollaborationPost, Comment, Notification, Wallet
)

class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['address', 'wallet_type']

class UserSerializer(serializers.ModelSerializer):
    wallets = WalletSerializer(many=True, read_only=True)  # Add this

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_onboarded', 'wallets']  # Remove 'wallet_address'

class VerticalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vertical
        fields = ['id', 'name']

class ChainEcosystemSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChainEcosystem
        fields = ['id', 'name']

class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    verticals = VerticalSerializer(many=True, read_only=True)
    chain_ecosystems = ChainEcosystemSerializer(many=True, read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'user', 'full_name', 'bio', 'city', 'position', 'project_name', 
            'superteam_chapter', 'verticals', 'chain_ecosystems', 'telegram_username',
            'twitter_username', 'linkedin_url', 'email', 'avatar_url', 'image',
            'wants_updates', 'created_at', 'updated_at'
        ]

class OnboardingSerializer(serializers.ModelSerializer):
    """Serializer for user onboarding"""
    verticals = serializers.ListField(
        child=serializers.CharField(max_length=50),
        write_only=True,
        required=False,
        allow_empty=True
    )
    chain_ecosystems = serializers.ListField(
        child=serializers.CharField(max_length=50),
        write_only=True,
        required=False,
        allow_empty=True
    )
    wallet_address = serializers.CharField(max_length=100, required=False)
    wants_updates = serializers.BooleanField(default=False, required=False)
    
    class Meta:
        model = UserProfile
        fields = [
            'full_name', 'telegram_username', 'city', 'bio', 'position',
            'project_name', 'chain_ecosystems', 'verticals', 'twitter_username',
            'linkedin_url', 'email', 'wallet_address', 'avatar_url', 'superteam_chapter',
            'wants_updates'
        ]
    
    def create(self, validated_data):
        user = self.context['request'].user
        
        # Extract many-to-many data
        verticals_data = validated_data.pop('verticals', [])
        chain_ecosystems_data = validated_data.pop('chain_ecosystems', [])
        wallet_address = validated_data.pop('wallet_address', None)
        
        # Handle wallet address update
        if wallet_address:
            # Only update if it's different from the current wallet address
            if wallet_address != user.wallet_address:
                # Check if another user (not the current user) has this wallet address
                existing_user = User.objects.filter(wallet_address=wallet_address).exclude(id=user.id).first()
                if existing_user:
                    raise serializers.ValidationError({
                        'wallet_address': 'This wallet address is already associated with another user.'
                    })
                
                try:
                    user.wallet_address = wallet_address
                    user.save()
                except IntegrityError:
                    raise serializers.ValidationError({
                        'wallet_address': 'This wallet address is already in use.'
                    })
        
        # Create or update profile
        profile, created = UserProfile.objects.get_or_create(user=user)
        
        # Update profile fields
        for field, value in validated_data.items():
            setattr(profile, field, value)
        
        profile.save()
        
        # Handle verticals
        if verticals_data:
            profile.verticals.clear()
            for vertical_name in verticals_data:
                vertical, _ = Vertical.objects.get_or_create(name=vertical_name)
                profile.verticals.add(vertical)
        
        # Handle chain ecosystems
        if chain_ecosystems_data:
            profile.chain_ecosystems.clear()
            for ecosystem_name in chain_ecosystems_data:
                ecosystem, _ = ChainEcosystem.objects.get_or_create(name=ecosystem_name)
                profile.chain_ecosystems.add(ecosystem)
        
        # Mark user as onboarded
        user.is_onboarded = True
        user.save()
        
        return profile
    
    def update(self, instance, validated_data):
        user = instance.user
        
        # Extract many-to-many data
        verticals_data = validated_data.pop('verticals', None)
        chain_ecosystems_data = validated_data.pop('chain_ecosystems', None)
        wallet_address = validated_data.pop('wallet_address', None)
        
        # Handle wallet address update
        if wallet_address:
            # Only update if it's different from the current wallet address
            if wallet_address != user.wallet_address:
                # Check if another user (not the current user) has this wallet address
                existing_user = User.objects.filter(wallet_address=wallet_address).exclude(id=user.id).first()
                if existing_user:
                    raise serializers.ValidationError({
                        'wallet_address': 'This wallet address is already associated with another user.'
                    })
                
                try:
                    user.wallet_address = wallet_address
                    user.save()
                except IntegrityError:
                    raise serializers.ValidationError({
                        'wallet_address': 'This wallet address is already in use.'
                    })
        
        # Update profile fields
        for field, value in validated_data.items():
            setattr(instance, field, value)
        
        instance.save()
        
        # Handle verticals
        if verticals_data is not None:
            instance.verticals.clear()
            for vertical_name in verticals_data:
                vertical, _ = Vertical.objects.get_or_create(name=vertical_name)
                instance.verticals.add(vertical)
        
        # Handle chain ecosystems
        if chain_ecosystems_data is not None:
            instance.chain_ecosystems.clear()
            for ecosystem_name in chain_ecosystems_data:
                ecosystem, _ = ChainEcosystem.objects.get_or_create(name=ecosystem_name)
                instance.chain_ecosystems.add(ecosystem)
        
        # Mark user as onboarded
        user.is_onboarded = True
        user.save()
        
        return instance

class TestLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class MockWalletLoginSerializer(serializers.Serializer):
    wallet_address = serializers.CharField(max_length=100)
    username = serializers.CharField(max_length=150, required=False)
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(max_length=30, required=False)
    last_name = serializers.CharField(max_length=30, required=False)

class NonceRequestSerializer(serializers.Serializer):
    wallet_address = serializers.CharField(max_length=100)

class WalletLoginSerializer(serializers.Serializer):
    wallet_address = serializers.CharField(max_length=100)
    signature = serializers.CharField()
    nonce = serializers.CharField()
    username = serializers.CharField(max_length=150, required=False)
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(max_length=30, required=False)
    last_name = serializers.CharField(max_length=30, required=False)

class AttendeesSerializer(serializers.ModelSerializer):
    """Serializer for attendees list with profile information"""
    profile = UserProfileSerializer(read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'profile', 'wallets']  # Remove 'wallet_address', add 'wallets'
        read_only_fields = ['id', 'username', 'first_name', 'last_name']

# Connection System Serializers
class UserWithProfileSerializer(serializers.ModelSerializer):
    """Enhanced user serializer with profile information for connections"""
    profile = UserProfileSerializer(read_only=True)
    wallets = WalletSerializer(many=True, read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_onboarded', 'profile', 'wallets']  # Remove 'wallet_address'

class ConnectionRequestSerializer(serializers.ModelSerializer):
    sender = UserWithProfileSerializer(read_only=True)
    receiver = UserWithProfileSerializer(read_only=True)
    
    class Meta:
        model = ConnectionRequest
        fields = ['id', 'sender', 'receiver', 'note_content', 'status', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

class ConnectionSerializer(serializers.ModelSerializer):
    user1 = UserWithProfileSerializer(read_only=True)
    user2 = UserWithProfileSerializer(read_only=True)
    connection_request = ConnectionRequestSerializer(read_only=True)
    
    class Meta:
        model = Connection
        fields = ['id', 'user1', 'user2', 'connection_request', 'created_at']
        read_only_fields = ['created_at']
        read_only_fields = ['created_at']

class SpamReportSerializer(serializers.ModelSerializer):
    reported_by = UserSerializer(read_only=True)
    reported_user = UserSerializer(read_only=True)
    
    class Meta:
        model = SpamReport
        fields = ['id', 'reported_by', 'reported_user', 'reason', 'created_at']
        read_only_fields = ['created_at']

class SendConnectionRequestSerializer(serializers.Serializer):
    receiver_id = serializers.UUIDField()
    note_content = serializers.CharField(max_length=500, required=False, allow_blank=True)
    
    def validate_receiver_id(self, value):
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Receiver user does not exist")
        return value

class RespondToConnectionRequestSerializer(serializers.Serializer):
    request_id = serializers.UUIDField()
    response = serializers.ChoiceField(choices=['interested', 'not_interested', 'spam'])
    
    def validate_request_id(self, value):
        try:
            ConnectionRequest.objects.get(id=value)
        except ConnectionRequest.DoesNotExist:
            raise serializers.ValidationError("Connection request does not exist")
        return value

class ReportSpamSerializer(serializers.Serializer):
    reported_user_id = serializers.UUIDField()
    reason = serializers.CharField(max_length=500, required=False, allow_blank=True)
    
    def validate_reported_user_id(self, value):
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Reported user does not exist")
        return value

# Collaboration System Serializers
class CollaborationPostSerializer(serializers.ModelSerializer):
    """Serializer for reading collaboration posts"""
    creator = UserSerializer(read_only=True)
    creator_profile = serializers.SerializerMethodField()
    comments_count = serializers.SerializerMethodField()
    is_creator = serializers.SerializerMethodField()
    brief_preview = serializers.SerializerMethodField()
    tags_list = serializers.SerializerMethodField()
    
    class Meta:
        model = CollaborationPost
        fields = [
            'id', 'title', 'brief', 'brief_preview', 'due_date', 'tags', 'tags_list', 
            'link', 'creator', 'creator_profile', 'comments_count', 'is_creator', 
            'created_at', 'updated_at'
        ]
    
    def get_creator_profile(self, obj):
        """Get creator profile information"""
        try:
            profile = obj.creator.profile
            return {
                'full_name': profile.full_name,
                'avatar_url': profile.avatar_url,
                'position': profile.position,
                'city': profile.city
            }
        except:
            return None
    
    def get_comments_count(self, obj):
        """Get total comments count"""
        return obj.comments.count()
    
    def get_is_creator(self, obj):
        """Check if current user is the creator"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.creator == request.user
        return False
    
    def get_brief_preview(self, obj):
        """Get first 7 words of brief + 'more' if longer"""
        if not obj.brief:
            return ''
        
        words = obj.brief.split()
        if len(words) <= 7:
            return obj.brief
        
        preview = ' '.join(words[:7])
        return f"{preview}... more"
    
    def get_tags_list(self, obj):
        """Return tags as list"""
        if not obj.tags:
            return []
        # Tags are stored as JSONField (list), so return as-is
        if isinstance(obj.tags, list):
            return obj.tags
        # Fallback for string format (comma-separated)
        elif isinstance(obj.tags, str):
            return [tag.strip() for tag in obj.tags.split(',') if tag.strip()]
        return []

class CreateCollaborationPostSerializer(serializers.ModelSerializer):
    """Serializer for creating/updating collaboration posts"""
    
    class Meta:
        model = CollaborationPost
        fields = ['title', 'brief', 'due_date', 'tags', 'link']
    
    def validate_title(self, value):
        """Validate title"""
        if len(value.strip()) < 5:
            raise serializers.ValidationError("Title must be at least 5 characters long")
        return value.strip()
    
    def validate_brief(self, value):
        """Validate brief"""
        if len(value.strip()) < 10:
            raise serializers.ValidationError("Brief must be at least 10 characters long")
        return value.strip()
    
    def validate_due_date(self, value):
        """Validate due date is in the future"""
        # Convert both to datetime for comparison
        now = timezone.now()
        
        # If value is a date object, convert to datetime at end of day
        if hasattr(value, 'date') and not hasattr(value, 'hour'):
            # It's a date object, convert to datetime at end of day
            from datetime import datetime, time
            value = timezone.make_aware(datetime.combine(value, time.max))
        elif not hasattr(value, 'hour'):
            # Handle string dates or other formats
            from datetime import datetime, time
            if isinstance(value, str):
                # Parse string date
                try:
                    from datetime import datetime
                    parsed_date = datetime.strptime(value, '%Y-%m-%d').date()
                    value = timezone.make_aware(datetime.combine(parsed_date, time.max))
                except ValueError:
                    raise serializers.ValidationError("Invalid date format. Use YYYY-MM-DD")
        
        # Now compare datetime objects
        if value <= now:
            raise serializers.ValidationError("Due date must be in the future")
        
        return value
    
    def validate_tags(self, value):
        """Validate and clean tags"""
        if not value:
            return []
        
        # Handle both string and list inputs
        if isinstance(value, str):
            # Split comma-separated string into list
            tags = [tag.strip() for tag in value.split(',') if tag.strip()]
        elif isinstance(value, list):
            # Clean list of tags
            tags = [str(tag).strip() for tag in value if str(tag).strip()]
        else:
            tags = []
        
        if len(tags) > 10:
            raise serializers.ValidationError("Maximum 10 tags allowed")
        
        for tag in tags:
            if len(tag) > 30:
                raise serializers.ValidationError("Each tag must be less than 30 characters")
        
        return tags

class CommentSerializer(serializers.ModelSerializer):
    """Serializer for reading comments"""
    commenter = UserSerializer(read_only=True)
    commenter_profile = serializers.SerializerMethodField()
    is_commenter = serializers.SerializerMethodField()
    mentions = serializers.SerializerMethodField()
    mentioned_users_details = serializers.SerializerMethodField()
    replies = serializers.SerializerMethodField()
    reply_count = serializers.SerializerMethodField()
    is_reply = serializers.SerializerMethodField()
    parent_comment_info = serializers.SerializerMethodField()
    
    class Meta:
        model = Comment
        fields = [
            'id', 'content', 'commenter', 'commenter_profile', 'is_commenter', 
            'mentions', 'mentioned_users_details', 'replies', 'reply_count',
            'is_reply', 'parent_comment_info', 'created_at', 'updated_at'
        ]
    
    def get_commenter_profile(self, obj):
        """Get commenter profile information"""
        try:
            profile = obj.commenter.profile
            return {
                'full_name': profile.full_name,
                'avatar_url': profile.avatar_url,
                'position': profile.position
            }
        except:
            return None
    
    def get_is_commenter(self, obj):
        """Check if current user is the commenter"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.commenter == request.user
        return False
    
    def get_mentions(self, obj):
        """Extract @username mentions from content"""
        import re
        mention_pattern = r'@(\w+)'
        mentions = re.findall(mention_pattern, obj.content)
        return mentions
    
    def get_mentioned_users_details(self, obj):
        """Get details of mentioned users"""
        mentioned_users = obj.mentioned_users.all()
        result = []
        for user in mentioned_users:
            try:
                profile = user.profile
                result.append({
                    'id': str(user.id),
                    'username': user.username,
                    'display_name': profile.full_name if profile.full_name else user.username,
                    'avatar_url': profile.avatar_url
                })
            except:
                result.append({
                    'id': str(user.id),
                    'username': user.username,
                    'display_name': user.username,
                    'avatar_url': ''
                })
        return result

    def get_replies(self, obj):
        """Get replies to this comment (only direct replies, not nested)"""
        if obj.is_reply:
            return []  # Replies don't have their own replies to keep it simple
        
        replies = obj.replies.all().order_by('created_at')
        # Use a simplified serializer to avoid infinite recursion
        result = []
        for reply in replies:
            try:
                profile = reply.commenter.profile
                commenter_info = {
                    'full_name': profile.full_name,
                    'avatar_url': profile.avatar_url,
                    'position': profile.position
                }
            except:
                commenter_info = None
            
            result.append({
                'id': str(reply.id),
                'content': reply.content,
                'commenter': {
                    'id': str(reply.commenter.id),
                    'username': reply.commenter.username
                },
                'commenter_profile': commenter_info,
                'is_commenter': reply.commenter == self.context.get('request').user if self.context.get('request') else False,
                'created_at': reply.created_at,
                'updated_at': reply.updated_at
            })
        return result
    
    def get_reply_count(self, obj):
        """Get total number of replies"""
        return obj.replies.count()
    
    def get_is_reply(self, obj):
        """Check if this comment is a reply"""
        return obj.parent_comment is not None
    
    def get_parent_comment_info(self, obj):
        """Get parent comment info if this is a reply"""
        if not obj.parent_comment:
            return None
        
        try:
            profile = obj.parent_comment.commenter.profile
            commenter_info = {
                'full_name': profile.full_name,
                'avatar_url': profile.avatar_url,
                'position': profile.position
            }
        except:
            commenter_info = None
        
        return {
            'id': str(obj.parent_comment.id),
            'commenter': {
                'id': str(obj.parent_comment.commenter.id),
                'username': obj.parent_comment.commenter.username
            },
            'commenter_profile': commenter_info,
            'content_preview': obj.parent_comment.content[:50] + '...' if len(obj.parent_comment.content) > 50 else obj.parent_comment.content
        }

class CreateCommentSerializer(serializers.ModelSerializer):
    """Serializer for creating comments and replies"""
    parent_comment_id = serializers.UUIDField(required=False, allow_null=True)
    
    class Meta:
        model = Comment
        fields = ['content', 'parent_comment_id']
    
    def validate_content(self, value):
        """Validate comment content"""
        if len(value.strip()) < 1:
            raise serializers.ValidationError("Comment cannot be empty")
        if len(value) > 1000:
            raise serializers.ValidationError("Comment must be less than 1000 characters")
        return value.strip()
    
    def validate_parent_comment_id(self, value):
        """Validate parent comment exists and belongs to the same post"""
        if value is None:
            return None
        
        try:
            parent_comment = Comment.objects.get(id=value)
            # Ensure we can't reply to a reply (only 1 level deep)
            if parent_comment.parent_comment is not None:
                raise serializers.ValidationError("Cannot reply to a reply. Only one level of replies is allowed.")
            return parent_comment
        except Comment.DoesNotExist:
            raise serializers.ValidationError("Parent comment does not exist")
    
    def create(self, validated_data):
        """Create comment or reply"""
        parent_comment = validated_data.pop('parent_comment_id', None)
        comment = Comment.objects.create(
            parent_comment=parent_comment,
            **validated_data
        )
        return comment

class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for notifications"""
    
    class Meta:
        model = Notification
        fields = [
              'id', 'type', 'title', 'message', 'is_read', 'created_at',
            'related_post_id', 'related_comment_id', 'related_connection_request_id', 'related_user_id'
        ]

class UserSearchSerializer(serializers.ModelSerializer):
    """Serializer for user search/autocomplete for mentions"""
    display_name = serializers.SerializerMethodField()
    mention_text = serializers.SerializerMethodField()
    profile_info = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'username', 'display_name', 'mention_text', 'profile_info']
    
    def get_display_name(self, obj):
        """Get the display name (full_name or username)"""
        try:
            profile = obj.profile
            return profile.full_name if profile.full_name else obj.username
        except:
            return obj.username
    
    def get_mention_text(self, obj):
        """Get the text to insert when user is mentioned (@username)"""
        return f"@{obj.username}"
    
    def get_profile_info(self, obj):
        """Get additional profile info for display"""
        try:
            profile = obj.profile
            return {
                'full_name': profile.full_name,
                'avatar_url': profile.avatar_url,
                'position': profile.position,
                'city': profile.city,
                'telegram_username': profile.telegram_username
            }
        except:
            return {
                'full_name': '',
                'avatar_url': '',
                'position': '',
                'city': '',
                'telegram_username': ''
            }