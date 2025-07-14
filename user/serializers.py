from rest_framework import serializers
from django.contrib.auth import authenticate
from django.db import IntegrityError
from .models import User, UserProfile, Vertical, ChainEcosystem

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'wallet_address', 'email', 'first_name', 'last_name', 'is_onboarded']
        read_only_fields = ['id']

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

class WalletLoginSerializer(serializers.Serializer):
    wallet_address = serializers.CharField(max_length=100)
    signature = serializers.CharField(max_length=500)
    message = serializers.CharField(max_length=500)
    
    def validate(self, attrs):
        wallet_address = attrs.get('wallet_address')
        signature = attrs.get('signature')
        message = attrs.get('message')
        
        if not all([wallet_address, signature, message]):
            raise serializers.ValidationError("All fields are required")
        
        return attrs

class MockWalletLoginSerializer(serializers.Serializer):
    """Mock wallet login serializer for testing without signature verification"""
    wallet_address = serializers.CharField(max_length=100)
    wallet_type = serializers.CharField(max_length=20, default='solana')
    
    def validate_wallet_address(self, value):
        if len(value) < 10:
            raise serializers.ValidationError("Wallet address must be at least 10 characters")
        return value
    
    def validate_wallet_type(self, value):
        allowed_types = ['solana', 'ethereum', 'bitcoin', 'phantom', 'metamask']
        if value.lower() not in allowed_types:
            raise serializers.ValidationError(f"Wallet type must be one of: {', '.join(allowed_types)}")
        return value.lower()

class TestLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class NonceRequestSerializer(serializers.Serializer):
    wallet_address = serializers.CharField(max_length=100)
    wallet_type = serializers.CharField(max_length=20, default='solana')
    
    def validate_wallet_address(self, value):
        if len(value) < 10:
            raise serializers.ValidationError("Wallet address must be at least 10 characters")
        return value