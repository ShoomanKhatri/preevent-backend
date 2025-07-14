from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid

POSITIONS = [
    ("CO_FOUNDER", "Co-founder"),
    ("DEVELOPER", "Developer"),
    ("DESIGNER", "Designer"),
    ("MARKETER", "Marketer"),
]

VERTICALS = [
    ("DeFi", "DeFi"),
    ("NFT", "NFT"),
    ("Gaming", "Gaming"),
    ("Infra", "Infra"),
    ("Social", "Social"),
    ("Tokenization", "Tokenization"),
]

CHAIN_ECOSYSTEMS = [
    ("SOLANA", "Solana"),
    ("ETHEREUM", "Ethereum"),
    ("POLKADOT", "Polkadot"),
    ("BITCOIN", "Bitcoin"),
    ("AVALANCHE", "Avalanche"),
    ("POLYGON", "Polygon"),
]

class User(AbstractUser):
    """Custom User model with wallet authentication"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wallet_address = models.CharField(max_length=100, unique=True, null=True, blank=True)
    nonce = models.CharField(max_length=100, null=True, blank=True)
    is_onboarded = models.BooleanField(default=False)  # Track if user completed onboarding
    
    def __str__(self):
        return self.username or self.wallet_address or str(self.id)

class ChainEcosystem(models.Model):
    """Model for blockchain ecosystems"""
    name = models.CharField(max_length=50, choices=CHAIN_ECOSYSTEMS, unique=True)
    
    def __str__(self):
        return self.name

class UserProfile(models.Model):
    """Extended user profile for onboarding"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Basic Information
    full_name = models.CharField(max_length=100, blank=True)
    bio = models.TextField(blank=True)
    city = models.CharField(max_length=100, blank=True)
    
    # Professional Information
    position = models.CharField(max_length=50, choices=POSITIONS, blank=True)
    project_name = models.CharField(max_length=100, blank=True)
    superteam_chapter = models.CharField(max_length=100, blank=True)
    
    # Many-to-Many relationships
    verticals = models.ManyToManyField("Vertical", blank=True)
    chain_ecosystems = models.ManyToManyField("ChainEcosystem", blank=True)
    
    # Social Links
    telegram_username = models.CharField(max_length=100, blank=True)
    twitter_username = models.CharField(max_length=100, blank=True)
    linkedin_url = models.URLField(blank=True)
    email = models.EmailField(blank=True)
    
    # Profile Image
    avatar_url = models.URLField(blank=True)  # For external image URLs
    image = models.ImageField(upload_to="profiles/", blank=True, null=True)  # For uploaded images
    
    # Preferences
    wants_updates = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.full_name or self.user.username} ({self.user.wallet_address or self.user.username})"

class Vertical(models.Model):
    """Model for project verticals"""
    name = models.CharField(max_length=50, choices=VERTICALS, unique=True)

    def __str__(self):
        return self.name