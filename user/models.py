from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import uuid
import re

POSITIONS = [
    ("ADVISOR", "Advisor"),
    ("AMBASSADOR", "Ambassador"),
    ("ANALYST", "Analyst"),
    ("ASSOCIATE", "Associate"),
    ("OPERATING_PARTNER", "Operating Partner"),
    ("MANAGING_PARTNER", "Managing Partner"),
    ("GENERAL_PARTNER", "General Partner"),
    ("AUDITOR", "Auditor"),
    ("BLOCKCHAIN_ARCHITECT", "Blockchain Architect"),
    ("BLOCKCHAIN_DEVELOPER", "Blockchain Developer"),
    ("COMMUNITY_MANAGER", "Community Manager"),
    ("CO_FOUNDER", "Co-Founder"),
    ("CURATOR", "Curator"),
    ("DATA_ANALYST", "Data Analyst"),
    ("DESIGNER", "Designer"),
    ("DEVELOPER", "Developer"),
    ("DEVOPS_ENGINEER", "DevOps Engineer"),
    ("DAPP_DEVELOPER", "dApp Developer"),
    ("ECOSYSTEM_LEAD", "Ecosystem Lead"),
    ("ENGINEER", "Engineer"),
    ("ETHICAL_HACKER", "Ethical Hacker"),
    ("FULL_STACK_DEVELOPER", "Full-Stack Developer"),
    ("GAME_DESIGNER", "Game Designer"),
    ("GRAPHIC_DESIGNER", "Graphic Designer"),
    ("HOST", "Host"),
    ("INFRASTRUCTURE_ENGINEER", "Infrastructure Engineer"),
    ("INTERN", "Intern"),
    ("INVESTOR", "Investor"),
    ("KOL", "KOL"),
    ("LEGAL_CONSULTANT", "Legal Consultant"),
    ("MARKETER", "Marketer"),
    ("METAVERSE_ARCHITECT", "Metaverse Architect"),
    ("MODERATOR", "Moderator"),
    ("NFT_SPECIALIST", "NFT Specialist"),
    ("EVENT_ORGANIZER", "Event Organizer"),
    ("PRODUCT_MANAGER", "Product Manager"),
    ("PROJECT_MANAGER", "Project Manager"),
    ("PROTOCOL_DEVELOPER", "Protocol Developer"),
    ("RESEARCHER", "Researcher"),
    ("SECURITY_ENGINEER", "Security Engineer"),
    ("SMART_CONTRACT_DEVELOPER", "Smart Contract Developer"),
    ("SOCIAL_MEDIA_MANAGER", "Social Media Manager"),
    ("STRATEGIST", "Strategist"),
    ("TOKENOMICS_STRATEGIST", "Tokenomics Strategist"),
    ("TRADER", "Trader"),
    ("VALIDATOR", "Validator"),
    ("VENTURE_CAPITALIST", "Venture Capitalist"),
    ("CONSULTANT", "Consultant"),
]

VERTICALS = [
    ("ACCELERATOR", "Accelerator"),
    ("AI", "AI"),
    ("BLOCKCHAIN", "Blockchain"),
    ("COMMUNITY", "Community"),
    ("DAO", "DAO"),
    ("DATA", "Data"),
    ("DEFI", "DeFi"),
    ("DEX", "DEX"),
    ("EVM", "EVM"),
    ("EVENT", "Event"),
    ("GAMEFI", "GameFi"),
    ("INVESTMENT", "Investment"),
    ("MARKETPLACE", "Marketplace"),
    ("METAVERSE", "Metaverse"),
    ("MINING", "Mining"),
    ("NFT", "NFT"),
    ("ORACLE", "Oracle"),
    ("RWA", "RWA"),
    ("SECURITY", "Security"),
    ("SOCIAL", "Social"),
    ("STABLECOIN", "Stablecoin"),
    ("STORAGE", "Storage"),
    ("TOKENIZATION", "Tokenization"),
    ("TRADING", "Trading"),
    ("WALLET", "Wallet"),
]

CHAIN_ECOSYSTEMS = [
    ("BITCOIN", "Bitcoin"),
    ("ETHEREUM", "Ethereum"),
    ("SOLANA", "Solana"),
    ("BINANCE_SMART_CHAIN", "Binance Smart Chain"),
    ("CARDANO", "Cardano"),
    ("POLKADOT", "Polkadot"),
    ("AVALANCHE", "Avalanche"),
    ("TRON", "Tron"),
    ("COSMOS", "Cosmos"),
    ("NEAR", "Near"),
    ("TEZOS", "Tezos"),
    ("ALGORAND", "Algorand"),
    ("FLOW", "Flow"),
    ("HEDERA", "Hedera"),
    ("RIPPLE", "Ripple"),
    ("DOGECOIN", "Dogecoin"),
    ("CHIA", "Chia"),
    ("STELLAR", "Stellar"),
    ("EOS", "EOS"),
    ("NEO", "NEO"),
    ("VECHAIN", "VeChain"),
    ("IOTA", "IOTA"),
    ("LISK", "Lisk"),
    ("ARK", "Ark"),
    ("ZILLIQA", "Zilliqa"),
    ("QTUM", "Qtum"),
    ("WANCHAIN", "Wanchain"),
    ("MULTIVERSX", "MultiversX"),
    ("CELO", "Celo"),
    ("THORCHAIN", "THORChain"),
    ("KLAYTN", "Klaytn"),
    ("HARMONY", "Harmony"),
    ("SECRET_NETWORK", "Secret Network"),
    ("OASIS_NETWORK", "Oasis Network"),
    ("SKALE", "Skale"),
    ("TELOS", "Telos"),
    ("ENERGI", "Energi"),
    ("RSK", "RSK"),
    ("ERGO", "Ergo"),
    ("BERACHAIN", "Berachain"),
    ("PLUME_NETWORK", "Plume Network"),
    ("TON", "TON"),
    ("MONAD", "Monad"),
    ("MOVEMENT", "Movement"),
    ("SEI", "Sei"),
    ("CELESTIA", "Celestia"),
    ("POLYGON", "Polygon"),
    ("ARBITRUM", "Arbitrum"),
    ("OPTIMISM", "Optimism"),
    ("BASE", "Base"),
    ("MANTLE", "Mantle"),
    ("BLAST", "Blast"),
    ("STARKNET", "Starknet"),
    ("HYPERLEDGER", "Hyperledger"),
    ("MAPLE_FINANCE", "Maple Finance"),
    ("BABYLON", "Babylon"),
    ("DEEPBOOK", "DeepBook"),
]

CITIES = [
    ("ABU_DHABI", "Abu Dhabi"),
    ("AMSTERDAM", "Amsterdam"),
    ("AUSTIN", "Austin"),
    ("BALI", "Bali"),
    ("BANGALORE", "Bangalore"),
    ("BANGKOK", "Bangkok"),
    ("BARCELONA", "Barcelona"),
    ("BELGRADE", "Belgrade"),
    ("BERLIN", "Berlin"),
    ("BRNO", "Brno"),
    ("BRUSSELS", "Brussels"),
    ("BUCHAREST", "Bucharest"),
    ("BUENOS_AIRES", "Buenos Aires"),
    ("CHIANG_MAI", "Chiang Mai"),
    ("DA_NANG", "Da Nang"),
    ("DAVOS", "Davos"),
    ("DUBAI", "Dubai"),
    ("HO_CHI_MINH_CITY", "Ho Chi Minh City"),
    ("HONG_KONG", "Hong Kong"),
    ("ISTANBUL", "Istanbul"),
    ("KUALA_LUMPUR", "Kuala Lumpur"),
    ("KYOTO", "Kyoto"),
    ("LA_PAZ", "La Paz"),
    ("LAGOS", "Lagos"),
    ("LISBON", "Lisbon"),
    ("LONDON", "London"),
    ("LOS_ANGELES", "Los Angeles"),
    ("LUGANO", "Lugano"),
    ("MADRID", "Madrid"),
    ("MALTA", "Malta"),
    ("MANILA", "Manila"),
    ("MEDELLIN", "Medellin"),
    ("MEXICO_CITY", "Mexico City"),
    ("MIAMI", "Miami"),
    ("MILAN", "Milan"),
    ("MONTREAL", "Montreal"),
    ("MUNICH", "Munich"),
    ("NAIROBI", "Nairobi"),
    ("NEW_YORK_CITY", "New York City"),
    ("OXFORD", "Oxford"),
    ("PARIS", "Paris"),
    ("PORTO", "Porto"),
    ("PRAGUE", "Prague"),
    ("RIO_DE_JANEIRO", "Rio de Janeiro"),
    ("ROATAN", "Roatan"),
    ("ROME", "Rome"),
    ("SALT_LAKE_CITY", "Salt Lake City"),
    ("SAN_FRANCISCO", "San Francisco"),
    ("SAN_JUAN", "San Juan"),
    ("SEOUL", "Seoul"),
    ("SINGAPORE", "Singapore"),
    ("SPLIT", "Split"),
    ("STANFORD", "Stanford"),
    ("STOCKHOLM", "Stockholm"),
    ("TAIPEI", "Taipei"),
    ("TEL_AVIV", "Tel Aviv"),
    ("TOKYO", "Tokyo"),
    ("TORONTO", "Toronto"),
    ("VIENNA", "Vienna"),
    ("WARSAW", "Warsaw"),
    ("ZUG", "Zug"),
    ("ZURICH", "Zurich"),
]

COMMUNITIES = [
    ("ALLMIGHT_US", "Allmight US"),
    ("SOL_BROTHERS", "Sol Brothers"),
    ("SKYLINE", "Skyline"),
    ("BLUESHIFT", "Blueshift"),
    ("SUPERTEAM_INDIA", "Superteam India"),
    ("SUPERTEAM_BALKAN", "Superteam Balkan"),
    ("SUPERTEAM_BRAZIL", "Superteam Brazil"),
    ("SUPERTEAM_CANADA", "Superteam Canada"),
    ("SUPERTEAM_FRANCE", "Superteam France"),
    ("SUPERTEAM_GERMANY", "Superteam Germany"),
    ("SUPERTEAM_IRELAND", "Superteam Ireland"),
    ("SUPERTEAM_JAPAN", "Superteam Japan"),
    ("SUPERTEAM_KOREA", "Superteam Korea"),
    ("SUPERTEAM_MALAYSIA", "Superteam Malaysia"),
    ("SUPERTEAM_MEXICO", "Superteam Mexico"),
    ("SUPERTEAM_NIGERIA", "Superteam Nigeria"),
    ("SUPERTEAM_PHILIPPINES", "Superteam Philippines"),
    ("SUPERTEAM_POLAND", "Superteam Poland"),
    ("SUPERTEAM_SINGAPORE", "Superteam Singapore"),
    ("SUPERTEAM_TURKEY", "Superteam Turkey"),
    ("SUPERTEAM_UAE", "Superteam UAE"),
    ("SUPERTEAM_UK", "Superteam UK"),
    ("SUPERTEAM_VIETNAM", "Superteam Vietnam"),
]

class User(AbstractUser):
    """Custom User model with wallet authentication"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nonce = models.CharField(max_length=100, null=True, blank=True)
    is_onboarded = models.BooleanField(default=False)
    email = models.EmailField(null=True, blank=True)

    def __str__(self):
        return self.username or str(self.id)

class Wallet(models.Model):
    """Model for user wallets (supports multiple wallets per user)"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='wallets')
    address = models.CharField(max_length=100, unique=True)
    wallet_type = models.CharField(max_length=50, blank=True)  # e.g., 'solana', 'ethereum'
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.address} ({self.wallet_type})"

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
    
    # Profile Image
    avatar_url = models.URLField(blank=True)  # For external image URLs
    image = models.ImageField(upload_to="profiles/", blank=True, null=True)  # For uploaded images
    
    # Preferences
    wants_updates = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.full_name or self.user.username} ({self.user.username})"

class Vertical(models.Model):
    """Model for project verticals"""
    name = models.CharField(max_length=50, choices=VERTICALS, unique=True)

    def __str__(self):
        return self.name

# Connection System Models
class ConnectionRequest(models.Model):
    """Model for connection requests between users"""
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('ACCEPTED', 'Accepted'),
        ('REJECTED', 'Rejected'),
        ('SPAM', 'Marked as Spam'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_requests')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_requests')
    note_content = models.TextField(blank=True, max_length=500)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['sender', 'receiver']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.sender.username} → {self.receiver.username} ({self.status})"

class Connection(models.Model):
    """Model for established connections between users"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='connections_as_user1')
    user2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='connections_as_user2')
    connection_request = models.OneToOneField(ConnectionRequest, on_delete=models.CASCADE, related_name='connection')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user1', 'user2']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user1.username} ↔ {self.user2.username}"
    
    def save(self, *args, **kwargs):
        # Ensure user1 has lower ID to avoid duplicates
        if self.user1.id > self.user2.id:
            self.user1, self.user2 = self.user2, self.user1
        super().save(*args, **kwargs)

class SpamReport(models.Model):
    """Model for spam reports"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reported_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='spam_reports_made')
    reported_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='spam_reports')
    connection_request = models.ForeignKey(ConnectionRequest, on_delete=models.CASCADE, related_name='spam_reports')
    reason = models.TextField(blank=True, max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['reported_user', 'reported_by', 'connection_request']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.reported_by.username} reported {self.reported_user.username}"

class UserSpamScore(models.Model):
    """Model to track user spam scores"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='spam_score_record')
    spam_score = models.IntegerField(default=0)
    is_banned = models.BooleanField(default=False)
    banned_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        status = "BANNED" if self.is_banned else f"Score: {self.spam_score}"
        return f"{self.user.username} - {status}"
    
    def increment_score(self):
        """Increment spam score and check if user should be banned"""
        self.spam_score += 1
        if self.spam_score >= 10 and not self.is_banned:
            self.is_banned = True
            self.banned_at = timezone.now()
            # Optionally deactivate user account
            self.user.is_active = False
            self.user.save()
        self.save()
    
    def is_banned_user(self):
        """Check if user is currently banned"""
        return self.is_banned
    
    def increase_spam_score(self):
        """Alias for increment_score to maintain consistency"""
        return self.increment_score()

# Collaboration System Models
class CollaborationPost(models.Model):
    """Model for collaboration posts on home page"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='collaboration_posts')
    title = models.CharField(max_length=200)
    brief = models.TextField(max_length=1000)
    due_date = models.DateTimeField()
    tags = models.JSONField(default=list, blank=True)  # Store as list of strings
    link = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
        
    def __str__(self):
        return f"{self.title} by {self.creator.username}"
    
    @property
    def brief_preview(self):
        """Return first 7 words of brief"""
        words = self.brief.split()
        if len(words) <= 7:
            return self.brief
        return ' '.join(words[:7]) + '...'
    
    @property
    def comment_count(self):
        """Get total comment count"""
        return self.comments.count()

class Comment(models.Model):
    """Model for comments on collaboration posts"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    post = models.ForeignKey(CollaborationPost, on_delete=models.CASCADE, related_name='comments')
    commenter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    content = models.TextField(max_length=500)
    mentioned_users = models.ManyToManyField(User, blank=True, related_name='mentions')
    
    # Reply functionality
    parent_comment = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['created_at']
        
    def __str__(self):
        if self.parent_comment:
            return f"Reply by {self.commenter.username} to {self.parent_comment.commenter.username}"
        return f"Comment by {self.commenter.username} on {self.post.title}"
    
    @property
    def is_reply(self):
        """Check if this comment is a reply to another comment"""
        return self.parent_comment is not None
    
    @property
    def reply_count(self):
        """Get total number of replies to this comment"""
        return self.replies.count()
    
    def save(self, *args, **kwargs):
        """Extract mentioned users from content and create notifications"""
        is_new = self.pk is None
        super().save(*args, **kwargs)
        
        if is_new:
            # Extract mentions using regex
            import re
            mentions = re.findall(r'@(\w+)', self.content)
            mentioned_users = User.objects.filter(username__in=mentions)
            
            # Add mentioned users
            self.mentioned_users.set(mentioned_users)
            
            # Create notifications for mentions
            for user in mentioned_users:
                if user != self.commenter:  # Don't notify self
                    Notification.objects.create(
                        user=user,
                        type='MENTION',
                        title=f'{self.commenter.username} mentioned you',
                        message=f'{self.commenter.username} mentioned you in "{self.post.title}"',
                        related_post=self.post,
                        related_comment=self,
                        related_user=self.commenter
                    )
            
            # Create notification for reply (if this is a reply)
            if self.parent_comment and self.parent_comment.commenter != self.commenter:
                Notification.objects.create(
                    user=self.parent_comment.commenter,
                    type='COMMENT_REPLY',
                    title=f'{self.commenter.username} replied to your comment',
                    message=f'{self.commenter.username} replied to your comment on "{self.post.title}"',
                    related_post=self.post,
                    related_comment=self,
                    related_user=self.commenter
                )

class Notification(models.Model):
    """Model for user notifications"""
    TYPE_CHOICES = [
        ('MENTION', 'Mention in Comment'),
        ('CONNECTION_ACCEPTED', 'Connection Request Accepted'),
        ('CONNECTION_REQUEST', 'New Connection Request'),
        ('POST_COMMENT', 'New Comment on Post'),
        ('COMMENT_REPLY', 'Reply to Comment'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    title = models.CharField(max_length=200)
    message = models.TextField(max_length=500)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Optional related objects
    related_post = models.ForeignKey(CollaborationPost, on_delete=models.CASCADE, null=True, blank=True)
    related_comment = models.ForeignKey(Comment, on_delete=models.CASCADE, null=True, blank=True)
    related_connection_request = models.ForeignKey(ConnectionRequest, on_delete=models.CASCADE, null=True, blank=True)
    related_user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='notifications_about')
    
    class Meta:
        ordering = ['-created_at']
        
    def __str__(self):
        return f"{self.type} notification for {self.user.username}"