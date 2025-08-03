from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, UserProfile, Wallet, Vertical, ChainEcosystem, ConnectionRequest, Connection

class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = True
    extra = 0

class WalletInline(admin.TabularInline):
    model = Wallet
    can_delete = True
    extra = 0

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline, WalletInline)
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_onboarded', 'is_staff', 'date_joined')
    list_filter = ('is_onboarded', 'is_staff', 'is_superuser', 'is_active', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    
    # Enable bulk delete actions
    actions = ['delete_selected']
    
    # Add custom fields to the user form
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Custom Fields', {
            'fields': ('nonce', 'is_onboarded'),
        }),
    )

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'full_name', 'position', 'city', 'created_at')
    list_filter = ('position', 'city', 'wants_updates', 'created_at')
    search_fields = ('user__username', 'full_name', 'project_name')
    actions = ['delete_selected']

@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = ('address', 'wallet_type', 'user', 'created_at')
    list_filter = ('wallet_type', 'created_at')
    search_fields = ('address', 'user__username')
    actions = ['delete_selected']

@admin.register(Vertical)
class VerticalAdmin(admin.ModelAdmin):
    list_display = ('name',)
    actions = ['delete_selected']

@admin.register(ChainEcosystem)
class ChainEcosystemAdmin(admin.ModelAdmin):
    list_display = ('name',)
    actions = ['delete_selected']

@admin.register(ConnectionRequest)
class ConnectionRequestAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'status', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('sender__username', 'receiver__username')
    actions = ['delete_selected']

@admin.register(Connection)
class ConnectionAdmin(admin.ModelAdmin):
    list_display = ('user1', 'user2', 'created_at')
    search_fields = ('user1__username', 'user2__username')
    actions = ['delete_selected']
