import hashlib
import hmac
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import json

class WalletAuthenticationMixin:
    """Mixin for wallet signature verification"""
    
    def verify_signature(self, message, signature, public_key):
        """
        Verify signature for different wallet types
        This is a simplified version - in production you'd need proper
        signature verification for each wallet type
        """
        try:
            # For testing purposes, we'll use a simple verification
            # In production, implement proper signature verification
            return len(signature) > 0 and len(public_key) > 0
        except Exception:
            return False
    
    def generate_nonce(self):
        """Generate a random nonce for wallet authentication"""
        import secrets
        return secrets.token_hex(16)
    
    def create_sign_message(self, nonce, wallet_address):
        """Create the message that needs to be signed"""
        return f"Sign this message to authenticate with ZEFE: {nonce}\nWallet: {wallet_address}"