import requests
from jose import jwt
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model

CLERK_JWKS_URL = "https://ample-lionfish-11.clerk.accounts.dev/.well-known/jwks.json"
CLERK_ISSUER = "https://ample-lionfish-11.clerk.accounts.dev"
CLERK_AUDIENCE = "http://localhost:8081"

User = get_user_model()

class ClerkJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            # print("DEBUG: Missing or invalid Authorization header")
            return None

        token = auth_header.split(" ")[1]
        # print(f"DEBUG: Received JWT token: {token[:20]}...")

        try:
            jwks_resp = requests.get(CLERK_JWKS_URL)
            jwks_resp.raise_for_status()
            jwks = jwks_resp.json()
            # print(f"DEBUG: JWKS keys: {[k['kid'] for k in jwks.get('keys', [])]}")
        except Exception as e:
            # print(f"DEBUG: Failed to fetch JWKS: {e}")
            raise AuthenticationFailed(f"Failed to fetch JWKS: {e}")

        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            # print(f"DEBUG: JWT header: {unverified_header}")
            if not kid:
                raise AuthenticationFailed("JWT header missing 'kid' field")
            key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
            if not key:
                raise AuthenticationFailed(f"No matching public key for kid: {kid}")
        except Exception as e:
            # print(f"DEBUG: Error processing JWT header: {e}")
            raise AuthenticationFailed(f"Error processing JWT header: {e}")

        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=CLERK_AUDIENCE,
                issuer=CLERK_ISSUER,
            )
            # print(f"DEBUG: JWT payload: {payload}")
        except Exception as e:
            # print(f"DEBUG: JWT decode error: {e}")
            raise AuthenticationFailed(f"Invalid token: {e}")

        # Get or create Django user
        email = None
        if "email_addresses" in payload and payload["email_addresses"]:
            email = payload["email_addresses"][0]
        elif "email" in payload and payload["email"]:
            email = payload["email"]
        username = payload.get("sub")
        name = payload.get("first_name", "")

        # print(f"DEBUG: Creating/fetching user: username={username}, email={email}, name={name}")

        try:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={"email": email, "first_name": name}
            )
            if created:
                print(f"DEBUG: Created new user: {user}")
            else:
                print(f"DEBUG: Fetched existing user: {user}")
        except Exception as e:
            print(f"DEBUG: User creation error: {e}")
            raise AuthenticationFailed(f"User creation error: {e}")

        return (user, None)