import jwt
from datetime import datetime, timedelta

SECRET_KEY = 'your_secret_key'

def create_jwt_token(user_id):
    """
    Create a JWT token for a user.
    """
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def verify_jwt_token(token):
    """
    Verify the JWT token and return the payload if valid.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

user_id = 123
token = create_jwt_token(user_id)
print("JWT Token:", token)

payload = verify_jwt_token(token)
if payload:
    print("Token is valid. User ID:", payload['user_id'])
else:
    print("Token is invalid or expired.")
