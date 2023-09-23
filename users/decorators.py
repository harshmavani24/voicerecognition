import jwt
from django.conf import settings
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render

def jwt_token_required(view_func):
    def decorator(request, *args, **kwargs):
        # Get the token from the cookie or local storage
        token = request.COOKIES.get('jwt')
        if not token:
            return redirect('/login')  # Redirect to login if token is missing

        try:
            # Decode the token
            payload = jwt.decode(token,'secret',algorithms=['HS256'])
            
            # Check if user ID is available in the decoded token
            user_id = payload.get('id')
            if not user_id:
                return redirect('/login')  # Redirect to login if user ID is missing
            
            # If the token is valid and user ID is available, proceed to the view
            # Add the decoded token to the request object for further use if needed
            request.decoded_token = payload
            return view_func(request, *args, **kwargs)

        except jwt.ExpiredSignatureError:
            return HttpResponseForbidden('Token Expired')  # Redirect to login if token has expired
        
        except jwt.InvalidTokenError:
            # Handle the case of an invalid token
            return HttpResponseForbidden('Invalid Token')

    return decorator
