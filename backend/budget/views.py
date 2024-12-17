from django.shortcuts import render
from rest_framework import viewsets
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from dotenv import load_dotenv
import os
from django.conf import settings
from rest_framework.response import Response
from .serializers import UserSeralizers
from rest_framework.permissions import AllowAny
from django.core.mail import send_mail
from django.conf import settings
from plaid import ApiClient
from rest_framework.permissions import IsAuthenticated
from django.http import JsonResponse
from django.utils.crypto import get_random_string
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from rest_framework import status
import requests

from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes
from django.http import JsonResponse
from rest_framework.decorators import api_view



from .serializers import RegistrationSerializer, ProfileUpdateSerializer

from django.contrib.auth.hashers import make_password

from .models import Users
import logging
from django.shortcuts import render
from django import forms
from .serializers import LoginSeralizer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth import authenticate, login
from django.contrib.auth import authenticate, login as django_login
from django.utils.timezone import now
import usaddress
from geopy.geocoders import Nominatim

from .validators import PasswordValidator

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework.decorators import api_view
from rest_framework.response import Response
from firebase_admin import auth as firebase_auth
import re

from .validators import validate_email_format

import json

from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid import ApiClient, Configuration
from plaid.api import plaid_api
# Create your views here.



def get_plaid_client():
    configuration = Configuration(
        host=plaid_api.Environment.Sandbox,  # Change to Development or Production as needed
        api_key={
            'clientId': 'YOUR_PLAID_CLIENT_ID',
            'secret': 'YOUR_PLAID_SECRET',
        }
    )
    client = plaid_api.PlaidApi(ApiClient(configuration))
    return client



class TodoView(viewsets.ModelViewSet):
    serializer_class = UserSeralizers
    queryset = Users.objects.all()
@csrf_exempt
@api_view(['POST'])  # This will only allow POST requests
def save_email(request):
    email = request.data.get('Email')

    # Check if email is provided
    if not email:
        return JsonResponse({"error": "Email is required."}, status=400)

    # Validate the email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return JsonResponse({"error": "Invalid email format."}, status=400)

    # Check if the email already exists
    if Users.objects.filter(Email=email).exists():
        return JsonResponse({"error": "Email already exists."}, status=400)

    # Save email to the session (this is just an example, ensure session is set up)
    request.session['Email'] = email
    return JsonResponse({"message": "Email is valid and saved!"}, status=200)
@api_view(['POST'])
def save_personal_info(request):
    email = request.data.get('Email')
    password = request.data.get('Password')
    
    if not email or not password:
        return JsonResponse({"error": "Email and Password are required"}, status=400)
    
    try:
        validate_password(password)
    except ValidationError as e:
        return JsonResponse({"error": " ".join(e.messages)}, status=400)
    
    # Save the email and password to the session
    request.session['Email'] = email
    request.session['Password'] = password

    return JsonResponse({"message": "Personal information saved successfully!"}, status=200)
api_view(["POST"])
@csrf_exempt
def save_email_and_password(request):
    if request.method == "POST":
        try:
            # Parse the JSON request body
            data = json.loads(request.body)
            email = data.get("Email", "")
            password = data.get("Password", "")

            # Check for missing fields
            if not email or not password:
                return JsonResponse({"error": "Email and password are required."}, status=400)

            # Validate the password
            PasswordValidator().validate(password)  # Use custom or built-in password validation

            # Save the email and hashed password to the database
            hashed_password = make_password(password)
            user = Users.objects.create(email=email, password=hashed_password)

            return JsonResponse({"message": "User saved successfully."}, status=201)

        except ValidationError as e:
            return JsonResponse({"error": e.messages}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format."}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Method not allowed."}, status=405)
api_view(["POST"])
@csrf_exempt
def validate_password(request):
    try:
        if request.method == "POST":
            # Parse the JSON body
            data = json.loads(request.body)
            password = data.get("password", "")

            if not password:
                return JsonResponse({"error": "Password is required."}, status=400)

            # Validate the password
            PasswordValidator().validate(password)

            return JsonResponse({"message": "Password is valid."}, status=200)
        else:
            return JsonResponse({"error": "Method not allowed."}, status=405)
    except ValidationError as e:
        # Log the validation error
        print(f"Validation error: {e}")
        return JsonResponse({"error": e.messages}, status=400)
    except json.JSONDecodeError:
        # Log JSON decoding issues
        print("Invalid JSON data.")
        return JsonResponse({"error": "Invalid JSON format."}, status=400)
    except Exception as e:
        # Catch all other errors
        print(f"Unexpected error: {str(e)}")
        return JsonResponse({"error": "An unexpected error occurred."}, status=500)

@api_view(['POST'])
def complete_registration(request):
    # Retrieve all the data from the session
    email = request.session.get('email')
    first_name = request.session.get('first_name')
    last_name = request.session.get('last_name')
    birthday = request.session.get('birthday')
    password = request.data.get('Password')
    
    if not email or not first_name or not last_name or not birthday or not password:
        return Response({"error": "All fields are required."}, status=400)

    # Create the user and save to the database
    try:
        user = Users.objects.create(
            username=email,
            email=email,
            password = password
        )
        user.set_password(password)  # Hash the password before saving
        user.save()
        
        # Optionally clear session data after successful registration
        request.session.flush()  # This clears all session data for the user

        return Response({"message": "Registration complete!"}, status=201)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['POST'])
def api_register_user(request):
    serializer = UserSeralizers(data=request.data)  
    try:
     if serializer.is_valid():
        user = serializer.save()
        user.set_password(user.Password)  # Hash the password
        return Response(serializer.data, status=201)
    except IntegrityError as e:
         if 'UNIQUE constraint failed' in str(e):
            return JsonResponse({"message": "Email already exists, please choose a different email address."})
         else:
              return Response({'status': 'error', 'errors': serializer.errors}, status=400)
@api_view(['POST'])
def verify_google_token(request):
    token = request.data.get("token")
    if not token:
        return Response({"error": "Missing token"}, status=400)

    try:
        # Verify the Firebase ID token
        decoded_token = firebase_auth.verify_id_token(token)
        user_id = decoded_token["uid"]
        email = decoded_token.get("email")

        # Check if user exists in your database
        user = User.objects.filter(email=email).first()  # Assuming you are using Django's default User model

        if not user:
            # If user does not exist, create a new user (first-time login)
            user = User.objects.create_user(username=email, email=email)
        
        return Response({
            "uid": user_id,
            "email": email,
        })
        
    except Exception as e:
        return Response({"error": str(e)}, status=400)
    
@csrf_exempt
@csrf_exempt

@csrf_exempt


class LoginView(APIView):
    def post(self, request):
        Username = request.data.get("Username")
        Password = request.data.get("Password")
        user = authenticate(Username=Username, Password=Password)
        if user:
            return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

class PasswordValidator:
    special_characters = "[~\!@#\$%\^&\*\(\)_\+{}\":;'\[\]]"

    def validate(self, password):
        # Check for at least one digit
        if not any('0' <= char <= '9' for char in password):
            raise ValidationError(_('Password must contain at least 1 digit.'))
        # Check for at least one letter (upper or lowercase)
        if not any(('a' <= char <= 'z') or ('A' <= char <= 'Z') for char in password):
            raise ValidationError(_('Password must contain at least 1 letter.'))
        # Check for at least one special character
        if not any(char in self.special_characters for char in password):
            raise ValidationError(_('Password must contain at least 1 special character.'))
        # Check for minimum length
        if len(password) < 8:
            raise ValidationError(_('Password must be at least 8 characters long.'))

    def get_help_text(self):
        return _(
            "Your password must contain at least 1 digit, 1 letter, 1 special character, "
            "and must be at least 8 characters long."
        )



@api_view(['POST'])
@permission_classes([AllowAny])  # Ensure this is added
@csrf_exempt
def validate_email(request):
    email = request.data.get('email')
    if not email:
        return Response({'message': 'Email is required'}, status=400)
    if not validate_email_format(email):  # Implement this function for regex validation
        return Response({'message': 'Invalid email format'}, status=400)
    if Users.objects.filter(email=email).exists():
        return Response({'message': 'Email already in use'}, status=400)
    return Response({'message': 'Email is valid'}, status=200)

@api_view(['POST'])
@csrf_exempt
def validate_login_email(request):
    email = request.data.get('email')
    if not email:
        return Response({'message': 'Email is required.'}, status=400)
    if not Users.objects.filter(email=email).exists():
        return Response({'message': 'Email not registered.'}, status=404)
    return Response({'message': 'Email is valid.'}, status=200)


@api_view(['POST'])
def validate_login_details(request):
    email = request.data.get('Email')
    password = request.data.get('Password')
    if not email or not password:
        return Response({'message': 'Email and Password are required.'}, status=400)
    try:
        user = Users.objects.get(Email=email)
        if not user.check_password(password):  # Assuming you're using Django's `check_password`
            return Response({'message': 'Invalid credentials.'}, status=401)
        return Response({'message': 'Login successful.'}, status=200)
    except Users.DoesNotExist:
        return Response({'message': 'Email not registered.'}, status=404)

@api_view(['POST'])
@permission_classes([AllowAny])  # Ensure this is added
def validate_user(request):
    email = request.data.get('email')
    password = request.data.get('password')
    errors = {}

    # Email validation
    if not email:
        errors['email'] = 'Email is required.'
    elif Users.objects.filter(email=email).exists():
        errors['email'] = 'Email already in use.'

    # Password validation
    if not password:
        errors['password'] = 'Password is required.'
    elif len(password) < 8:
        errors['password'] = 'Password must be at least 8 characters long.'
    elif not any(char.isdigit() for char in password):
        errors['password'] = 'Password must contain at least one number.'
    elif not any(char.isupper() for char in password):
        errors['password'] = 'Password must contain at least one uppercase letter.'

    if errors:
        return Response(errors, status=400)

    # Save user if validation passes
    user = Users.objects.create(email=email, password= make_password(password))
    return JsonResponse({
            "message": "User created successfully!",
            "user_id": user.id
        }, status=201)
@csrf_exempt
@api_view(["POST"])
def validate_credentials(request):
    if request.method == "POST":
        try:
            # Parse the request body
            data = json.loads(request.body)
            email = data.get("Email", "")
            password = data.get("Password", "")

            # Validate email and password
            validate_email(email)
            PasswordValidator().validate(password)

            return JsonResponse({"message": "Email and Password are valid!"}, status=200)

        except ValidationError as e:
            return JsonResponse({"errors": e.messages}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"errors": ["Invalid JSON data."]}, status=400)
    else:
        return JsonResponse({"errors": ["Method not allowed."]}, status=405)

@api_view(['POST'])
def login_email(request):
    email = request.data.get('Email')

    if not email:
        return Response({'message': 'Email is required'}, status=400)

    # Use the custom user model
    User = get_user_model()

    # Check if the email exists in the database
    if not User.objects.filter(Email=email).exists():
        return Response({'message': 'Email not registered'}, status=404)

    return Response({'message': 'Email validated'}, status=200)
@api_view(['POST'])
def login_user(request):
    email = request.data.get('Email')
    password = request.data.get('Password')

    print(f"Attempting login with Email: {email}, Password: {password}")

    if not email or not password:
        return Response({'message': 'Email and Password are required'}, status=400)

    user = authenticate(username=email, password=password)
    print(f"Authenticated user: {user}")

    if user is None:
        return Response({'message': 'Invalid email or password'}, status=401)

    # Generate or retrieve the token
    token, _ = Token.objects.get_or_create(user=user)
     # Save the token in the User model
    user.token = token.key
    user.save()

    if user.last_login == None:
        return Response({
        'message': 'Please complete your profile',
        'token': token.key
        })
    
    else:

     return Response({
        'message': 'Login successful',
        'token': token.key
    }, status=200)

@api_view(['POST'])
def send_confirmation_email(request):
    email = request.data.get('Email')

    if not email:
        return JsonResponse({'error': 'Email is required'}, status=400)

    # Generate a confirmation token (this could be a JWT or any token system)
    token = get_random_string(length=32)  # You can create a better token with expiration etc.

    # Generate confirmation link (Make sure this route exists in your app)
    confirmation_link = f'http://your-frontend-url/confirm-email/{token}'

    subject = 'Please Confirm Your Email Address'
    message = f'Click the link below to confirm your email address:\n\n{confirmation_link}'
    from_email = settings.EMAIL_HOST_USER

    try:
        send_mail(subject, message, from_email, [email])
        return JsonResponse({'message': 'Confirmation email sent successfully'}, status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
class RegisterUserView(APIView):
    """
    Handles initial registration with email and password.
    """
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Save email in session to ensure continuation
            request.session['email'] = user.email
            return Response({"message": "Registration successful."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateProfileView(APIView):
    """
    Allows users to update profile after initial login.
    """
    def post(self, request):
        email = request.session.get('email')
        if not email:
            return Response({"error": "No active session found."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = ProfileUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Profile updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class CustomLoginView(APIView):
    api_view(["POST"])
    def post(self, request):
        email = request.data.get('Email')
        password = request.data.get('Password')

        if not email:
            return Response({"detail": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Use email instead of username for authentication
        user = authenticate(request, username=email)
        

        if user is not None:
            # If the user is authenticated, get or create the token
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.id,
                'email': user.email,

            })
        else:
            return Response({"detail": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)
class ValidateLoginEmailView(APIView):
    permission_classes = [AllowAny]  # Allow public access to this endpoint

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email:
            return Response({'message': 'Email is required.'}, status=400)

        if not Users.objects.filter(email=email).exists():
            return Response({'message': 'Email not registered.'}, status=404)

        return Response({'message': 'Email is valid.'}, status=200)
class RefreshTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Get the refresh token from the request
        refresh_token = request.data.get('refresh_token')
        
        if not refresh_token:
            return Response({'error': 'Refresh token is required'}, status=400)
        
        try:
            # Parse the refresh token to generate a new access token
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)
            
            # Return the new access token
            return Response({
                'access_token': new_access_token
            }, status=200)
        except Exception as e:
            return Response({'error': str(e)}, status=400)

class ValidateLoginDetailsView(APIView):
    permission_classes = [AllowAny]  # Public access to this endpoint

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name')

        # Check if both email and password are provided
        if not email or not password:
            return Response(
                {'message': 'Email and Password are required.'},
                status=400
            )

        # Authenticate the user
        user = authenticate(email=email, password=password)
        if user is None:
            return Response(
                {'message': 'Invalid email or password.'},
                status=401
            )
    
        
        django_login(request, user)

        refresh = RefreshToken.for_user(user)
        new_access_token = str(refresh.access_token)
        new_refresh_token = str(refresh)

        print(f"New Access Token {new_access_token}")
        print(f"New Refresh Token {new_refresh_token}")

        # Update user tokens in the database
        user.access_token = new_access_token
        user.refresh_token = new_refresh_token
        user.save()
        first_name = request.data.get('first_name')
        birthday = request.data.get('birthday')
        gender = request.data.get('gender')
        address = request.data.get('address')
        city = request.data.get('city')
        state = request.data.get('state')

         # Save tokens to the user model


        # Check if it's the user's first login
        if user.is_first_login or not first_name or not birthday or not gender or not address or not city or not state :
            user.is_first_login = False
            print(user.last_login)
            user.save()
            return Response({
                'message': 'Welcome! This is your first login.',
                'first_login': True,
                'access_token': new_access_token,
                'refresh_token': new_refresh_token
            }, status=200)
        else:
         return Response({
            'message': 'Password is valid.',
            'first_login': False,
            'access_token': new_access_token,
            'refresh_token': new_refresh_token
        }, status=200)
   
def validate_info(request): 
 first_name = request.data.get("first_name")
 last_name = request.data.get('last_name')
 gender = request.data.get('gender')
 birthday = request.data.get('birthday')

 if first_name.upper() and last_name.upper() and gender == None:
    return Response("First and last name must be lowercase")
 else:
    return Response("First and Last name are valid")

def validate_address(request):
    address = request.data.get("address")

    try:
        ##Checks the address entered 
        parsed_address = usaddress.parse(address)

        if parsed_address:
            Response("Address is valid")
    except usaddress.RepeatedLabelError:
          Response("Please enter a valid address")


logger = logging.getLogger(__name__)


logger = logging.getLogger(__name__)


api_view(["POST"])
class completeBasicInfo(APIView):
    permission_classes = [AllowAny]  # Allow public access to this endpoin
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        gender = request.data.get('gender')
        birthday = request.data.get('birthday')



        # Validation logic
        if not first_name or not gender or not birthday:
            return Response({'message': 'All fields are required.'}, status=400)
        
        try:
            user = Users.objects.get(email = email)
        except Users.DoesNotExist:
            return Response({'message': 'User does not exist.'}, status=404)
        
        user.first_name = first_name
        user.last_name = last_name
        user.gender = gender
        user.birthday = birthday
        user.save()

        try:
            user.save()
            return Response({"Message": "User information updated successfully."}, status=200)
        except Exception as e:
            return Response({"Message": "Failed to update user information.", "error": str(e)}, status=500)

class ValidateAddressInfoView(APIView):
    permission_classes = [AllowAny]


    def post(self, request):

       # Extract input fields from request data
     email = request.data.get('email')
     address = request.data.get("address")
     city = request.data.get("city")
     state = request.data.get("state")
    
    # Your PositionStack API key
     api_key = 'd140fb9a855f8f16408e296dc89e3c31'
    
    # Combine address, city, and state to form the full address
     full_address = f'{address}, {city}, {state}'
    
    # PositionStack API endpoint
     url = "http://api.positionstack.com/v1/forward"
    
    # Set up the parameters for the API request
     params = {
        'access_key': api_key,
        'query': full_address,
        'limit': 1,
        "output": "json"
    }
    
    # Send the request to the PositionStack API
     response = requests.get(url, params=params)

    # Check if the request was successful
     if response.status_code == 200:
        data = response.json()
        
        if data["data"]:
            # Address is valid, extract relevant information
            result = data["data"][0]
            return JsonResponse({
                "valid": True,
                "address": result.get("label", "No address available"),
                "city": result.get("city"),
                "state": result.get("region"),
                "country": result.get("country"),
                "latitude": result.get("latitude"),
                "longitude": result.get("longitude")
            })
        
        else:
            # No matching address found
            return JsonResponse({"valid": False, "error": "Address not found"})
     else:
        # API request failed
        return JsonResponse({"valid": False, "error": "API request failed"})


class SaveCompletedProfile(APIView):

    permission_classes = [AllowAny]

    def post(self, request):
      user = request.user
      data = request.data

      try:
            # Update user information
            user.first_name = data.get('first_name', user.first_name)
            user.last_name = data.get('last_name', user.last_name)
            user.bank_name = data.get('bank_name')
            user.account_number = data.get('account_number')
            user.routing_number = data.get('routing_number')
            user.save()

            # Save additional info if needed
            return Response({"message": "Profile updated successfully with bank information."}, status=200)
      except Exception as e:
            return Response({"error": str(e)}, status=400)

api_view(["POST"])
class TellerAccountsProxyView(APIView):
   permission_classes = [IsAuthenticated]


   def post(self, request):
        teller_access_token = request.data.get("tellerAccessToken")
        if not teller_access_token:
            return Response({"error": "Missing Teller access token"}, status=400)

        # Use the Teller access token to fetch bank information
        url = "https://api.teller.io/accounts"
        headers = {"Authorization": f"Bearer {teller_access_token}"}

        try:
            # Forward request to Teller API
            teller_response = requests.get(url, headers=headers)
            teller_response.raise_for_status()  # Raise exception for HTTP errors

            # Return data from Teller API
            return Response(teller_response.json(), status=200)

        except requests.exceptions.RequestException as e:
            logger.error(f"Teller API request failed: {e}")  # Log error for debugging
            return Response({"error": "Failed to fetch data from Teller API"}, status=502)
# Helper function to load certificate and key paths
def load_cert_and_key():
    cert_path = os.getenv('CERT_PATH')
    key_path = os.getenv('KEY_PATH')

    if not cert_path or not key_path:
        raise ValueError("CERT_PATH or KEY_PATH is not set in the environment.")
    if not os.path.exists(cert_path):
        raise ValueError(f"Certificate file not found at {cert_path}.")
    if not os.path.exists(key_path):
        raise ValueError(f"Private key file not found at {key_path}.")
    
    return cert_path, key_path

# Helper function to get access token for the user
def get_access_token_for_user(user):
    if user.access_token:
        return user.access_token
    else:
        logger.error(f"No access token found for user {user.email}")
        return None

# View to create link token
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_link_token(request):
    try:
        # Load certificate and key
        cert_path, key_path = load_cert_and_key()
    except ValueError as e:
        logger.error(f"Certificate error: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)

    user = request.user

    # Prepare data for the Teller API request
    data = {
        "application": {"name": "budget"},
        "user": {"id": str(user.id)},
    }

    # Retrieve the Teller API URL from environment variables
    base_url = os.getenv('TELLER_API_URL', 'https://api-sandbox.teller.io/v1')
    if not base_url:
        logger.error("TELLER_API_URL is not set in the environment.")
        return JsonResponse({"error": "TELLER_API_URL is not configured."}, status=500)

    # Fetch access token for the user
    access_token = get_access_token_for_user(user)
    if not access_token:
        
        return JsonResponse({"error": "Unable to retrieve access token."}, status=500)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    try:
        # Make a POST request to the Teller API
        response = requests.post(
            f"{base_url}/link",
            json=data,
            headers=headers,
            cert=(cert_path, key_path)
        )

        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            try:
                error_details = response.json()
            except ValueError:
                error_details = response.text
            logger.error(f"Teller API error for user {user.id}: {response.status_code}, {error_details}")
            return JsonResponse({"error": error_details}, status=response.status_code)
    except requests.exceptions.RequestException as e:
        logger.error(f"Teller API request failed for user {user.id}: {str(e)}")
        return JsonResponse({"error": "Failed to connect to Teller API."}, status=500)

# View to exchange public token
@api_view(['POST'])
def exchange_public_token(request):
    public_token = request.data.get('public_token')
    if not public_token:
        return JsonResponse({"error": "public_token is required."}, status=400)

    url = "https://api.teller.io/v1/token"
    headers = {"Authorization": f"Bearer {settings.TELLER_API_KEY}"}
    data = {"public_token": public_token}

    try:
        response = requests.post(url, json=data, headers=headers)
        if response.status_code == 200:
            return JsonResponse(response.json())  # Send access token and refresh token
        else:
            logger.error(f"Teller API error: {response.status_code}, {response.text}")
            return JsonResponse({"error": "Failed to exchange public token"}, status=response.status_code)
    except requests.exceptions.RequestException as e:
        logger.error(f"Teller API request failed: {str(e)}")
        return JsonResponse({"error": "Failed to connect to Teller API."}, status=500)


class complete_location_info(APIView):
    permission_classes = [AllowAny]

    def post(self, request):

       # Extract input fields from request data
     address = request.data.get("address")
     city = request.data.get("city")
     state = request.data.get("state")
    
    # Your PositionStack API key
     api_key = 'd140fb9a855f8f16408e296dc89e3c31'
    
    # Combine address, city, and state to form the full address
     full_address = f'{address}, {city}, {state}'
    
    # PositionStack API endpoint
     url = "http://api.positionstack.com/v1/forward"
    
    # Set up the parameters for the API request
     params = {
        'access_key': api_key,
        'query': full_address,
        'limit': 1,
        "output": "json"
    }
    
    # Send the request to the PositionStack API
     response = requests.get(url, params=params)

    # Check if the request was successful
     if response.status_code == 200:
        data = response.json()
        
        if data["data"]:
            # Address is valid, extract relevant information
            result = data["data"][0]
            return JsonResponse({
                "valid": True,
                "address": result.get("label", "No address available"),
                "city": result.get("city"),
                "state": result.get("region"),
                "country": result.get("country"),
                "latitude": result.get("latitude"),
                "longitude": result.get("longitude")
            })
        else:
            # No matching address found
            return JsonResponse({"valid": False, "error": "Address not found"})
     else:
        # API request failed
        return JsonResponse({"valid": False, "error": "API request failed"})


   


class CreateLinkTokenView(APIView):
    def post(self, request):
        try:
            plaid_client = get_plaid_client()
            request_body = LinkTokenCreateRequest(
                user=LinkTokenCreateRequestUser(client_user_id="unique_user_id"),
                client_name="budget",
                products=[LinkTokenCreateRequestProducts.AUTH, LinkTokenCreateRequestProducts.TRANSACTIONS],
                country_codes=[LinkTokenCreateRequestCountryCodes.US],
                language='en'
            )
            response = plaid_client.link_token_create(request_body)
            return Response({'link_token': response['link_token']})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ExchangePublicTokenView(APIView):
    def post(self, request):
        public_token = request.data.get('public_token')
        if not public_token:
            return Response({'error': 'Public token is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            plaid_client = get_plaid_client()
            request_body = LinkTokenExchangeRequest(public_token=public_token)
            response = plaid_client.item_public_token_exchange(request_body)
            access_token = response['access_token']
            return Response({'access_token': access_token})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)