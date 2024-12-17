from rest_framework import serializers
from .models import Users
import re
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.core.validators import validate_email
from django.contrib.auth.hashers import make_password

from .validators import PasswordValidator

from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User



class UserSeralizers(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['first_name', 'last_name',  'birthday', 'last_login', 'gender', 'address', 'city', 'state', 'account_number','amount','currency', 'routing_number', 'transaction_date','transaction_description']

    def validate(self, data):
        errors = {}

        # Custom validation for FirstName, LastName, Username, Password
        if len(data['first_name']) < 5:
            errors['first_name'] = "First Name must be at least 5 characters long."
        if len(data['last_name']) < 5:
            errors['last_name'] = "Last Name must be at least 5 characters long."

        # Check if the email already exists
        email = data.get('email', '')
        if Users.objects.filter(email=email).exists():
            errors['email'] = "This email is already registered. Please use a different email address."

        # Email format validation
        email_validator = EmailValidator()
        try:
            email_validator(email)
        except ValidationError:
            errors['email'] = "Please enter a valid email address."

        if errors:
            raise serializers.ValidationError(errors)
        
        return data

class LoginSeralizer(serializers.Serializer):
    Username = serializers.CharField()
    Password = serializers.CharField(write_only=True)

    def validate(self, data):
        # Extract username and password from input
        username = data["Username"]
        password = data["Password"]

        try:
            # Query user by username
            user = Users.objects.get(Username=username)
        except Users.DoesNotExist:
            raise serializers.ValidationError("Invalid username or password.")

        # Check if the provided password matches the stored hashed password
        if not check_password(password, user.Password):
            raise serializers.ValidationError("Invalid username or password.")

        # If validation is successful, return the validated data
        return data
class RegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['email', 'password',]
        extra_kwargs = {'password': {'write_only': True}}

    def validate_email(self, value):
        try:
            validate_email(value)
        except ValidationError:
            raise serializers.ValidationError("Invalid email address.")
        if Users.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value

    def validate_password(self, value):
        PasswordValidator.validate(value)
        return value

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['first_name', 'last_name', 'birthday', 'address', 'gender']
        def post(self, request):
         first_name = request.data.get("first_name")
         last_name = request.data.get('last_name')
         gender = request.data.get('gender')
         birthday = request.data.get('birthday')
         address = request.data.get('address')

         if not first_name or not last_name or not gender or not birthday or not address:
             return Response("All of these fields are required")
         else:
             user = Users.objects.create()


class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Your code to fetch data
        data = {"message": "You are authenticated!"}
        return Response(data)

class CustomLoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Check if both email and password were provided
        if not email or not password:
            return Response({"detail": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate the user using the email and password
        user = authenticate(request, username=email, password=password)
        
        if user is not None:
            # User is authenticated, now check if they have a token or create one
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.id,
                'email': user.email
            })
        else:
            return Response({"detail": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

