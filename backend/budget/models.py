from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import EmailValidator

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email.lower())  # Ensure case-insensitive email
        user = self.model(email=email, **extra_fields)  # Use the correct field name
        user.set_password(password)  # Automatically hashes the password
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(email, password, **extra_fields)

class Users(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=15, blank=False)  # Use snake_case
    last_name = models.CharField(max_length=15, blank=False)
    username = models.CharField(max_length=10, blank=False, unique=False)
    email = models.EmailField(max_length=254, blank=False, validators=[EmailValidator()], unique=True)
    birthday = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    access_token = models.TextField(blank=True, null=True)
    refresh_token = models.TextField(blank=True, null=True)
    gender = models.CharField(max_length=14, blank=True, unique=False )
    address = models.CharField(max_length=64, blank=True, unique=False )
    city = models.CharField(max_length=24, blank=True, unique=False )
    state = models.CharField(max_length=32, blank=True, unique=False )
    is_first_login = models.BooleanField(default=True)
    account_number = models.CharField(max_length=48, blank=True, unique=False)
    routing_number = models.CharField(max_length=48, blank=True, unique=False)
    amount = models.CharField(max_length=48, blank=True, unique=False)
    transaction_date = models.CharField(max_length=48, blank=True, unique=False)
    transaction_description = models.CharField(max_length=48,blank=True, unique=False)
    currency = models.CharField(max_length=48, blank=True, unique=False)
    

    objects = UserManager()

    USERNAME_FIELD = "email"  # Authentication field
    REQUIRED_FIELDS = ['first_name', 'last_name', 'username']

    def __str__(self):
        return f"{self.first_name} {self.last_name}"