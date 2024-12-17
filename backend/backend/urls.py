"""
URL configuration for backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from budget import views
from budget.views import ValidateLoginEmailView
from budget.views import LoginView
from budget.views import save_email, save_personal_info, complete_registration
from budget.views import api_register_user
from budget.views import login_user
from budget.views import verify_google_token
from budget.views import validate_credentials
from budget.views import validate_password
from budget.views import save_email_and_password
from budget.views import create_link_token
from budget.views import send_confirmation_email
from budget.views import login_user
from budget.views import ValidateLoginDetailsView
from budget.views import RegisterUserView, UpdateProfileView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from budget.views import completeBasicInfo
from budget.views import RefreshTokenView
router = routers.DefaultRouter()
from budget.views import CustomLoginView
from budget.views import complete_location_info
from budget.views import login_email
from budget.views import SaveCompletedProfile
from budget.views import ValidateAddressInfoView
from budget.views import TellerAccountsProxyView
from budget.views import login_user
from budget.views import CreateLinkTokenView, ExchangePublicTokenView
from budget.views import create_link_token, exchange_public_token
router.register(r'Users', views.TodoView, 'Users')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/Users/', api_register_user, name='register_user'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/Login/', CustomLoginView.as_view(), name='Login'),
    path("auth/google/", verify_google_token),
    path('api/save_email/', save_email, name='save_email'),
    path('api/validate_password/', validate_password, name='validate_password'),
    path('api/save_personal_info/', save_personal_info, name='save_personal_info'),
    path('api/complete-registration/', complete_registration, name='complete_registration'),
    path('api/validate_credentials/', validate_credentials, name='validate_credentials'),
    path('api/save_email_and_password/', save_email_and_password, name='save_email_and_password'),
    path('api/register/', RegisterUserView.as_view(), name='register'),
    path('api/login_user/', login_user, name = 'login_user' ),
    path('api/update-profile/', UpdateProfileView.as_view(), name='update_profile'),
    path('api/register_email/', views.validate_email, name='register_email'),
      path('refresh-token/', RefreshTokenView.as_view(), name='refresh_token'),  # Add route for refreshing token
    # Step 2: Send Data to Database
    path('api/register_details/', views.validate_user, name='register_details'),
    path('api/login_email/', login_email, name = "login_email" ),
    path('api/validate_basic_info/', completeBasicInfo.as_view(), name = 'validate_basic_info'),
    path('api/validate_address_info/', ValidateAddressInfoView.as_view(), name = "validate_address_info"),
    path('api/teller/accounts/', TellerAccountsProxyView.as_view(), name='teller-accounts'),
    ##Step 3: Confirm Email:
     path('api/send-confirmation-email/', send_confirmation_email, name='send_confirmation_email'),
     path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/validate_login_email/', ValidateLoginEmailView.as_view(), name = "validate_login_email"),
    path('api/validate_login_details/', ValidateLoginDetailsView.as_view(), name = "login_details"),
    path('api/create_link_token/', create_link_token, name='create_link_token'),
    path('api/save_complete_profile/', SaveCompletedProfile.as_view(), name='save_complete_profile'),
    path('api/exchange_public_token/', views.exchange_public_token, name='exchange_public_token'),
    ##Login info
]
    