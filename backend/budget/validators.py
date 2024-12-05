
from django.core.exceptions import ValidationError
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
import re


class PasswordValidator:
    special_characters = "[~\!@#\$%\^&\*\(\)_\+{}\":;'\[\]]"
    

def validate_email_format(email):
    """
    Validates an email address format using regex.
    Returns True if the email is valid, otherwise False.
    """
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None
    