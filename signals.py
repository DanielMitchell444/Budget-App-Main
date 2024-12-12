from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.utils.timezone import now

@receiver(user_logged_in)
def update_first_login(sender, request, user, **kwargs):
    if user.last_login == None:
        user.last_login = False
        user.save()
        request.session['last_login'] = True
    else:
        request.session['last_login'] = False

        request.session['last_login'] = False