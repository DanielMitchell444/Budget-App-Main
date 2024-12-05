from django.core.management.base import BaseCommand
from .models import Users

class Command(BaseCommand):
    help = 'Removes duplicate users with the same email'

    def handle(self, *args, **kwargs):
        duplicate_users = Users.objects.filter(Email='duplicate-email@example.com')
        
        if duplicate_users.count() > 1:
            self.stdout.write(self.style.WARNING("Found duplicates. Removing all except the first one."))
            # Keep the first user and delete the rest
            duplicate_users.exclude(id=duplicate_users.first().id).delete()
            self.stdout.write(self.style.SUCCESS("Duplicates removed successfully."))
        else:
            self.stdout.write(self.style.SUCCESS("No duplicates found."))