# Generated by Django 5.1.2 on 2024-11-11 20:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('budget', '0013_remove_users_gender'),
    ]

    operations = [
        migrations.AlterField(
            model_name='users',
            name='Birthday',
            field=models.DateField(),
        ),
    ]
