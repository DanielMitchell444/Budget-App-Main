# Generated by Django 5.1.2 on 2024-11-16 15:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('budget', '0018_alter_users_password_alter_users_username'),
    ]

    operations = [
        migrations.AlterField(
            model_name='users',
            name='Password',
            field=models.CharField(default='', max_length=15),
        ),
    ]
