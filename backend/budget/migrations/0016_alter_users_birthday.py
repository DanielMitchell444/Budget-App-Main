# Generated by Django 5.1.2 on 2024-11-11 22:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('budget', '0015_alter_users_firstname_alter_users_lastname_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='users',
            name='Birthday',
            field=models.CharField(max_length=20),
        ),
    ]
