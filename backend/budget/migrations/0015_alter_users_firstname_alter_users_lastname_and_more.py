# Generated by Django 5.1.2 on 2024-11-11 22:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('budget', '0014_alter_users_birthday'),
    ]

    operations = [
        migrations.AlterField(
            model_name='users',
            name='FirstName',
            field=models.CharField(max_length=15),
        ),
        migrations.AlterField(
            model_name='users',
            name='LastName',
            field=models.CharField(max_length=15),
        ),
        migrations.AlterField(
            model_name='users',
            name='Password',
            field=models.CharField(max_length=15),
        ),
        migrations.AlterField(
            model_name='users',
            name='Username',
            field=models.CharField(max_length=15),
        ),
    ]
