# Generated by Django 4.2.2 on 2023-06-09 12:21

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0012_user_username"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="phonenumber",
            field=models.CharField(default=None, max_length=20, null=True, unique=True),
        ),
    ]
