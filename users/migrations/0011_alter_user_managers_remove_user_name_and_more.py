# Generated by Django 4.2.2 on 2023-06-09 12:06

from django.db import migrations, models
import users.manager


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0010_user_phonenumber"),
    ]

    operations = [
        migrations.AlterModelManagers(
            name="user",
            managers=[
                ("objects", users.manager.UserManager()),
            ],
        ),
        migrations.RemoveField(
            model_name="user",
            name="name",
        ),
        migrations.AddField(
            model_name="user",
            name="is_varified",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="user",
            name="otp",
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
