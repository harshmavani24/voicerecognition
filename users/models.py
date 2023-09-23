from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.utils import timezone



from .manager import UserManager
# Create your models here.
class User(AbstractUser):
    name = models.CharField(max_length=255, default='')
    email = models.EmailField(max_length=255,unique=True)
    password = models.CharField(max_length=255)
    # phonenumber = models.CharField(max_length=20,default=None)
    phonenumber = models.CharField(max_length=20, default=None, null=True)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    otp = models.CharField(max_length=200 , null=True, blank=True)  
    forgot_token = models.CharField(max_length=128, null=True, blank=True)
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ('-id',)
        managed = True
        db_table = 'users_user'
        
    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email
        super().save(*args, **kwargs)
        
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = UserManager()
    
    # def name(self):
    #     return self.name

    def __str__(self):
        return self.email
    
class PendingUser(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20)
    password = models.CharField(max_length=128)
    otp = models.CharField(max_length=200 , null=True, blank=True)  
    created_at = models.DateTimeField(default=timezone.now)

from django.db import models
from django.contrib.auth.models import User

class Query(models.Model):
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20)
    email = models.EmailField()
    link = models.CharField(max_length=255)
    message = models.TextField()
    photos = models.ImageField(upload_to='query_photos')
    date = models.DateField()
    time = models.TimeField()


# make model for secure voice lock to unlock user profile

# class Query(models.Model):
#     name = models.CharField(max_length=255)
#     phone = models.CharField(max_length=20)
#     email = models.EmailField()
#     query = models.TextField()
#     date = models.DateTimeField(auto_now_add=True)
#     status = models.BooleanField(default=False)

'''    
class Visitor(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    company = models.CharField(max_length=255)
    checkInTime = models.DateTimeField()
    checkOutTime = models.DateTimeField()


    
class Registration(models.Model):
    name = models.CharField(max_length=255)
    role = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    company = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    confirmPassword = models.CharField(max_length=255)
    checkInTime = models.DateTimeField()
    checkOutTime = models.DateTimeField()
'''