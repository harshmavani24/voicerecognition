from rest_framework import serializers
from .models import PendingUser, User,Query
from django.core.exceptions import ValidationError
# from hcaptcha.fields import hCaptchaField
from django.contrib.auth import get_user_model
User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'name', 'email','phonenumber', 'password', 'confirm_password', 'is_active','otp','is_verified']
        extra_kwargs = {
            'password': {'write_only': True},
        }
    
    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.pop('confirm_password', None)
        if password and confirm_password and password != confirm_password:
            response = {
                'status': 'error',
                'message': 'Passwords do not match'
            }
            raise ValidationError(response)
        
        return attrs
    
    def create(self,validated_data):
        password = validated_data.pop('password',None)
        otp = validated_data.pop('otp', None)

        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        if otp is not None:
            saved_otp = instance.otp
            if saved_otp != otp:
                raise ValidationError('Invalid OTP')
            instance.otp = ''  # Clear OTP after successful verification

        
        instance.save()
        return instance


class VerifyAccountSerializer(serializers.Serializer):
    email = serializers.EmailField(default=None)
    otp = serializers.CharField()
        
    def __init__(self, *args, **kwargs):
        email = kwargs.pop('email', None)
        super().__init__(*args, **kwargs)
        if email:
            self.fields['email'].default = email
    def validate(self, data):
        email = data['email']
        otp = data['otp']

        # Check if there is a pending_user with the given email and OTP
        pending_user = PendingUser.objects.filter(email=email, otp=otp).first()
        if not pending_user:
            raise serializers.ValidationError('Invalid email or OTP')

        return data
    
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    # hcaptcha = hCaptchaField()

    
class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField()

class QuerySerializer(serializers.ModelSerializer):
    photos = serializers.ImageField(max_length=None, use_url=True)

    class Meta:
        model = Query
        fields = '__all__'
    
    # def update(self,instance,validated_data):
    #     for attr,value in validated_data.items():
    #         if attr == 'password':
    #             instance.set_password(value)
    #         else:
    #             setattr(instance,attr,value)
    #     instance.save()
    #     return instance
'''
class VisitorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Visitor
        fields = '__all__'

class QuerySerializer(serializers.ModelSerializer):
    class Meta:
        model = Query
        fields = '__all__'
        
class RegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Registration
        fields = '__all__'
'''