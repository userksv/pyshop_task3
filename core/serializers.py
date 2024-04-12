import uuid

from rest_framework import serializers

from rest_framework.exceptions import ValidationError
from rest_framework.authtoken.models import Token

from django.contrib.auth.models import User
from django.contrib.auth import authenticate

from core.models import RefreshToken

class UserSerializer(serializers.ModelSerializer):
    id = serializers.PrimaryKeyRelatedField(read_only=True)
    username = serializers.CharField(read_only=True)
    email = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "username"]


class RefreshTokenSerializer(serializers.ModelSerializer):
    refresh_token = serializers.UUIDField()
    class Meta:
        model = RefreshToken
        fields = ['refresh_token']


class UserLoginSerializer(serializers.ModelSerializer):
    id = serializers.PrimaryKeyRelatedField(read_only=True)
    username = serializers.CharField(read_only=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "username",  "password"]

    def authenticate_user(self):
        username = self.validated_data.get('email')
        password = self.validated_data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            return user
        else:
            raise serializers.ValidationError("Unable to log in with provided credentials.")


class UserLogoutSerializer(serializers.ModelSerializer):
    refresh_token = serializers.UUIDField()

    class Meta:
        model = RefreshToken
        fields = ['refresh_token']
        

class UserRegisterSerializer(serializers.ModelSerializer):
    id = serializers.PrimaryKeyRelatedField(read_only=True)
    username = serializers.CharField()
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["id", "username", "email", "password", "password2"]
        extra_kwargs = {
            'password': {"write_only": True},
        }

    def validate_username(self, username):
        if User.objects.filter(username=username).exists():
            detail = {
                "detail": "User Already exist!"
            }
            raise ValidationError(detail=detail)
        return username

    def validate(self, instance):
        if instance['password'] != instance['password2']:
            raise ValidationError({"message": "Both password must match"})

        if User.objects.filter(email=instance['email']).exists():
            raise ValidationError({"message": "Email already taken!"})

        return instance

    def create(self, validated_data):
        passowrd = validated_data.pop('password2') # method does not require password2 because instance validated?
        user = User.objects.create(**validated_data)
        user.set_password(passowrd)
        user.save()
        return user