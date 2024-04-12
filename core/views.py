import jwt, time

from django.contrib.auth.models import User
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist


from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authentication import BasicAuthentication

# serilaizer
from .models import RefreshToken
from .serializers import UserRegisterSerializer, UserLoginSerializer, RefreshTokenSerializer, UserSerializer, UserLogoutSerializer

# These values used for validating token expiration, meaning to compare with
from constance import config
REFRESH_TOKEN_EXPIRY_DAYS = config.REFRESH_TOKEN_EXPIRY_DAYS
ACCESS_TOKEN_EXPIRY_SECONDS = config.ACCESS_TOKEN_EXPIRY_SECONDS

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


class RegisterAPIView(APIView):
    # serializer_class = UserRegisterSerializer
    @swagger_auto_schema(
        operation_description='Creates a new user and sends back response with created users credentials(id, email)',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, default='example@mail.com'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, default='Testing321'),
            },
            required=['email', 'password']
        ),
        responses={
            201: 'Created',
            400: 'Bad Request',
        }
    )
    def post(self, request, *args, **kargs):
        registration_data = request.data
        registration_data.update({'password2':registration_data['password']})
        registration_data.update({'username':registration_data['email']})
        serializer = UserRegisterSerializer(data=registration_data)
        if serializer.is_valid():
            serializer.save()
            response = {
                'id': serializer.data['id'],
                'email': serializer.data['email'],
            }
            return Response(response, status=status.HTTP_200_OK)
        raise ValidationError(
            serializer.errors, code=status.HTTP_406_NOT_ACCEPTABLE)
    

class LoginAPIView(APIView):
    serializer_class = UserLoginSerializer
    @swagger_auto_schema(
        operation_description='Logs in the user with provided credentials and return access and refresh tokens.',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, default='example@mail.com'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, default='Testing321'),
            },
            required=['email', 'password']
        ),
        responses={
            200: 'Returns access and refresh tokens',
            400: 'Bad Request',
        }
    )
    def post(self, request, *args, **kargs):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.authenticate_user()
            access_token = self._create_access_token(user)
            refresh_token = self._create_refresh_token(user)
            response = {
                'access_token': access_token,
                'refresh_token': str(refresh_token),
            }
            return Response(response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _create_refresh_token(self, user):
        refresh_token, created = RefreshToken.objects.get_or_create(user=user)
        return refresh_token
    
    def _create_access_token(self, user):
        key = settings.SECRET_KEY # signature?
        payload = {
            "token_type": "access",
            "username": user.username,
            "exp": int(time.time() + 30), # lifespan 30 seconds CHANGE
            "user_id": user.id
            }
        access_token = jwt.encode(payload, key, algorithm="HS256")
        return access_token


class LogoutAPIView(APIView):
    serializer_class = UserLogoutSerializer
    @swagger_auto_schema(
        operation_description='Logs the user out and destroys refresh token',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, default=''),
            },
            required=['refresh_token', 'refresh_token']
        ),
        responses={
            200: 'User logged out',
            400: 'Bad Request',
        }
    )
    def post(self, request):
        serializer = UserLogoutSerializer(data=request.data)
        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh_token']
            try:
                queryset = RefreshToken.objects.filter(uuid_token=refresh_token)
                if queryset.exists():
                    queryset.delete()
                    return Response({'Success': 'User logged out!'}, status=status.HTTP_200_OK)
                else:
                    return Response({'Error': 'user not found'}, status=status.HTTP_404_NOT_FOUND)
            except ObjectDoesNotExist:
                return Response({'Error': 'Object does not exist'}, status=status.HTTP_404_NOT_FOUND)    
        else:
            return Response({'Error': 'Check your request'}, status=status.HTTP_400_BAD_REQUEST)


class MeAPIView(APIView):
    serializer_class = UserSerializer
    
    def get(self, request):
        response = {}
        access_token = request.META.get('HTTP_AUTHORIZATION').split(' ')[1]
        try:
            decoded = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = decoded['user_id']
            user = User.objects.get(id=int(user_id))
            response['id'] = user.id
            response['username'] = ''
            response['email'] = user.username
            return Response(response, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            response = {'response':'Token expired!'}
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    def put(self,request):
        response = {}
        access_token = request.META.get('HTTP_AUTHORIZATION').split(' ')[1]
        data = request.data
        try:
            decoded = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = decoded['user_id']
            User.objects.filter(id=user_id).update(**data)
            user = User.objects.get(id=user_id)
            response['id'] = user.id
            response['username'] = user.username
            response['email'] = user.email
            return Response(response, status=status.HTTP_200_OK)
        except:
            response = {'response':'Token expired!'}
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        

class RefreshTokenAPIView(LoginAPIView):
    serializer_class = RefreshTokenSerializer
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

    def post(self, request):
        serializer = RefreshTokenSerializer(data=request.data)
        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh_token']
            try:
                token_from_db = RefreshToken.objects.get(uuid_token=str(refresh_token))
                if token_from_db.is_expired():
                    # print(token_from_db, 'Token EXPIRED')
                    token_from_db = self._update_refresh_token(token_from_db.user)

                new_access_token = self._create_access_token(token_from_db.user) # using method from loginview class
                return Response({'access_token': new_access_token}, status=status.HTTP_200_OK)
            except:
                return Response({'error': 'token not found'}, status=status.HTTP_400_BAD_REQUEST)
            
        return Response({'error': 'Some kind of error!'}, status=status.HTTP_400_BAD_REQUEST)
    
    def _update_refresh_token(self, user):
        # 1. Delete expired token
        RefreshToken.objects.filter(user=user).delete()
        # 2 Create new token
        refresh_token = RefreshToken.objects.create(user=user)
        
        return refresh_token