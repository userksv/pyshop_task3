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
        operation_description='''Creates a new user and sends back response with created users credentials(id, email)
                            username field is required in django, thus I am using email.value for username field.''',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, default='example@mail.com'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, default='Testing321'),
            },
            required=['email', 'password']
        ),
        responses={201: 'Created', 400: 'Bad Request'}
    )
    def post(self, request, *args, **kargs):
        registration_data = request.data
        registration_data.update({'password2':registration_data['password']})
        registration_data.update({'username':registration_data['email']})
        registration_data.update({'email':registration_data['email']})
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
        operation_description='Logs in the user with provided credentials and return access and refresh tokens.(access_token life set to 120 secs for test purpose)',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, default='example@mail.com'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, default='Testing321'),
            },
            required=['email', 'password']
        ),
        responses={200: 'Returns access and refresh tokens', 400: 'Bad Request'}
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
            "exp": int(time.time() + ACCESS_TOKEN_EXPIRY_SECONDS), # lifespan 30 seconds default
            # "exp": int(time.time() + 120), # for testing
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
            properties={'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, default='')},
            required=['refresh_token', 'refresh_token']
        ),
        responses={200: 'User logged out', 400: 'Bad Request'}
    )
    def post(self, request):
        serializer = UserLogoutSerializer(data=request.data)
        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh_token']
            try:
                queryset = RefreshToken.objects.get(uuid_token=refresh_token)
                queryset.delete()
                return Response({'Success': 'User logged out!'}, status=status.HTTP_200_OK)
            except ObjectDoesNotExist:
                return Response({'Error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)    
        else:
            return Response({'Error': 'Check your request'}, status=status.HTTP_400_BAD_REQUEST)


class MeAPIView(APIView):
    serializer_class = UserSerializer
    
    @swagger_auto_schema(
        operation_description='Returns user id, empty username and email. First obtain access token by Logging in, then authorize with token',
        responses={200: 'User information', 400: 'Bad Request'},
        security=[{'Bearer' : []}],
    )
    def get(self, request):
        response = {}
        if not request.headers.get('Authorization'):
            return Response({'Error': 'No access token'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            access_token = request.headers.get('Authorization').split(' ')[-1]
            try:
                decoded = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
                user_id = decoded['user_id']
                user = User.objects.get(id=int(user_id))
                response['id'] = user.id
                response['username'] = user.first_name # 
                response['email'] = user.email
                return Response(response, status=status.HTTP_200_OK)
            except jwt.ExpiredSignatureError:
                response = {'Error':'Token expired!'}
                return Response(response, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description='''Returns updated user info. First obtain access token by Logging in, then authorize with access token
                                actual username field is not changing, instead I am using first_name field''',
        responses={200: 'User information', 400: 'Bad Request'},
        security=[{'Bearer' : []}],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, default='Mike Tyson'),
            },
            required=['username', 'username']
        ),
    )
    def put(self,request):
        response = {}
        if not request.headers.get('Authorization'):
            return Response(status=status.HTTP_400_BAD_REQUEST)
        else:
            access_token = request.headers.get('Authorization').split(' ')[-1]
            data = request.data
            poped = data.pop('username')
            data['first_name'] = poped
            
            try:
                decoded = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
                user_id = decoded['user_id']
                User.objects.filter(id=user_id).update(**data)
                user = User.objects.get(id=user_id)
                response['id'] = user.id
                response['username'] = user.first_name
                response['email'] = user.email
                return Response(response, status=status.HTTP_200_OK)
            except:
                response = {'response':'Token expired!'}
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
            

class RefreshTokenAPIView(LoginAPIView):
    serializer_class = RefreshTokenSerializer
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
    @swagger_auto_schema(
        operation_description='Updates refresh and access tokens, refresh token updates only if it expires. \
                                First obtain refresh token by Logging in, then pass it to request body.',
        responses={200: 'Refreshed access token', 400: 'Bad Request'},
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, default=''),
            },
            required=['refresh_token', 'refresh_token']
        )
    )
    def post(self, request):
        serializer = RefreshTokenSerializer(data=request.data)
        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh_token']
            try:
                token_from_db = RefreshToken.objects.get(uuid_token=str(refresh_token))
                if token_from_db.is_expired():
                    token_from_db = self._update_refresh_token(token_from_db.user)

                new_access_token = self._create_access_token(token_from_db.user) # using method from loginview class
                return Response({'access_token': new_access_token}, status=status.HTTP_200_OK)
            except ObjectDoesNotExist:
                return Response({'Error': 'Token not found'}, status=status.HTTP_404_NOT_FOUND)
            
        return Response({'Error': 'Check your request'}, status=status.HTTP_400_BAD_REQUEST)
    
    def _update_refresh_token(self, user):
        # 1. Delete expired token
        RefreshToken.objects.filter(user=user).delete()
        # 2 Create new token
        refresh_token = RefreshToken.objects.create(user=user)
        
        return refresh_token
    