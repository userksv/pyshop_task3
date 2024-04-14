import uuid
import time

from django.test import TestCase
from django.contrib.auth.models import User

from rest_framework.test import APIClient

from constance import config
ACCESS_TOKEN_EXPIRY_SECONDS = config.ACCESS_TOKEN_EXPIRY_SECONDS

class RegisterAPITestCase(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_register_endpoint(self):
        # Define the request payload
        payload = {
            "password": "Testing321",
            "email": "user@example.com"
        }

        # Make the POST request to the endpoint
        response = self.client.post('/api/register/', payload, format='json')

        # Check the response status code
        self.assertEqual(response.status_code, 200)

        # Check the response data
        expected_data = {"id": 1, "email": "user@example.com"}
        self.assertEqual(response.data, expected_data)


class LoginAPITestCase(TestCase):
    def setUp(self) -> None:
        self.client = APIClient()

        self.username = 'user@example.com'
        self.password = 'Testing321'

        self.user = User.objects.create_user(username=self.username, password=self.password)

    def test_login_endpoint(self):
        '''On user registration in View for `username` is used `email` '''
        payload = {
            'email': self.username,
            'password': self.password
        }

        response = self.client.post('/api/login/', payload, format='json')

        # Check for the correct status code
        self.assertEqual(response.status_code, 200)

        # Check if the response contains the tokens
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)

        # test invalid credentials
        invalid_payload = {
            'email': self.username,
            'password': 'wrong_pass'
        }

        response_invalid = self.client.post('/api/login/', invalid_payload, format='json')
        self.assertEqual(response_invalid.status_code, 400)
        self.assertIn('Unable to log in with provided credentials.', response_invalid.data)


class LogoutAPITestCase(TestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.username = 'user@example.com'
        self.password = 'Testing321'
        self.user = User.objects.create_user(username=self.username, password=self.password)
        
    def test_logout_endpoint(self):
        
        payload = {
            'email': self.username,
            'password': self.password
        }

        response = self.client.post('/api/login/', payload, format='json')
        refresh_token = response.data['refresh_token']
        
        logout_response = self.client.post('/api/logout/', {'refresh_token':refresh_token}, format='json')
        self.assertEqual(logout_response.status_code, 200)
        self.assertEqual(logout_response.data, {'Success': 'User logged out!'})
        self.assertIn('Success', logout_response.data)
        
        # if user does not exist refresh_token is valid uuid
        refresh_token = uuid.uuid4()
        logout_response_error = self.client.post('/api/logout/', {'refresh_token': str(refresh_token)}, format='json')
        self.assertEqual(logout_response_error.status_code, 404)
        self.assertEqual(logout_response_error.data, {'Error': 'User not found'})
        self.assertIn('Error', logout_response_error.data)

        # if refersh token not valid uuid
        logout_response_error = self.client.post('/api/logout/', {'refresh_token': 'unvalid_token'}, format='json')
        self.assertEqual(logout_response_error.status_code, 400)
        self.assertEqual(logout_response_error.data, {'Error': 'Check your request'})
        self.assertIn('Error', logout_response_error.data)


class RefreshTokenAPITestCase(TestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.username = 'user@example.com'
        self.password = 'Testing321'
        self.user = User.objects.create_user(username=self.username, password=self.password)

    def test_refresh_endpoint(self):

        payload = {
            'email': self.username,
            'password': self.password
        }

        response = self.client.post('/api/login/', payload, format='json')
        refresh_token = response.data['refresh_token']

        refresh_response = self.client.post('/api/refresh/', {'refresh_token': refresh_token}, format='json')
        self.assertEqual(refresh_response.status_code, 200)
        self.assertIn('access_token', refresh_response.data)

        # if user does not exist refresh_token is valid uuid
        refresh_token = uuid.uuid4()
        refresh_response_error = self.client.post('/api/refresh/', {'refresh_token': str(refresh_token)}, format='json')
        self.assertEqual(refresh_response_error.status_code, 404)
        self.assertEqual(refresh_response_error.data, {'Error': 'Token not found'})
        self.assertIn('Error', refresh_response_error.data)

         # if refersh token not valid uuid
        refresh_response_error = self.client.post('/api/refresh/', {'refresh_token': 'unvalid_token'}, format='json')
        self.assertEqual(refresh_response_error.status_code, 400)
        self.assertEqual(refresh_response_error.data, {'Error': 'Check your request'})
        self.assertIn('Error', refresh_response_error.data)

    
class MeAPITestCase(TestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.username = 'user@example.com'
        self.password = 'Testing321'
        self.email = 'user@example.com'
        self.user = User.objects.create_user(username=self.username, password=self.password, email=self.email)

    def test_me_get_endoint(self):
        payload = {
            'email': self.username,
            'password': self.password
        }

        response = self.client.post('/api/login/', payload, format='json')
        access_token = response.data['access_token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        get_response = self.client.get('/api/me/')
        expected_data = {'id': self.user.id, 'username': '', 'email': self.user.email}
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(get_response.data, expected_data)
        
    def test_me_endpoint_no_token(self):
        
        response = self.client.get('/api/me/')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, {'Error': 'No access token'})

    # def test_me_endpoint_token_expired(self):
    #     payload = {
    #         'email': self.username,
    #         'password': self.password
    #     }

    #     response = self.client.post('/api/login/', payload, format='json')
    #     access_token = response.data['access_token']
    #     time.sleep(ACCESS_TOKEN_EXPIRY_SECONDS + 1)
    #     self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
    #     get_response = self.client.get('/api/me/')
    #     self.assertEqual(get_response.status_code, 400)
    #     self.assertIn('Error', get_response.data)


    def test_me_endpoint_put(self):
        payload = {
            'email': self.username,
            'password': self.password
        }

        response = self.client.post('/api/login/', payload, format='json')
        access_token = response.data['access_token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        data = {"username": "John Smith"}
        # username field in User model, never chanched. I did not implement custom User model(username is required)
        # if actual username will be changed, than /api/login/ won't work
        expected_data = {'id': self.user.id, 'username': data['username'], 'email': self.user.email}
        get_response = self.client.put('/api/me/', data, format='json')
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(get_response.data, expected_data)