
from django.test import TestCase
from django.contrib.auth.models import User


from rest_framework.test import APIClient


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
