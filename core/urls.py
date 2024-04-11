from django.urls import path
from .import views

urlpatterns = [
    path('register/', views.RegisterAPIView.as_view(), name='register'),
    path('login/', views.LoginAPIView.as_view(), name='login'),
    path('logout/', views.LogoutAPIView.as_view(), name='logout'),
    path('refresh/', views.RefreshTokenAPIView.as_view(), name='refresh'),
    path('me/', views.MeAPIView.as_view(), name='me')
]