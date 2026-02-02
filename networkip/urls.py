from django.urls import path
from . import views

app_name = 'networkip'

urlpatterns = [
    path('', views.index, name='index'),
    path('api/', views.api_scan, name='api_scan'),
]
