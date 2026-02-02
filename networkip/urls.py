from django.urls import path
from . import views

app_name = 'networkip'

urlpatterns = [
    path('', views.index, name='index'),
    path('api/home/', views.api_scan_home, name='api_scan_home'),
    path('api/vm/', views.api_scan_vm, name='api_scan_vm'),
]
