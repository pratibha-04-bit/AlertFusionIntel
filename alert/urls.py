# urls.py
from django.urls import path
from .views import create_ticket, alert_list_view,alert_detail,alerts_list

urlpatterns = [
    path('create-ticket/', create_ticket, name='create_ticket'),
    path('alerts_dt/', alert_list_view, name='alert_list_dt'),
    path('alerts/', alerts_list, name='alerts_list'),
    path('alerts/<int:pk>/', alert_detail, name='alert_detail'),
]
