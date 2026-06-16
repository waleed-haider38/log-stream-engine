from django.urls import path
from . import views

urlpatterns = [
    path('logs/ingest/', views.ingest_logs, name='ingest_logs')
]
