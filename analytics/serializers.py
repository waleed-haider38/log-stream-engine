from rest_framework import serializers
from .models import LogEntry

class LogEntrySerializer(serializers.Serializer):
    class Meta:
        model = LogEntry

        fields = ['timestamp','level','ip_address','message']