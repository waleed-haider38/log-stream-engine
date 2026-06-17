from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import LogEntrySerializer
from .services import log_tracker_service

# Create your views here.
@api_view(['POST'])
def ingest_logs(request):
    #Assign data to serializer
    serializer = LogEntrySerializer(data=request.data)

    if serializer.is_valid():
        serializer.save()
    
    ip = serializer.validated_data['ip_address']
    time = serializer.validated_data['timestamp']

    is_attack = log_tracker_service.process_log(ip , time)

    if is_attack:
            return Response(
                {"Alert": "Hacker is attacking"},
                status=status.HTTP_401_UNAUTHORIZED
            )
    
    return Response(
        {"status":"success", "message": "Log Ingested Successfully"},
        status=status.HTTP_201_CREATED
    )
    return Response(serializer.error , status=status.HTTP_400_BAD_REQUEST)
