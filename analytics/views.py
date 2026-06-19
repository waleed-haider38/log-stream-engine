from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import LogEntrySerializer
from .services import log_tracker_service, log_search_service
from .models import LogEntry
from django.utils.dateparse import parse_datetime

# Create your views here.
@api_view(['POST'])
def ingest_logs(request):
    """
    API endpoint to ingest streaming network logs.
    Performs algorithmic string parsing via a Two-Pointer engine for system errors
    and runs real-time threat detection using an in-memory Sliding Window.
    """
    # Assign the incoming client payload data to the serializer for structural validation
    serializer = LogEntrySerializer(data=request.data)

    # Core Guard: Only execute pipeline layers if incoming metrics comply with the schema
    if serializer.is_valid():
        
        # 1. ORM Optimization Layer: Initialize model object instance in-memory 
        # without committing a write transaction to the physical database disk.
        log_instance = serializer.save(commit=False)
        
        # 2. Algorithmic Parsing Layer (Two-Pointer Engine):
        # Scan high-severity system alerts to extract explicit trace cores.
        if log_instance.level in ['ERROR', 'CRITICAL']:
            # Fixed: Resolved typo from 'messge' to 'message'
            log_instance.message = log_search_service.extract_error_core(log_instance.message)
        
        # 3. Database Persistence: Securely commit the processed or raw log record to SQLite
        log_instance.save()
        
        # 4. In-Memory Security Analysis Layer (Sliding Window Engine):
        # Extract metadata metrics to evaluate rapid traffic frequency signatures.
        ip = serializer.validated_data['ip_address']
        time = serializer.validated_data['timestamp']

        # Check if traffic pattern breaks threshold limits via central state tracker
        is_attack = log_tracker_service.process_log(ip, time)

        # Threat Mitigation Routine: Halt operational route access if malicious signatures trip parameters
        if is_attack:
            return Response(
                {"Alert": "Hacker is attacking"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Success Pipeline Target: Executed if record successfully validates and system state remains green
        return Response(
            {"status": "success", "message": "Log Ingested and Parsed Successfully"},
            status=status.HTTP_201_CREATED
        )
    
    # Validation Failure Gate: Returned if structural rules or constraints fail schema verification
    # Also fixed 'serializer.error' property lookup syntax to 'serializer.errors'
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def search_logs(request):
    """
    Handles GET requests to search database logs within a specific time range 
    using high-performance Binary Search.
    """
    # 1. Grab time range strings from URL parameter (e.g., /api/logs/search/?start=...&end=...)
    start_param = request.query_params.get('start')
    end_param = request.query_params.get('end')

    # Quick validation safety check
    if not start_param or not end_param:
        return Response(
            {"error": "Please provide both 'start' and 'end' datetime parameters."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Convert the raw strings into usable Python datetime objects
    start_time = parse_datetime(start_param)
    end_time = parse_datetime(end_param)

    # Pull out all raw timestamps currently stored in the database, sorted chronologically
    all_timestamps = list(LogEntry.objects.order_by('timestamp').values_list('timestamp', flat=True))

    # Task A: Call binary search engine service to isolate matching timestamp structures
    matched_timestamp = log_search_service.find_logs_in_range(all_timestamps, start_time, end_time)

    # Task B: Fetch full log records from the database that match those binary-searched bounds
    logs = LogEntry.objects.filter(timestamp__in=matched_timestamp)

    # Task C: Serialize the queryset into clean primitive types
    serializer = LogEntrySerializer(logs, many=True)

    # Task D: Return response containing your serialized data with a 200 OK status
    return Response(serializer.data, status=status.HTTP_200_OK)