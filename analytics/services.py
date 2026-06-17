from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging

# Standard logger setup taake terminal par alerts dikha sakein
logger = logging.getLogger(__name__)

class LogSlidingWindowTracker:
    def __init__(self, window_seconds=60, threshold=100):
        # Har IP ke liye alag deque (queue) maintain karne ke liye defaultdict
        self.ip_tracker = defaultdict(deque)
        self.window_seconds = window_seconds
        self.threshold = threshold

    def process_log(self, ip_address, timestamp):
        """
        Real-time log string handling logic:
        1. Insert current timestamp
        2. Shrink window by popping older timestamps
        3. Check count against threshold
        """
        # Ensure data type is a proper python datetime object
        if isinstance(timestamp, str):
            # Agar format ISO string ho toh parse karein
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
        current_queue = self.ip_tracker[ip_address]
        
        # --- Step 1: INSERT ---
        current_queue.append(timestamp)
        
        # --- Step 2: SHRINK (Sliding Action) ---
        # Boundary line calculate karein: Current time minus 60 seconds
        boundary_time = timestamp - timedelta(seconds=self.window_seconds)
        
        # Jab tak queue ka left-most element boundary se purana hai, pop karte rahein
        while current_queue and current_queue[0] < boundary_time:
            current_queue.popleft()
            
        # --- Step 3: COUNT & ALERT ---
        # Safai ke baad pichle 60 seconds ke hits ka count check karein
        recent_hits_count = len(current_queue)
        
        if recent_hits_count > self.threshold:
            logger.warning(
                f"🚨 [SECURITY ALERT] Brute force attack detected from IP: {ip_address}! "
                f"Total hits in last {self.window_seconds}s: {recent_hits_count}"
            )
            return True # Attack detected
            
        return False # System safe

# Singleton instance taake poore project mein aik hi memory tracker share ho
log_tracker_service = LogSlidingWindowTracker(window_seconds=60, threshold=5) 
# Note: Asani se test karne ke liye mainne abhi threshold 5 rakh diya hai.