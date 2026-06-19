import bisect
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Standard logger setup to display operational alerts in the terminal
logger = logging.getLogger(__name__)

class LogSlidingWindowTracker:
    """
    Tracks and identifies potential real-time network threats (e.g., Brute-Force/DDoS attacks)
    using an in-memory sliding window queue pattern over streaming event data.
    """
    def __init__(self, window_seconds=60, threshold=100):
        # Keeps an independent tracking double-ended queue (deque) for each individual IP address
        self.ip_tracker = defaultdict(deque)
        self.window_seconds = window_seconds
        self.threshold = threshold

    def process_log(self, ip_address, timestamp):
        """
        Main routing gateway for real-time validation:
        1. Insert current streaming timestamp to head of array.
        2. Shrink window boundaries (Slide) by removing expired historic records.
        3. Evaluate threat matrix status based on traffic frequency metrics.
        """
        # Ensure incoming payload data is normalized into a native Python datetime object
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
        current_queue = self.ip_tracker[ip_address]
        
        # --- STEP 1: INSERT ---
        # Append the fresh incoming occurrence timestamp onto the right side of the queue
        current_queue.append(timestamp)
        
        # --- STEP 2: SHRINK (The Sliding Window Action) ---
        # Dynamically establish the sliding historic cutoff limit line
        boundary_time = timestamp - timedelta(seconds=self.window_seconds)
        
        # Evict all stale elements sitting on the left side that drop below the boundary
        while current_queue and current_queue[0] < boundary_time:
            current_queue.popleft()
            
        # --- STEP 3: COUNT & EVALUATE THREATS ---
        # Count remaining valid logs currently inside the active window range
        recent_hits_count = len(current_queue)
        
        if recent_hits_count > self.threshold:
            logger.warning(
                f"🚨 [SECURITY ALERT] Brute force attack detected from IP: {ip_address}! "
                f"Total hits in last {self.window_seconds}s: {recent_hits_count}"
            )
            return True  # Attack vectors detected
            
        return False  # Target stream behaves within standard metrics


class LogSearchService:
    """
    Executes lightning-fast time-range analysis over ordered historical log data.
    Leverages high-performance Binary Search algorithms to achieve O(log n) efficiency.
    """
    def find_logs_in_range(self, all_timestamps, start_time, end_time):
        """
        Parameters:
            all_timestamps (list): Chronologically sorted list of datetime objects.
            start_time (datetime): Lower boundary condition filter.
            end_time (datetime): Upper boundary condition filter.
        
        Returns:
            list: Sub-slice array containing elements safely matching the specified boundaries.
        """
        # Defensive check: Instantly exit if the target search array space is empty
        if not all_timestamps:
            return []

        # Find the lower search pointer boundary using bisect_left.
        # This gives the first index where elements are >= start_time.
        start_index = bisect.bisect_left(all_timestamps, start_time)
        
        # Find the upper search pointer boundary using bisect_right.
        # This identifies the rightmost safe edge offset point past elements <= end_time.
        end_index = bisect.bisect_right(all_timestamps, end_time)
        
        # Extract and isolate the matching target subarray segment via a memory-slice operation
        matching_logs = all_timestamps[start_index:end_index]
        
        return matching_logs
def extract_error_core(self, raw_message: str) -> str:
        """
        Uses a Two-Pointer approach to parse raw logs and extract 
        the core error message wrapped inside brackets [...].
        """
        # Defensive check: Agar string empty hai toh empty string return karein
        if not raw_message:
            return ""

        # 1. Setup pointers: left ko 0 par aur right ko string ke last index par rakhein
        left = 0
        right = len(raw_message) - 1

        # 2. Left pointer ko aage barhayein jab tak left < right ho aur '[' na mil jaye
        while left < right and raw_message[left] != '[':
            left += 1

        # 3. Right pointer ko peeche layein jab tak right > left ho aur ']' na mil jaye
        while right > left and raw_message[right] != ']':
            right -= 1

        # 4. Check karein agar brackets validly mil gaye hain (left < right)
        if left < right:
            # Slicing ke liye : use karein aur yahin se return kar dein
            return raw_message[left + 1 : right]

        # 5. Fallback Guard: Agar brackets nahi mile, toh original raw_message return kar dein
        return raw_message
# Instantiate singletons to maintain a uniform central state across application instances
log_tracker_service = LogSlidingWindowTracker(window_seconds=60, threshold=5)
log_search_service = LogSearchService()