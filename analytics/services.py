from collections import defaultdict, deque
from datetime import datetime, timedelta

class LogTrackerService:
    def __init__(self):
        # In-memory storage for sliding window timestamps
        self.window_duration = timedelta(seconds=10)
        self.max_threshold = 5
        self.ip_tracker = defaultdict(deque)

    def process_log(self, ip, timestamp_str):
        # Convert timestamp string to a timezone-aware datetime object
        if isinstance(timestamp_str, str):
            clean_time_str = timestamp_str.replace('Z', '+00:00')
            current_time = datetime.fromisoformat(clean_time_str)
        else:
            current_time = timestamp_str

        user_queue = self.ip_tracker[ip]

        # Evict timestamps older than 10 seconds from the left of the deque: O(1)
        while user_queue and (current_time - user_queue[0]) > self.window_duration:
            user_queue.popleft()

        # Append current hit
        user_queue.append(current_time)

        # If hits cross threshold (5), flag it as a brute-force attack
        if len(user_queue) > self.max_threshold:
            print(f"🚨 [SECURITY ALERT] Brute force attack detected from IP: {ip}")
            return True

        return False


class LogSearchService:
    def extract_error_core(self, message):
        # Two-pointer engine to isolate messy traces inside brackets [...]
        left = 0
        right = len(message) - 1

        while left < len(message) and message[left] != '[':
            left += 1

        while right >= 0 and message[right] != ']':
            right -= 1

        if left < right:
            return message[left + 1:right]

        return message

    def find_logs_in_range(self, all_timestamps, start_time, end_time):
        import bisect
        if not all_timestamps:
            return []
            
        # Binary search range query discovery: O(log N)
        left_idx = bisect.bisect_left(all_timestamps, start_time)
        right_idx = bisect.bisect_right(all_timestamps, end_time)

        return all_timestamps[left_idx:right_idx]


# Instantiate singleton service layers for views to import
log_tracker_service = LogTrackerService()
log_search_service = LogSearchService()