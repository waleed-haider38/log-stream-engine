# LogStream Engine

LogStream Engine is a high-performance backend system built with Python and Django REST Framework (DRF). It is designed to handle real-time network log ingestion, clean messy error strings using advanced string parsing, and monitor incoming traffic for security threats using an in-memory sliding window matrix.

---

## 🛠️ Key Technical Features & Algorithms

### 1. In-Memory Security Tracker (Sliding Window Algorithm)

- **Concept:** Monitors rapid traffic bursts (like Brute-Force or DDoS attacks) dynamically without making slow database read queries.
- **Implementation:** Uses a Python `deque` inside an optimized `defaultdict` structure. When a new log hits the endpoint, older timestamps outside the 10-second sliding window are removed from the left side of the queue in $O(1)$ constant time. If an IP addresses crosses 5 requests within that window, the engine instantly flags it and blocks further access.

### 2. Log Stream Parsing (Two-Pointer Technique)

- **Concept:** Extracts raw core error messages embedded inside complex system trace formats without the heavy performance overhead of Regular Expressions (RegEx).
- **Implementation:** Uses a linear string parsing approach with two pointers (`left` moving forward from the start, `right` moving backward from the end) to target and extract content enclosed inside square brackets (`[...]`) in a single $O(n)$ data pass using zero extra memory.

### 3. High-Performance Log Querying (Binary Search Range Query)

- **Concept:** Quickly searches and filters massive amounts of chronological log records based on specific start and end time boundaries.
- **Implementation:** Utilizes Python's low-level, C-optimized `bisect` module. It uses `bisect_left` to locate the lower time boundary and `bisect_right` to locate the upper boundary, reducing range discovery down to $O(\log n)$ logarithmic runtime complexity.

---

## 🚀 Tech Stack

- **Language:** Python
- **Framework:** Django & Django REST Framework (DRF)
- **Data Structures:** Collections (`defaultdict`, `deque`), Arrays
- **Algorithms:** Two-Pointer String Slicing, Sliding Window Rate Limiting, Binary Search Range Queries

---

## 💻 Installation & Setup

### 1. Initialize Virtual Environment

```bash
.venv\Scripts\activate
```

## Install Dependencies

pip install django djangorestframework requests

## Apply Database Migration

python manage.py migrate

## Run the simulation

python simulate_stream.py

## Run the SERVER

python manage.py runserver

### 📤 Finish Line Commit

To save this file and complete your remote repository setup, run these commands in your terminal window:
