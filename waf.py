# waf.py
from flask import request, abort
from collections import defaultdict
import time

attempts = defaultdict(list)
MAX_ATTEMPTS = 5
BLOCK_TIME = 300 

def waf_protection(app):
    @app.before_request
    def block_malicious_ips():
        ip = request.remote_addr
        current_time = time.time()
        recent_attempts = [t for t in attempts[ip] if current_time - t < BLOCK_TIME]
        attempts[ip] = recent_attempts

        if len(recent_attempts) >= MAX_ATTEMPTS:
            abort(403, description="Blocked by WAF")

    @app.after_request
    def record_attempt(response):
        if response.status_code == 401 or response.status_code == 403:
            ip = request.remote_addr
            attempts[ip].append(time.time())
        return response
