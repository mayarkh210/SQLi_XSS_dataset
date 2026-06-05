from attack_generator_tool import AttackGenerator
import requests
import time
import random

generator = AttackGenerator()

def send_to_dvwa(payload, attack_type="xss"):
    try:
        if attack_type == "xss":
            url = "http://localhost/vulnerabilities/xss_r/"
            data = {"txtName": payload, "mtxMessage": "test", "btnSign": "Sign Guestbook"}
        else:
            url = "http://localhost/vulnerabilities/sqli/"
            data = {"id": payload, "Submit": "Submit"}
        
        response = requests.post(url, data=data, timeout=5)
        return response.status_code
    except:
        return None

print("Starting Real-time Adversarial Testing Environment...\n")
print("Press Ctrl+C to stop\n")

try:
    while True:
        # Generate attack or benign
        if random.random() < 0.7:  # 70% attacks
            attack = generator.generate_random_attack(complexity="high")
            payload = attack["payload"]
            print(f"🚀 ATTACK ({attack['type']}) → {payload[:80]}...")
            send_to_dvwa(payload, attack["type"].lower())
        else:
            benign = random.choice(["hello world", "search books", "id=123", "user=admin", "email=test@example.com"])
            print(f"✅ BENIGN → {benign}")
            send_to_dvwa(benign)
        
        time.sleep(0.8)   # Adjust speed

except KeyboardInterrupt:
    print("\n\nEnvironment stopped.")