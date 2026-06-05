import requests  # For simulating app interaction
from generator import real_time_generator
from detector import detect_attack
from sklearn.metrics import accuracy_score  # For evaluation

# Simulate sending to vulnerable app (replace with real endpoint if testing exploitation)
def send_to_app(payload):
    try:
        # Example: POST to DVWA XSS endpoint (adjust URL/path)
        response = requests.post('http://localhost/vulnerabilities/xss_r/', data={'txtName': payload, 'mtxMessage': 'test', 'btnSign': 'Sign Guestbook'})
        return "Success" if response.status_code == 200 else "Failed"
    except:
        return "Simulated send"

# Real-time test loop
true_labels = []  # 1 for attack (all generated are attacks)
predictions = []  # 1 if detected as attack

for payload, attack_type in real_time_generator(num_payloads=20, delay=0.5):
    result = detect_attack(payload)
    print(f"Payload: {payload} | Detected: {result}")
    if result == "Benign":  # If not detected, simulate send
        send_result = send_to_app(payload)
        print(f"Sent to app: {send_result}")
    true_labels.append(1)  # Assume generated are attacks
    predictions.append(1 if result == "Attack" else 0)

# Evaluate
accuracy = accuracy_score(true_labels, predictions)
print(f"Overall Accuracy: {accuracy * 100:.2f}%")