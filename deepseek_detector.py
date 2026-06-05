import requests
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from attack_generator_tool import AttackGenerator
import time
import random

# DeepSeek API (replace with your key)
DEEPSEEK_API_KEY = "your_deepseek_api_key"
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"

def detect_with_deepseek(payload):
    prompt = f"""
    Analyze this HTTP parameter value. Is it a SQL injection or XSS attack? Answer only: "BENIGN" or "ATTACK"
    
    Training examples:
    BENIGN: "user=john", "search=books", "id=12345"
    ATTACK: "1' OR '1'='1", "'; DROP TABLE--", "<svg onload=alert(1)>"
    
    Input to classify: {payload}
    
    Verdict:"""
    
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.05
    }
    
    try:
        response = requests.post(DEEPSEEK_API_URL, headers=headers, json=data, timeout=15)
        result = response.json()["choices"][0]["message"]["content"].strip()
        return 1 if any(word in result.upper() for word in ["ATTACK", "MALICIOUS"]) else 0
    except:
        return 0

# Same testing logic as Grok
generator = AttackGenerator()
payloads = []
true_labels = []

for i in range(100):
    payloads.append(generator.generate_random_attack("high")["payload"])
    true_labels.append(1)
    payloads.append(random.choice(["hello", "search", "id=123", "email@test.com"]))
    true_labels.append(0)

predictions = [detect_with_deepseek(p) for p in payloads]
for i in range(len(payloads)):
    time.sleep(0.2)

acc = accuracy_score(true_labels, predictions)
prec = precision_score(true_labels, predictions)
rec = recall_score(true_labels, predictions)
f1 = f1_score(true_labels, predictions)

print(f"\nDeepSeek Results:")
print(f"Accuracy: {acc:.4f}, Precision: {prec:.4f}, Recall: {rec:.4f}, F1: {f1:.4f}")