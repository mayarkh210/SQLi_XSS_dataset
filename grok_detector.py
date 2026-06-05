import requests
import json
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from attack_generator_tool import AttackGenerator  # Your advanced generator
import time

# Grok API setup (xAI API key required)
GROK_API_KEY = "your_xai_api_key_here"
GROK_API_URL = "https://api.x.ai/v1/chat/completions"

def detect_with_grok(payload):
    prompt = f"""
    Classify this web input as BENIGN or ATTACK (SQLi/XSS). Respond ONLY with "BENIGN" or "ATTACK":
    
    Examples:
    "hello world" -> BENIGN
    "id=123" -> BENIGN
    "' OR 1=1 --" -> ATTACK
    "<script>alert(1)</script>" -> ATTACK
    
    Input: {payload}
    
    Classification:"""
    
    headers = {
        "Authorization": f"Bearer {GROK_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "grok-beta",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 10
    }
    
    try:
        response = requests.post(GROK_API_URL, headers=headers, json=data, timeout=10)
        result = response.json()["choices"][0]["message"]["content"].strip()
        return 1 if "ATTACK" in result.upper() else 0
    except:
        return 0  # Default to benign on error

# Test with complex scenario
generator = AttackGenerator()
payloads = []
true_labels = []

print("Generating 200 complex payloads...")
for i in range(100):  # 30% benign, 70% attacks
    payloads.append(generator.generate_random_attack("high")["payload"])
    true_labels.append(1)
    payloads.append(random.choice([
        "hello world", "search books", "id=123", "email=test.com", "user=admin"
    ]))
    true_labels.append(0)

# Run detection
predictions = []
for payload in payloads:
    pred = detect_with_grok(payload)
    predictions.append(pred)
    time.sleep(0.1)  # Rate limiting

# Metrics
acc = accuracy_score(true_labels, predictions)
prec = precision_score(true_labels, predictions)
rec = recall_score(true_labels, predictions)
f1 = f1_score(true_labels, predictions)

print(f"\nGrok LLM Results:")
print(f"Accuracy: {acc:.4f}, Precision: {prec:.4f}, Recall: {rec:.4f}, F1: {f1:.4f}")