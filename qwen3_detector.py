import requests
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from attack_generator_tool import AttackGenerator
import time
import random

# Qwen 3 via Together.ai or similar (Alibaba Cloud API)
Qwen_API_URL = "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
Qwen_API_KEY = "your_qwen_api_key"

def detect_with_qwen(payload):
    prompt = f"""Web security classification task. Given this input string, output ONLY "0" for BENIGN or "1" for ATTACK (SQLi/XSS):

0: "normal query"
0: "user=admin123"  
1: "' OR 1=1#"
1: "<img src=x onerror=prompt(1)>"

STRING: {payload}

OUTPUT:"""
    
    headers = {
        "Authorization": f"Bearer {Qwen_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "qwen-max",
        "input": {"messages": [{"role": "user", "content": prompt}]},
        "parameters": {"temperature": 0.01, "result_format": "message"}
    }
    
    try:
        response = requests.post(Qwen_API_URL, headers=headers, json=data, timeout=15)
        result = response.json()["output"]["choices"][0]["message"]["content"].strip()
        return int(result) if result in ["0", "1"] else 0
    except:
        return 0

# Testing (same as above)
generator = AttackGenerator()
payloads, true_labels = [], []
for i in range(100):
    payloads.append(generator.generate_random_attack("high")["payload"])
    true_labels.append(1)
    payloads.append(random.choice(["hello world", "search news", "page=1"]))
    true_labels.append(0)

predictions = []
for payload in payloads:
    pred = detect_with_qwen(payload)
    predictions.append(pred)
    time.sleep(0.15)

acc = accuracy_score(true_labels, predictions)
prec = precision_score(true_labels, predictions)
rec = recall_score(true_labels, predictions)
f1 = f1_score(true_labels, predictions)

print(f"\nQwen 3 Results:")
print(f"Accuracy: {acc:.4f}, Precision: {prec:.4f}, Recall: {rec:.4f}, F1: {f1:.4f}")