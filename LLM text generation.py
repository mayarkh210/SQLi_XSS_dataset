{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": null,
   "id": "44f02f1b-5a95-4a06-911b-89b7dd9649db",
   "metadata": {},
   "outputs": [],
   "source": [
    "import re\n",
    "from transformers import pipeline  # or vLLM for speed\n",
    "\n",
    "# Load your fine-tuned model\n",
    "generator = pipeline(\"text-generation\", model=\"path/to/your-fine-tuned-llama3-8b\", device=\"cuda\")\n",
    "\n",
    "def compute_pattern_score(payload: str) -> float:\n",
    "    \"\"\"Implement your pattern scorer from the repo\"\"\"\n",
    "    # Example: weighted score based on regex matches, keywords, entropy, etc.\n",
    "    sql_keywords = len(re.findall(r'(?i)(union|select|drop|insert|update|delete|exec|cast|convert)', payload))\n",
    "    xss_patterns = len(re.findall(r'(?i)(onerror|onload|javascript:|alert\\(|<script|eval\\()', payload))\n",
    "    encoding = len(re.findall(r'%[0-9a-fA-F]{2}|&#x|&#\\d+', payload))\n",
    "    # ... add more + normalize to 0-1 scale\n",
    "    return min(1.0, (sql_keywords * 0.2 + xss_patterns * 0.3 + encoding * 0.15 + ...))\n",
    "\n",
    "def generate_payload(vulnerable: bool, attack_type: str, context: str,\n",
    "                     target_length: int = 85, target_special: int = 7,\n",
    "                     target_pattern: float = 0.95, max_attempts=5):\n",
    "    \n",
    "    label = \"vulnerable\" if vulnerable else \"benign\"\n",
    "    \n",
    "    prompt = f\"\"\"Generate a realistic {label} {attack_type} payload for a {context} \n",
    "that matches these properties: length≈{target_length}, special_chars={target_special}, \n",
    "pattern_score≈{target_pattern}. \n",
    "\n",
    "{ few_shot_examples_from_repo }\"\"\"   # Load from templates/\n",
    "\n",
    "    for attempt in range(max_attempts):\n",
    "        output = generator(prompt, max_new_tokens=150, temperature=0.75, top_p=0.9,\n",
    "                           do_sample=True, return_full_text=False)[0]['generated_text']\n",
    "        \n",
    "        payload = output.strip().split('\\n')[0]  # Clean as needed\n",
    "        \n",
    "        # Post-generation validation\n",
    "        actual_len = len(payload)\n",
    "        actual_special = len(re.findall(r'[^a-zA-Z0-9\\s]', payload))\n",
    "        actual_score = compute_pattern_score(payload)\n",
    "        \n",
    "        if (abs(actual_len - target_length) <= 15 and \n",
    "            abs(actual_special - target_special) <= 2 and \n",
    "            abs(actual_score - target_pattern) <= 0.08):\n",
    "            return payload, actual_score\n",
    "    \n",
    "    return None, None  # Retry or mutate"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3 (ipykernel)",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.9.21"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 5
}
