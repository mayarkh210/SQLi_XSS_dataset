{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": 1,
   "id": "61eea612",
   "metadata": {},
   "outputs": [
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      "C:\\Users\\haidy\\AppData\\Roaming\\Python\\Python39\\site-packages\\pandas\\core\\computation\\expressions.py:21: UserWarning: Pandas requires version '2.8.4' or newer of 'numexpr' (version '2.8.1' currently installed).\n",
      "  from pandas.core.computation.check import NUMEXPR_INSTALLED\n",
      "C:\\Users\\haidy\\AppData\\Roaming\\Python\\Python39\\site-packages\\pandas\\core\\arrays\\masked.py:60: UserWarning: Pandas requires version '1.3.6' or newer of 'bottleneck' (version '1.3.4' currently installed).\n",
      "  from pandas.core import (\n"
     ]
    }
   ],
   "source": [
    "import pandas as pd\n",
    "import numpy as np\n",
    "from sklearn.model_selection import train_test_split\n",
    "from sklearn.ensemble import RandomForestClassifier\n",
    "from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score\n",
    "from sklearn.feature_extraction.text import TfidfVectorizer\n",
    "import re\n",
    "from collections import Counter\n",
    "import logging\n",
    "\n",
    "import os"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 3,
   "id": "162559d4",
   "metadata": {},
   "outputs": [
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      "2025-05-20 12:13:15,924 - INFO - Datasets loaded successfully.\n"
     ]
    }
   ],
   "source": [
    "\n",
    "# Set up logging\n",
    "logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')\n",
    "\n",
    "# Load datasets\n",
    "try:\n",
    "    code_df = pd.read_csv(r'C:\\Web Application Attacks\\Datasets\\code_vulnerabilities.csv')\n",
    "    payload_df = pd.read_csv(r'C:\\Web Application Attacks\\Datasets\\payload_full.csv')\n",
    "    logging.info(\"Datasets loaded successfully.\")\n",
    "except FileNotFoundError as e:\n",
    "    logging.error(f\"Error loading datasets: {e}\")\n",
    "    raise\n",
    "# Load datasets\n",
    "#code_df = pd.read_csv(r'C:\\Web Application Attacks\\Datasets\\code_vulnerabilities.csv')\n",
    "#payload_df = pd.read_csv(r'C:\\Web Application Attacks\\Datasets\\payload_full.csv')"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 4,
   "id": "6c478589",
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/html": [
       "<div>\n",
       "<style scoped>\n",
       "    .dataframe tbody tr th:only-of-type {\n",
       "        vertical-align: middle;\n",
       "    }\n",
       "\n",
       "    .dataframe tbody tr th {\n",
       "        vertical-align: top;\n",
       "    }\n",
       "\n",
       "    .dataframe thead th {\n",
       "        text-align: right;\n",
       "    }\n",
       "</style>\n",
       "<table border=\"1\" class=\"dataframe\">\n",
       "  <thead>\n",
       "    <tr style=\"text-align: right;\">\n",
       "      <th></th>\n",
       "      <th>payload</th>\n",
       "      <th>length</th>\n",
       "      <th>attack_type</th>\n",
       "      <th>label</th>\n",
       "    </tr>\n",
       "  </thead>\n",
       "  <tbody>\n",
       "    <tr>\n",
       "      <th>0</th>\n",
       "      <td>c/ caridad s/n</td>\n",
       "      <td>14</td>\n",
       "      <td>norm</td>\n",
       "      <td>norm</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>1</th>\n",
       "      <td>campello, el</td>\n",
       "      <td>12</td>\n",
       "      <td>norm</td>\n",
       "      <td>norm</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>2</th>\n",
       "      <td>40184</td>\n",
       "      <td>5</td>\n",
       "      <td>norm</td>\n",
       "      <td>norm</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>3</th>\n",
       "      <td>1442431887503330</td>\n",
       "      <td>16</td>\n",
       "      <td>norm</td>\n",
       "      <td>norm</td>\n",
       "    </tr>\n",
       "    <tr>\n",
       "      <th>4</th>\n",
       "      <td>nue37</td>\n",
       "      <td>5</td>\n",
       "      <td>norm</td>\n",
       "      <td>norm</td>\n",
       "    </tr>\n",
       "  </tbody>\n",
       "</table>\n",
       "</div>"
      ],
      "text/plain": [
       "            payload  length attack_type label\n",
       "0    c/ caridad s/n      14        norm  norm\n",
       "1      campello, el      12        norm  norm\n",
       "2             40184       5        norm  norm\n",
       "3  1442431887503330      16        norm  norm\n",
       "4             nue37       5        norm  norm"
      ]
     },
     "execution_count": 4,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "#code_df.head()\n",
    "payload_df.head()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 5,
   "id": "99765c97",
   "metadata": {},
   "outputs": [],
   "source": [
    "# --- Preprocess Code Vulnerabilities ---\n",
    "# Define patterns for SQLi and XSS\n",
    "sqli_risky = ['execute', 'query', 'raw', 'sql', 'concat']\n",
    "xss_risky = ['innerHTML', 'eval', 'document.write', 'setTimeout', 'setInterval']\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 6,
   "id": "2984fba6",
   "metadata": {},
   "outputs": [],
   "source": [
    "def extract_code_features(code, tokens):\n",
    "    tokens = eval(tokens) if isinstance(tokens, str) else tokens\n",
    "    code_lower = code.lower()\n",
    "    \n",
    "    # Feature: Presence of risky functions\n",
    "    sqli_features = [1 if any(p in code_lower for p in sqli_risky) else 0]\n",
    "    xss_features = [1 if any(p in code_lower for p in xss_risky) else 0]\n",
    "    \n",
    "    # Feature: Code length and token count\n",
    "    code_length = len(code)\n",
    "    token_count = len(tokens)\n",
    "    \n",
    "    # Feature: Frequency of common tokens\n",
    "    token_freq = Counter(tokens)\n",
    "    common_tokens = ['execute', 'innerHTML', 'user_input', 'query']\n",
    "    token_features = [token_freq.get(t, 0) for t in common_tokens]\n",
    "    \n",
    "    return sqli_features + xss_features + [code_length, token_count] + token_features\n",
    "\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 7,
   "id": "f9f0ab3d",
   "metadata": {},
   "outputs": [
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      "2025-05-20 12:14:17,515 - INFO - Code features extracted successfully.\n"
     ]
    }
   ],
   "source": [
    "# Apply feature extraction\n",
    "try:\n",
    "    code_features = code_df.apply(\n",
    "        lambda row: extract_code_features(row['Code Snippet'], row['Preprocessed Tokens']),\n",
    "        axis=1\n",
    "    )\n",
    "    code_features_df = pd.DataFrame(\n",
    "        code_features.tolist(),\n",
    "        columns=['sqli_risky', 'xss_risky', 'code_length', 'token_count'] + \n",
    "                [f'token_{t}' for t in ['execute', 'innerHTML', 'user_input', 'query']]\n",
    "    )\n",
    "    code_df = pd.concat([code_df, code_features_df], axis=1)\n",
    "    logging.info(\"Code features extracted successfully.\")\n",
    "except Exception as e:\n",
    "    logging.error(f\"Error extracting code features: {e}\")\n",
    "    raise\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 8,
   "id": "974b2efe",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Add synthetic normal code samples\n",
    "normal_code_samples = [\n",
    "    {\"Code Snippet\": \"cursor.execute('SELECT * FROM users WHERE username = ?', [user_input])\", \n",
    "     \"Vulnerability Type\": \"none\", \n",
    "     \"Preprocessed Tokens\": [\"cursor\", \"execute\", \"select\", \"from\", \"users\", \"where\", \"username\", \"user_input\"]},\n",
    "    {\"Code Snippet\": \"element.textContent = user_input\", \n",
    "     \"Vulnerability Type\": \"none\", \n",
    "     \"Preprocessed Tokens\": [\"element\", \"textContent\", \"user_input\"]},\n",
    "    {\"Code Snippet\": \"cursor.execute('SELECT * FROM products WHERE id = %s', (product_id,))\", \n",
    "     \"Vulnerability Type\": \"none\", \n",
    "     \"Preprocessed Tokens\": [\"cursor\", \"execute\", \"select\", \"from\", \"products\", \"where\", \"id\", \"product_id\"]},\n",
    "    {\"Code Snippet\": \"element.innerText = sanitized_input\", \n",
    "     \"Vulnerability Type\": \"none\", \n",
    "     \"Preprocessed Tokens\": [\"element\", \"innerText\", \"sanitized_input\"]}\n",
    "] * 150  # Replicate to approximate 600 normal samples\n",
    "normal_code_df = pd.DataFrame(normal_code_samples)\n",
    "normal_code_features = normal_code_df.apply(\n",
    "    lambda row: extract_code_features(row['Code Snippet'], row['Preprocessed Tokens']),\n",
    "    axis=1\n",
    ")\n",
    "normal_code_features_df = pd.DataFrame(\n",
    "    normal_code_features.tolist(),\n",
    "    columns=['sqli_risky', 'xss_risky', 'code_length', 'token_count'] + \n",
    "            [f'token_{t}' for t in ['execute', 'innerHTML', 'user_input', 'query']]\n",
    ")\n",
    "normal_code_df = pd.concat([normal_code_df, normal_code_features_df], axis=1)\n",
    "code_df = pd.concat([code_df, normal_code_df], ignore_index=True)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 9,
   "id": "92f92918",
   "metadata": {},
   "outputs": [],
   "source": [
    "# --- Preprocess Payloads ---\n",
    "# Define patterns for SQLi and XSS\n",
    "sqli_patterns = [r'\\b(select|union|where|from|and|or|sleep|waitfor|delay|--|#)\\b', r'[\\'\"]']\n",
    "xss_patterns = [r'(<script>|javascript:|on\\w+=|alert|eval|<img|<iframe)', r'[\\'\";]']\n",
    "\n",
    "def extract_payload_features(payload, length):\n",
    "    payload_lower = str(payload).lower()\n",
    "    \n",
    "    # Feature: Presence of risky patterns\n",
    "    sqli_features = [1 if any(re.search(p, payload_lower, re.IGNORECASE) for p in sqli_patterns) else 0]\n",
    "    xss_features = [1 if any(re.search(p, payload_lower, re.IGNORECASE) for p in xss_patterns) else 0]\n",
    "    \n",
    "    # Feature: Special character frequency\n",
    "    special_chars = len(re.findall(r'[\\'\";<>=&|]', payload_lower))\n",
    "    \n",
    "    # Feature: Payload length\n",
    "    payload_length = length\n",
    "    \n",
    "    return sqli_features + xss_features + [special_chars, payload_length]\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 10,
   "id": "a406855e",
   "metadata": {},
   "outputs": [
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      "2025-05-20 12:15:07,628 - INFO - Payload features extracted successfully.\n"
     ]
    }
   ],
   "source": [
    "# Apply feature extraction\n",
    "try:\n",
    "    payload_features = payload_df.apply(\n",
    "        lambda row: extract_payload_features(row['payload'], row['length']),\n",
    "        axis=1\n",
    "    )\n",
    "    payload_features_df = pd.DataFrame(\n",
    "        payload_features.tolist(),\n",
    "        columns=['sqli_pattern', 'xss_pattern', 'special_chars', 'payload_length']\n",
    "    )\n",
    "    payload_df = pd.concat([payload_df, payload_features_df], axis=1)\n",
    "    logging.info(\"Payload features extracted successfully.\")\n",
    "except Exception as e:\n",
    "    logging.error(f\"Error extracting payload features: {e}\")\n",
    "    raise\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 11,
   "id": "f80e4565",
   "metadata": {},
   "outputs": [],
   "source": [
    "# --- Combine Datasets ---\n",
    "# Create pairs: normal code + normal payload, vulnerable code + anomalous payload\n",
    "combined_data = []"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 12,
   "id": "5b0e4a41",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Normal pairs\n",
    "normal_codes = code_df[code_df['Vulnerability Type'] == 'none']\n",
    "normal_payloads = payload_df[payload_df['label'] == 'norm']\n",
    "for _, code_row in normal_codes.iterrows():\n",
    "    for _, payload_row in normal_payloads.sample(min(2, len(normal_payloads))).iterrows():\n",
    "        combined_data.append({\n",
    "            'code_snippet': code_row['Code Snippet'],\n",
    "            'payload': payload_row['payload'],\n",
    "            'code_sqli_risky': code_row['sqli_risky'],\n",
    "            'code_xss_risky': code_row['xss_risky'],\n",
    "            'code_length': code_row['code_length'],\n",
    "            'token_count': code_row['token_count'],\n",
    "            'token_execute': code_row['token_execute'],\n",
    "            'token_innerHTML': code_row['token_innerHTML'],\n",
    "            'token_user_input': code_row['token_user_input'],\n",
    "            'token_query': code_row['token_query'],\n",
    "            'payload_sqli_pattern': payload_row['sqli_pattern'],\n",
    "            'payload_xss_pattern': payload_row['xss_pattern'],\n",
    "            'special_chars': payload_row['special_chars'],\n",
    "            'payload_length': payload_row['payload_length'],\n",
    "            'attack_type': 'none',\n",
    "            'label': 0  # Safe\n",
    "        })"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 13,
   "id": "7daccb54",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Malicious pairs: Match SQLi/XSS code with SQLi/XSS payloads\n",
    "sqli_codes = code_df[code_df['Vulnerability Type'] == 'SQLi']\n",
    "xss_codes = code_df[code_df['Vulnerability Type'] == 'XSS']\n",
    "sqli_payloads = payload_df[payload_df['attack_type'] == 'sqli']\n",
    "xss_payloads = payload_df[payload_df['attack_type'] == 'xss']"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 14,
   "id": "df0a16e1",
   "metadata": {},
   "outputs": [],
   "source": [
    "for _, code_row in sqli_codes.iterrows():\n",
    "    for _, payload_row in sqli_payloads.sample(min(5, len(sqli_payloads))).iterrows():\n",
    "        combined_data.append({\n",
    "            'code_snippet': code_row['Code Snippet'],\n",
    "            'payload': payload_row['payload'],\n",
    "            'code_sqli_risky': code_row['sqli_risky'],\n",
    "            'code_xss_risky': code_row['xss_risky'],\n",
    "            'code_length': code_row['code_length'],\n",
    "            'token_count': code_row['token_count'],\n",
    "            'token_execute': code_row['token_execute'],\n",
    "            'token_innerHTML': code_row['token_innerHTML'],\n",
    "            'token_user_input': code_row['token_user_input'],\n",
    "            'token_query': code_row['token_query'],\n",
    "            'payload_sqli_pattern': payload_row['sqli_pattern'],\n",
    "            'payload_xss_pattern': payload_row['xss_pattern'],\n",
    "            'special_chars': payload_row['special_chars'],\n",
    "            'payload_length': payload_row['payload_length'],\n",
    "            'attack_type': 'sqli',\n",
    "            'label': 1  # Malicious\n",
    "        })"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 15,
   "id": "93deb730",
   "metadata": {},
   "outputs": [],
   "source": [
    "for _, code_row in xss_codes.iterrows():\n",
    "    for _, payload_row in xss_payloads.sample(min(5, len(xss_payloads))).iterrows():\n",
    "        combined_data.append({\n",
    "            'code_snippet': code_row['Code Snippet'],\n",
    "            'payload': payload_row['payload'],\n",
    "            'code_sqli_risky': code_row['sqli_risky'],\n",
    "            'code_xss_risky': code_row['xss_risky'],\n",
    "            'code_length': code_row['code_length'],\n",
    "            'token_count': code_row['token_count'],\n",
    "            'token_execute': code_row['token_execute'],\n",
    "            'token_innerHTML': code_row['token_innerHTML'],\n",
    "            'token_user_input': code_row['token_user_input'],\n",
    "            'token_query': code_row['token_query'],\n",
    "            'payload_sqli_pattern': payload_row['sqli_pattern'],\n",
    "            'payload_xss_pattern': payload_row['xss_pattern'],\n",
    "            'special_chars': payload_row['special_chars'],\n",
    "            'payload_length': payload_row['payload_length'],\n",
    "            'attack_type': 'xss',\n",
    "            'label': 1  # Malicious\n",
    "        })\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 16,
   "id": "cf782185",
   "metadata": {},
   "outputs": [
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      "2025-05-20 12:17:08,652 - INFO - Combined dataset created with 6200 rows.\n"
     ]
    }
   ],
   "source": [
    "# Create combined DataFrame\n",
    "combined_df = pd.DataFrame(combined_data)\n",
    "logging.info(f\"Combined dataset created with {len(combined_df)} rows.\")\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 17,
   "id": "a5da7c7a",
   "metadata": {},
   "outputs": [
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      "2025-05-20 12:17:23,742 - INFO - Code TF-IDF features: 42, Payload TF-IDF features: 50\n",
      "2025-05-20 12:17:23,742 - INFO - TF-IDF features added to combined dataset.\n"
     ]
    }
   ],
   "source": [
    "# --- Text Vectorization ---\n",
    "# Vectorize code snippets and payloads for additional features\n",
    "tfidf_code = TfidfVectorizer(max_features=50, stop_words=None)\n",
    "tfidf_payload = TfidfVectorizer(max_features=50, stop_words=None)\n",
    "\n",
    "try:\n",
    "    code_tfidf = tfidf_code.fit_transform(combined_df['code_snippet']).toarray()\n",
    "    payload_tfidf = tfidf_payload.fit_transform(combined_df['payload'].astype(str)).toarray()\n",
    "    \n",
    "    # Get actual number of features\n",
    "    code_tfidf_features = code_tfidf.shape[1]\n",
    "    payload_tfidf_features = payload_tfidf.shape[1]\n",
    "    logging.info(f\"Code TF-IDF features: {code_tfidf_features}, Payload TF-IDF features: {payload_tfidf_features}\")\n",
    "    \n",
    "    code_tfidf_df = pd.DataFrame(\n",
    "        code_tfidf, \n",
    "        columns=[f'code_tfidf_{i}' for i in range(code_tfidf_features)]\n",
    "    )\n",
    "    payload_tfidf_df = pd.DataFrame(\n",
    "        payload_tfidf, \n",
    "        columns=[f'payload_tfidf_{i}' for i in range(payload_tfidf_features)]\n",
    "    )\n",
    "    \n",
    "    combined_df = pd.concat([combined_df, code_tfidf_df, payload_tfidf_df], axis=1)\n",
    "    logging.info(\"TF-IDF features added to combined dataset.\")\n",
    "except Exception as e:\n",
    "    logging.error(f\"Error during text vectorization: {e}\")\n",
    "    raise\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 18,
   "id": "c7ff0605",
   "metadata": {},
   "outputs": [],
   "source": [
    "# --- Train Model ---\n",
    "# Features for training\n",
    "feature_cols = (\n",
    "    ['code_sqli_risky', 'code_xss_risky', 'code_length', 'token_count'] +\n",
    "    [f'token_{t}' for t in ['execute', 'innerHTML', 'user_input', 'query']] +\n",
    "    ['payload_sqli_pattern', 'payload_xss_pattern', 'special_chars', 'payload_length'] +\n",
    "    [f'code_tfidf_{i}' for i in range(code_tfidf_features)] +\n",
    "    [f'payload_tfidf_{i}' for i in range(payload_tfidf_features)]\n",
    ")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 19,
   "id": "ef36dd70",
   "metadata": {},
   "outputs": [
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      "2025-05-20 12:18:43,159 - INFO - Data split into training and testing sets.\n"
     ]
    }
   ],
   "source": [
    "# Verify all feature columns exist\n",
    "missing_cols = [col for col in feature_cols if col not in combined_df.columns]\n",
    "if missing_cols:\n",
    "    logging.error(f\"Missing columns in combined_df: {missing_cols}\")\n",
    "    raise KeyError(f\"Columns {missing_cols} not found in combined_df\")\n",
    "\n",
    "X = combined_df[feature_cols]\n",
    "y = combined_df['label']\n",
    "\n",
    "# Split data\n",
    "try:\n",
    "    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)\n",
    "    logging.info(\"Data split into training and testing sets.\")\n",
    "except Exception as e:\n",
    "    logging.error(f\"Error splitting data: {e}\")\n",
    "    raise\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 20,
   "id": "ce5ae1dd",
   "metadata": {},
   "outputs": [
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      "2025-05-20 12:19:10,777 - INFO - Random Forest model trained.\n"
     ]
    }
   ],
   "source": [
    "# Train Random Forest\n",
    "model = RandomForestClassifier(n_estimators=100, random_state=42)\n",
    "model.fit(X_train, y_train)\n",
    "logging.info(\"Random Forest model trained.\")\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 21,
   "id": "3e6a0a92",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Predict and evaluate\n",
    "y_pred = model.predict(X_test)\n",
    "accuracy = accuracy_score(y_test, y_pred)\n",
    "precision = precision_score(y_test, y_pred)\n",
    "recall = recall_score(y_test, y_pred)\n",
    "f1 = f1_score(y_test, y_pred)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 22,
   "id": "5e91e18a",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Model Performance:\n",
      "Accuracy: 1.0000\n",
      "Precision: 1.0000\n",
      "Recall: 1.0000\n",
      "F1-Score: 1.0000\n"
     ]
    }
   ],
   "source": [
    "# Print results\n",
    "print(f\"Model Performance:\")\n",
    "print(f\"Accuracy: {accuracy:.4f}\")\n",
    "print(f\"Precision: {precision:.4f}\")\n",
    "print(f\"Recall: {recall:.4f}\")\n",
    "print(f\"F1-Score: {f1:.4f}\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 23,
   "id": "9be916ea",
   "metadata": {},
   "outputs": [
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      "2025-05-20 12:20:23,322 - INFO - Combined dataset saved as 'combined_attack_detection.csv'\n"
     ]
    }
   ],
   "source": [
    "# Save combined dataset\n",
    "try:\n",
    "    combined_df.to_csv('combined_attack_detection.csv', index=False)\n",
    "    logging.info(\"Combined dataset saved as 'combined_attack_detection.csv'\")\n",
    "except Exception as e:\n",
    "    logging.error(f\"Error saving combined dataset: {e}\")\n",
    "    raise"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "id": "b3864b92",
   "metadata": {},
   "outputs": [],
   "source": []
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python [conda env:base] *",
   "language": "python",
   "name": "conda-base-py"
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
