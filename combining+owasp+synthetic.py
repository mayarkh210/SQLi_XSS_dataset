{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": 1,
   "id": "f3cf8070-8883-419f-b968-31aa369e474a",
   "metadata": {},
   "outputs": [],
   "source": [
    "import pandas as pd\n",
    "import numpy as np\n",
    "\n",
    "# Load the combined attack detection dataset\n",
    "df_combined = pd.read_csv('combined_attack_detection_with_owasp.csv')\n",
    "\n",
    "# Load the synthetic dataset\n",
    "df_synthetic = pd.read_csv('synthetic_attack_detection.csv')"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 2,
   "id": "a7afc21e-9b3c-4e9a-8476-9fa8719323e3",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Step 1: Preprocess the synthetic dataset to match the combined dataset pattern\n",
    "\n",
    "# Assume the last three columns are: code_snippet, payload, attack_type\n",
    "code_snippet_col = df_synthetic.columns[-3]\n",
    "payload_col = df_synthetic.columns[-2]\n",
    "attack_type_col = df_synthetic.columns[-1]\n",
    "\n",
    "# Extract these for reordering\n",
    "code_snippet = df_synthetic[code_snippet_col]\n",
    "payload = df_synthetic[payload_col]\n",
    "attack_type = df_synthetic[attack_type_col]\n",
    "\n",
    "# Drop these columns temporarily\n",
    "df_temp = df_synthetic.drop([code_snippet_col, payload_col, attack_type_col], axis=1)\n",
    "\n",
    "# Define the core feature columns (non-TF-IDF) to match combined dataset\n",
    "feature_order = [\n",
    "    'code_sqli_risky', 'code_xss_risky', 'code_length', 'token_count',\n",
    "    'token_execute', 'token_innerHTML', 'token_user_input', 'token_query',\n",
    "    'payload_sqli_pattern', 'payload_xss_pattern', 'special_chars', 'payload_length'\n",
    "]"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 3,
   "id": "8f3c91e3-eb45-4f7e-81da-23b832b3801c",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Select and reorder these features\n",
    "df_features = df_temp[feature_order].copy()\n",
    "\n",
    "# Handle TF-IDF columns: Only include columns present in both datasets\n",
    "code_tfidf_cols_combined = [col for col in df_combined.columns if col.startswith('code_tfidf_')]\n",
    "payload_tfidf_cols_combined = [col for col in df_combined.columns if col.startswith('payload_tfidf_')]\n",
    "code_tfidf_cols_synthetic = [col for col in df_temp.columns if col.startswith('code_tfidf_')]\n",
    "payload_tfidf_cols_synthetic = [col for col in df_temp.columns if col.startswith('payload_tfidf_')]\n",
    "\n",
    "# Use intersection of TF-IDF columns to avoid zero-padding\n",
    "code_tfidf_common = sorted(list(set(code_tfidf_cols_combined) & set(code_tfidf_cols_synthetic)))\n",
    "payload_tfidf_common = sorted(list(set(payload_tfidf_cols_combined) & set(payload_tfidf_cols_synthetic)))\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 4,
   "id": "0ab2744d-36f5-4d3c-9594-42da78d2eb22",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Select common TF-IDF columns\n",
    "code_tfidf_df = df_temp[code_tfidf_common]\n",
    "payload_tfidf_df = df_temp[payload_tfidf_common]\n",
    "\n",
    "# Construct the preprocessed synthetic dataset\n",
    "df_preprocessed = pd.concat([\n",
    "    code_snippet.rename('code_snippet'),\n",
    "    payload.rename('payload'),\n",
    "    df_features,\n",
    "    attack_type.rename('attack_type')\n",
    "], axis=1)\n",
    "\n",
    "# Add label column: 1 for attacks (sqli or xss)\n",
    "df_preprocessed['label'] = 1"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 5,
   "id": "4d01f730-4868-46b1-924d-132c633867c8",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Append common TF-IDF columns\n",
    "df_preprocessed = pd.concat([df_preprocessed, code_tfidf_df, payload_tfidf_df], axis=1)\n",
    "\n",
    "# Ensure all expected columns from combined dataset are present\n",
    "expected_cols = ['code_snippet', 'payload'] + feature_order + ['attack_type', 'label'] + \\\n",
    "                code_tfidf_common + payload_tfidf_common\n",
    "\n",
    "# Fill missing columns with appropriate defaults\n",
    "for col in expected_cols:\n",
    "    if col not in df_preprocessed.columns:\n",
    "        df_preprocessed[col] = 0.0 if 'tfidf' in col else 'none' if col == 'attack_type' else 0\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 6,
   "id": "2a213df2-dc1f-48e0-bd14-ee9a01958b01",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Reorder columns to match expected_cols\n",
    "df_preprocessed = df_preprocessed[expected_cols]\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 7,
   "id": "b7ac3908-64ee-42e2-a3d5-6e0bd2662def",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Step 2: Combine the preprocessed synthetic dataset with the combined dataset\n",
    "df_final = pd.concat([df_combined[expected_cols], df_preprocessed], ignore_index=True)\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 8,
   "id": "80d0fd60-9686-4bd7-b416-8d4fdc90d9bc",
   "metadata": {},
   "outputs": [],
   "source": [
    "# Step 3: Remove columns with excessive zeros (e.g., >90% zeros)\n",
    "threshold = 0.9  # Remove columns where 90% or more values are zero\n",
    "zero_proportion = (df_final == 0).mean()\n",
    "columns_to_keep = zero_proportion[zero_proportion < threshold].index\n",
    "df_final = df_final[columns_to_keep]\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 9,
   "id": "e1c5d5cb-200b-424f-b370-c429910e0dd8",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Merged dataset saved to 'merged_attack_detection.csv'\n",
      "Number of columns after removing high-zero columns: 43\n",
      "Removed 65 columns with >= 90.0% zero values\n"
     ]
    }
   ],
   "source": [
    "# Step 4: Save the merged dataset to a new CSV file\n",
    "output_file = 'merged_attack_detection.csv'\n",
    "df_final.to_csv(output_file, index=False)\n",
    "\n",
    "print(f\"Merged dataset saved to '{output_file}'\")\n",
    "print(f\"Number of columns after removing high-zero columns: {len(df_final.columns)}\")\n",
    "print(f\"Removed {len(expected_cols) - len(df_final.columns)} columns with >= {threshold*100}% zero values\")"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "id": "fbf15e1b-944b-41cc-b3ce-21cb309e0c70",
   "metadata": {},
   "outputs": [],
   "source": []
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "id": "5f98a973-082e-48ac-b999-0a3841cc9783",
   "metadata": {},
   "outputs": [],
   "source": []
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
