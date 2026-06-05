import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import numpy as np
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split

# Sample data (benign vs. attack; expand with generator.py outputs)
texts = [
    "normal search query", "SELECT * FROM users", "hello world",  # Benign
    "' OR '1'='1", "'; --", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",  # Attacks
    # Add more from generator
] * 50  # Repeat for larger dataset
labels = [0, 0, 0, 1, 1, 1, 1] * 50

# Preprocess
tokenizer = Tokenizer(num_words=1000)
tokenizer.fit_on_texts(texts)
sequences = tokenizer.texts_to_sequences(texts)
padded = pad_sequences(sequences, maxlen=50)

# Split
X_train, X_test, y_train, y_test = train_test_split(padded, np.array(labels), test_size=0.2, random_state=42)

# Build LSTM model
model = Sequential([
    Embedding(1000, 32, input_length=50),
    LSTM(64),
    Dense(1, activation='sigmoid')
])
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.fit(X_train, y_train, epochs=5, batch_size=32)

# Predict and confusion matrix (run this part after training)
pred = (model.predict(X_test) > 0.5).astype(int)
cm = confusion_matrix(y_test, pred)
print("LSTM Confusion Matrix:")
print(cm)

# Detection function (for real-time use)
def detect_attack(input_text, threshold=0.5):
    seq = tokenizer.texts_to_sequences([input_text])
    padded = pad_sequences(seq, maxlen=50)
    pred = model.predict(padded)[0][0]
    return "Attack" if pred > threshold else "Benign"