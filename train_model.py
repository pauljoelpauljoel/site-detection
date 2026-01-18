import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

# Generate dummy data for demonstration
# Features: [length_url, has_ip, has_at, dot_count, is_https]
# 0: Safe, 1: Suspicious, 2: Scam

data = [
    [20, 0, 0, 2, 1, 0], # Safe: Short, no IP, no @, few dots, https
    [25, 0, 0, 2, 1, 0], # Safe
    [30, 0, 0, 3, 1, 0], # Safe
    [15, 0, 0, 2, 0, 1], # Suspicious: No https
    [80, 0, 1, 4, 0, 2], # Scam: Long, @ symbol, many dots, no https
    [90, 1, 0, 5, 0, 2], # Scam: IP address, long
    [45, 0, 0, 4, 0, 1], # Suspicious
    [100, 1, 1, 6, 0, 2] # Scam
]

# Create a larger synthetic dataset
X_dummy = []
y_dummy = []

for _ in range(100):
    # Safe samples
    X_dummy.append([np.random.randint(10, 50), 0, 0, np.random.randint(1, 3), 1])
    y_dummy.append(0)
    
    # Suspicious samples
    X_dummy.append([np.random.randint(40, 70), 0, np.random.randint(0, 2), np.random.randint(2, 5), np.random.randint(0, 2)])
    y_dummy.append(1)
    
    # Scam samples
    X_dummy.append([np.random.randint(60, 150), np.random.randint(0, 2), np.random.randint(0, 2), np.random.randint(3, 7), 0])
    y_dummy.append(2)

df = pd.DataFrame(X_dummy, columns=['url_length', 'has_ip', 'has_at', 'dot_count', 'is_https'])
df['label'] = y_dummy

X = df.drop('label', axis=1)
y = df['label']

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Save model
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model trained and saved as model.pkl")
