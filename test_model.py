import joblib
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Example dataset: payloads and labels (0 = safe, 1 = malicious)
data = [
    ("SELECT * FROM users WHERE username='admin'--", 1),  # Malicious
    ("' OR '1'='1", 1),  # Malicious
    ("DROP TABLE users", 1),  # Malicious
    ("admin' #", 1),  # Malicious
    ("username=admin&password=123456", 0),  # Safe
    ("GET /index.html HTTP/1.1", 0),  # Safe
    ("username=user123&password=mysecurepassword", 0),  # Safe
    ("<script>alert('XSS');</script>", 1),  # Malicious
    ("user_input=' OR 1=1", 1),  # Malicious
    ("GET /home HTTP/1.1", 0),  # Safe
]

# Split data into payloads and labels
payloads, labels = zip(*data)

# Convert text payloads into feature vectors using CountVectorizer
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(payloads)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)

# Train the model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")

# Save the trained model and vectorizer
joblib.dump(model, 'sql_injection_model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')
print("Model and vectorizer saved.")
