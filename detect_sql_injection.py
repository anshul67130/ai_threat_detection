import joblib

# Load the trained model and vectorizer
model = joblib.load('sql_injection_model.pkl')
vectorizer = joblib.load('vectorizer.pkl')

def detect_sql_injection(payload):
    """
    Detect whether the given payload is malicious (SQL injection).
    """
    # Transform the payload into feature vector
    X = vectorizer.transform([payload])
    
    # Predict using the trained model
    prediction = model.predict(X)[0]
    
    if prediction == 1:
        return "Malicious SQL injection detected!"
    return "Payload is safe."

# Test the detector
test_payloads = [
    "SELECT * FROM users WHERE username='admin'--",  # Malicious
    "username=admin&password=123456",  # Safe
    "' OR '1'='1",  # Malicious
    "GET /home HTTP/1.1",  # Safe
]

for payload in test_payloads:
    print(f"Payload: {payload}")
    print(f"Result: {detect_sql_injection(payload)}\n")
