import joblib
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Example dataset: payloads and labels (0 = safe, 1 = malicious)

data = [
    # Safe payloads
    ("username=admin&password=admin", 0),
    ("username=admin&password=123456", 0),
    ("username=john_doe&password=secure123", 0),
    ("username=alice123&password=password1", 0),
    ("username=bob_user&password=my_secret", 0),
    ("username=test_user&password=test_pass", 0),
    ("username=safe_user&password=safe_pass", 0),
    ("username=valid_user&password=valid_password", 0),
    ("username=guest&password=welcome123", 0),
    ("username=employee1&password=worksecure", 0),
    ("username=user123&password=securepassword", 0),
    ("usrname=admin1&password=adminpass", 0),
    ("username=normaluser&password=normalpass", 0),
    ("username=legit_user&password=legit_pass", 0),
    ("username=janedoe&password=123456", 0),
    ("username=guest_user&password=guestpass", 0),

    # Malicious payloads
    ("username=admin'--&password=", 1),
    ("username=' OR '1'='1&password=", 1),
    ("username=admin' OR 1=1 --&password=", 1),
    ("username=admin&password=123 OR '1'='1", 1),
    ("username=user1&password=' UNION SELECT * FROM users --", 1),
    ("username=test&password='; DROP TABLE users; --", 1),
    ("username=alice' AND '1'='1&password=test", 1),
    ("username=admin';--&password=", 1),
    ("username=' OR 1=1; --&password=", 1),
    ("username=guest&password='; SHUTDOWN; --", 1),
    ("username=normaluser' AND 1=1&password=normalpass", 1),
    ("username=janedoe'; EXEC xp_cmdshell('whoami') --&password=", 1),
    ("username=attacker' OR 'a'='a&password=hacked", 1),
    ("username=admin'; WAITFOR DELAY '0:0:5' --&password=", 1),
    ("username='; SELECT * FROM users WHERE 'x'='x&password=", 1),
    ("username=guest' UNION ALL SELECT username, password FROM users --&password=", 1),
    ("username=test'; DELETE FROM users WHERE 'a'='a&password=", 1),
    ("username=admin&password=' OR 'a'='a' --", 1),
    ("username=' OR EXISTS(SELECT * FROM users) --&password=", 1),
    ("username=admin' UNION SELECT null, username, password FROM users --&password=", 1),

    # Mixed payloads
    ("username=safe_user'--&password=test", 1),
    ("username=legit_user&password=secure_pass", 0),
    ("username=test_user&password=' OR '1'='1", 1),
    ("username=employee1&password=worksecure", 0),
    ("username=guest&password=welcome123", 0),
    ("username=guest'--&password=", 1),
    ("username=user123&password=securepassword", 0),
    ("username=admin1&password=' OR 'x'='x", 1),
    ("username=normaluser&password=normalpass", 0),
    ("username=legit_user' AND '1'='1&password=legit_pass", 1),
    ("username=john_doe&password=' UNION SELECT * FROM accounts", 1),
    ("username=alice123&password=password1", 0),
    ("username=bob_user&password=my_secret", 0),
    ("username=safe_user&password='; DROP DATABASE test;", 1),
    ("username=janedoe&password=123456", 0),
    ("username=test_user&password=test_pass", 0),
    ("username=guest_user&password=guestpass", 0),
    ("username=valid_user&password=' UNION SELECT * FROM sensitive_data", 1),
    ("username=janedoe' OR 'a'='a&password=secure", 1),
    ("username=admin' OR '1'='1&password=", 1),
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
