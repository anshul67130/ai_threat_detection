from flask import Flask, request, jsonify, render_template
import joblib
import logging
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(filename="server.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Load the trained model and vectorizer
model = joblib.load('sql_injection_model.pkl')
vectorizer = joblib.load('vectorizer.pkl')

# In-memory log to store blocked requests
blocked_requests = []

def detect_sql_injection(payload):
    """
    Detect whether the given payload is malicious (SQL injection).
    """
    try:
        # Transform the payload into feature vector
        X = vectorizer.transform([payload])
        prediction = model.predict(X)[0]
        if prediction == 1:
            logging.warning(f"Malicious payload detected: {payload}")
            return True
    except Exception as e:
        logging.error(f"Error during detection: {e}")
    return False

@app.route('/')
def home():
    """
    Render the home page with a simple form.
    """
    return '''
    <h1>Threat Detection Demo</h1>
    <form action="/submit" method="post">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username"><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password"><br><br>
        <button type="submit">Submit</button>
    </form>
    '''

@app.route('/submit', methods=['POST'])
def submit():
    """
    Process the form submission and perform threat detection.
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Combine username and password for analysis
    payload = f"username={username}&password={password}"
    is_malicious = detect_sql_injection(payload)

    if is_malicious:
        # Log blocked request
        blocked_requests.append({
            "payload": payload,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        logging.info(f"Blocked malicious request: {payload}")
        return jsonify({
            "status": "blocked",
            "message": "Malicious SQL injection detected! Access denied."
        }), 403

    logging.info(f"Safe request processed: {payload}")
    return jsonify({
        "status": "allowed",
        "message": "Request is safe. Access granted.",
        "username": username
    })


@app.route('/logs')
def logs():
    """
    Serve the blocked requests as JSON data for the dashboard.
    """
    return jsonify(blocked_requests)

if __name__ == '__main__':
    app.run(debug=True)
