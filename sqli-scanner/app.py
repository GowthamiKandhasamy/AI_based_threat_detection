from flask import Flask, render_template, request, redirect, url_for, send_file, session, send_from_directory
import os
import pandas as pd
import matplotlib.pyplot as plt
import pickle  # For loading the vectorizer
from keras.models import load_model
import numpy as np
import requests  # For Slack integration

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set your secret key for session management

# Configure paths
UPLOAD_FOLDER = 'uploads/'
REPORT_FOLDER = 'reports/'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# Load the model
model_path = 'models/model_fold_3.h5'  # Ensure this points to the correct model file
model = load_model(model_path)

# Load the vectorizer
vectorizer_path = 'models/vectorizer.pkl'  # Ensure this points to the correct vectorizer file
with open(vectorizer_path, 'rb') as f:
    vectorizer = pickle.load(f)  # Load the vectorizer from a file

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if 'file' in request.files:
            uploaded_file = request.files['file']
            if uploaded_file.filename.endswith('.sql'):
                filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
                uploaded_file.save(filepath)
                return redirect(url_for('scan', filename=uploaded_file.filename))
    return render_template("index.html")

@app.route("/scan/<filename>")
def scan(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    vulnerabilities = {
        "Total Queries": 0,
        "Vulnerable Queries": 0,
        "Safe Queries": 0,
        "Detailed": []
    }
    
    with open(filepath, 'r') as file:
        queries = file.read().splitlines()
    
    for query in queries:
        result = scan_query(query)  # Your ML model scanning logic
        vulnerabilities["Total Queries"] += 1
        vulnerabilities["Detailed"].append((query, result))
        if result == "Vulnerable":
            vulnerabilities["Vulnerable Queries"] += 1
            send_slack_alert(query)
        else:
            vulnerabilities["Safe Queries"] += 1
    
    # Store vulnerabilities in the session
    session['vulnerabilities'] = vulnerabilities
    create_report(vulnerabilities, filename)
    return redirect(url_for('visualize', filename=filename))

def scan_query(query):
    # Preprocess the input query
    query = preprocess_query(query)  # Define your preprocessing function
    query_vector = vectorizer.transform([query]).toarray()  # Transform to vector
    prediction = model.predict(query_vector)
    return "Vulnerable" if np.argmax(prediction) == 1 else "Safe"  # Adjust based on your class labels

def preprocess_query(query):
    # Preprocessing logic similar to what you used during training
    return query.strip().lower()  # Example normalization

def send_slack_alert(query):
    # Slack integration
    slack_webhook_url = "https://hooks.slack.com/services/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"
    payload = {
        "text": f"Vulnerability detected in query: {query}"
    }
    requests.post(slack_webhook_url, json=payload)  # Send alert to Slack

def create_report(vulnerabilities, filename):
    # Generate a report and save as CSV
    report_path = os.path.join(REPORT_FOLDER, f"report_{filename}.csv")
    df = pd.DataFrame(vulnerabilities["Detailed"], columns=["Query", "Result"])

    # Add columns for vulnerability type and mitigation strategy
    df['Vulnerability Type'] = df.apply(lambda x: get_vulnerability_type(x['Query'], x['Result']), axis=1)
    df['Mitigation Strategy'] = df.apply(lambda x: get_mitigation_strategy(x['Query'], x['Result']), axis=1)

    df.to_csv(report_path, index=False)

    # Generate visualizations
    plt.bar(['Vulnerable', 'Safe'], [vulnerabilities["Vulnerable Queries"], vulnerabilities["Safe Queries"]])
    plt.title('Scan Results')
    plt.xlabel('Query Status')
    plt.ylabel('Count')
    plt.savefig(os.path.join(REPORT_FOLDER, f"visualization_{filename}.png"))
    plt.close()

def get_vulnerability_type(query, result):
    if result == "Vulnerable":
        if "UNION" in query:
            return "Union-Based SQL Injection"
        elif "OR" in query and ("1=1" in query or "1='1'" in query):
            return "Classic SQL Injection"
        elif "SLEEP" in query:
            return "Time-Based SQL Injection"
        elif "--" in query or "/*" in query:
            return "Comment-Based SQL Injection"
        elif "EXEC" in query or "xp_cmdshell" in query:
            return "Out-of-Band SQL Injection"
        elif "SELECT" in query and "FROM" in query:
            return "Select Statement Injection"
        elif "INSERT" in query:
            return "Insert Statement Injection"
        elif "UPDATE" in query:
            return "Update Statement Injection"
        elif "DELETE" in query:
            return "Delete Statement Injection"
        elif "DROP" in query:
            return "Drop Table Injection"
    return "Safe Query"

def get_mitigation_strategy(query, result):
    if result == "Vulnerable":
        if "UNION" in query:
            return "Avoid using UNION queries without proper input validation."
        elif "OR" in query and ("1=1" in query or "1='1'" in query):
            return "Use parameterized queries to prevent Classic SQL Injection."
        elif "SLEEP" in query:
            return "Implement input validation to avoid time-based exploits."
        elif "--" in query or "/*" in query:
            return "Sanitize inputs to prevent comment injections."
        elif "EXEC" in query or "xp_cmdshell" in query:
            return "Limit database user permissions and avoid executing arbitrary commands."
        elif "SELECT" in query:
            return "Ensure SELECT statements are protected with strict input validation."
        elif "INSERT" in query:
            return "Validate all inputs to INSERT statements to prevent SQL Injection."
        elif "UPDATE" in query:
            return "Use ORM tools to safely execute UPDATE queries."
        elif "DELETE" in query:
            return "Ensure DELETE operations are well-guarded with proper authentication."
        elif "DROP" in query:
            return "Restrict permissions for DROP operations and validate input thoroughly."
    return "No action needed; ensure continued input validation."

@app.route("/visualize/<filename>")
def visualize(filename):
    vulnerabilities = session.get('vulnerabilities', None)

    if vulnerabilities is None:
        return "No vulnerabilities data available.", 400  # Handle case where data is missing

    # Render the visualization HTML and pass vulnerabilities and filename data
    return render_template("visualization.html", vulnerabilities=vulnerabilities, filename=filename)

@app.route('/reports/<path:filename>')
def serve_report(filename):
    return send_from_directory(REPORT_FOLDER, filename)

@app.route("/reports/<filename>")
def download_report(filename):
    return send_file(os.path.join(REPORT_FOLDER, filename), as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
