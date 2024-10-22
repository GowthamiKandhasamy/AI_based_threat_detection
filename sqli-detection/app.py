import joblib
from flask import Flask, request, render_template
import re
import numpy as np
from scipy.sparse import hstack
import requests

# Load the trained model and vectorizer
model = joblib.load('trained_sql_injection_model.joblib')
vectorizer = joblib.load('tfidf_vectorizer.joblib')

app = Flask(__name__)

# Define Slack Webhook URL (replace with your actual URL)
SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/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'

# Define known vulnerability patterns for static analysis
VULNERABILITY_PATTERNS = {
    "SQL Injection": [
        r"(?i)union select",   # Union-based SQLi
        r"(?i)or 1=1",         # True condition
        r"(?i)--",             # SQL comment
        r"(?i)sleep\((\d+)\)", # Time-based SQLi
        r"(?i)select.*from.*information_schema",  # Error-based SQLi
        r"(?i);.*drop.*",      # Stacked query injection (e.g., DROP TABLE)
    ]
}

# Function to send alert to Slack
def send_slack_alert(query, vulnerabilities):
    alert_message = f"🚨 *SQL Injection Alert Detected* 🚨\nQuery: `{query}`\nDetected Vulnerabilities: {', '.join(vulnerabilities)}"
    slack_data = {'text': alert_message}

    response = requests.post(SLACK_WEBHOOK_URL, json=slack_data)
    if response.status_code != 200:
        raise ValueError(f"Request to Slack returned an error {response.status_code}, the response is:\n{response.text}")

# Provides specific suggestions based on detected vulnerabilities
def provide_suggestions(vulnerabilities, query):
    suggestions = []
    if "SQL Injection" in vulnerabilities:
        if re.search(r"(?i)union select", query):
            suggestions.append({
                "suggestion": "Your query includes a `UNION SELECT`, which is often used in SQL injection attacks to combine the results from another table. Use parameterized queries to prevent this type of injection.",
                "example": "cursor.execute('SELECT * FROM users WHERE id = ?', [id])"
            })
        elif re.search(r"(?i)or 1=1", query):
            suggestions.append({
                "suggestion": "Your query includes an always-true condition (`OR '1'='1'`), which is commonly used in authentication bypass attacks. Avoid using string concatenation to construct SQL queries.",
                "example": "cursor.execute('SELECT * FROM users WHERE username = ?', [username])"
            })
        elif re.search(r"(?i)sleep\((\d+)\)", query):
            suggestions.append({
                "suggestion": "Your query includes the function `SLEEP()`, which is often used in time-based blind SQL injection attacks to delay execution. Avoid allowing user input in database functions.",
                "example": "cursor.execute('SELECT * FROM users WHERE id = ?', [id])"
            })
        elif re.search(r"(?i);.*drop.*", query):
            suggestions.append({
                "suggestion": "Your query contains multiple SQL statements (`stacked queries`), which can be used to perform malicious operations like dropping tables. Limit the use of stacked queries in user input.",
                "example": "Avoid running multiple queries in a single execution."
            })
        else:
            suggestions.append({
                "suggestion": "Use Object-Relational Mapping (ORM) frameworks to avoid SQL injections.",
                "example": "User.query.filter_by(username=username).first()"
            })
    return suggestions

# Performs static analysis of the query for known vulnerabilities
def static_analysis(query):
    detected_vulnerabilities = []
    for vuln_type, patterns in VULNERABILITY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, query):
                detected_vulnerabilities.append(vuln_type)
                break
    return detected_vulnerabilities

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    query = request.form['query']

    # Transform the query using the vectorizer (TF-IDF)
    transformed_query = vectorizer.transform([query])

    # Calculate the query length feature (length of the query in characters)
    query_length = np.array([[len(query)]])

    # Combine the TF-IDF features with the query length feature
    combined_features = hstack([transformed_query, query_length])

    # Make prediction using the trained model
    is_sqli = model.predict(combined_features)[0]

    # Check for static vulnerabilities
    detected_vulnerabilities = static_analysis(query)
    
    if is_sqli or detected_vulnerabilities:
        result = "Vulnerable"
        details = "The submitted query is vulnerable."
        vulnerabilities = detected_vulnerabilities if detected_vulnerabilities else ["SQL Injection"]
        suggestions = provide_suggestions(vulnerabilities, query)

        # Send alert to Slack
        send_slack_alert(query, vulnerabilities)
    else:
        result = "Safe"
        details = "The submitted query appears safe."
        vulnerabilities = None
        suggestions = None

    return render_template('index.html', result=result, details=details, vulnerabilities=vulnerabilities, suggestions=suggestions)

if __name__ == '__main__':
    app.run(debug=True)
