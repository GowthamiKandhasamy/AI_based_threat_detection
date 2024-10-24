# AI_based_threat_detection
An AI-based threat detection software that focuses on OWASP's top vulnerabilities: BAC and SQLi

BAC setup details:

Configure venv for the folder
Install the python packages in the requirement
Train the model using "train_multioutput_rf_model.py"
Run "bac_multioutput_dashboard.py"

Integration details:

Install psutil and requirements here as well
Ensure that BAC runs on 8080, SQLi on 5000 and main_dashboard on 5050
Install flask_cors library in your directory
Add "from flask_cors import CORS" to your app.py code
Enable CORS immediately after initializing your flask app with "CORS(app)" or "CORS(app.server)" (for dash applications)

Better create two directories: BAC and SQli and place the files in them. Make sure that you've changed the path in my files
Place the integration files (dashboard.html and main_dashboard.py) alongside the directories you created. That's the easier way to work with Flask API
The "View system log" button does nothing as of now. If you have a better idea on what to do with it or any replacement you could think of, do it. Otherwise, just remove it
