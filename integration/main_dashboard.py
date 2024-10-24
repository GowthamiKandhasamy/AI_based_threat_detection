from flask import Flask, jsonify
import psutil

app = Flask(__name__)

@app.route('/system_metrics')
def system_metrics():
    # Get CPU and memory usage
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.percent

    # Return metrics as JSON
    return jsonify(cpu=cpu_usage, memory=memory_usage)

if __name__ == '__main__':
    app.run(debug=True, port=5050)
