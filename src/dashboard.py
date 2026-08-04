from flask import Flask, render_template, jsonify
import plotly.express as px
import plotly.utils
import json
import pandas as pd
from src.detector import LogDetector

app = Flask(__name__)
detector = LogDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    return jsonify(detector.alerts)

@app.route('/api/analyze/<path:log_path>')
def analyze(log_path):
    anomalies = detector.analyze(log_path)
    return jsonify(anomalies.to_dict(orient='records'))

@app.route('/api/chart')
def chart():
    if not detector.alerts:
        return jsonify({})

    df = pd.DataFrame(detector.alerts)
    fig = px.bar(
        df.groupby('attack_type').size().reset_index(name='count'),
        x='attack_type',
        y='count',
        title='Anomalies by Attack Type',
        color='attack_type'
    )
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

if __name__ == '__main__':
    app.run(debug=True)