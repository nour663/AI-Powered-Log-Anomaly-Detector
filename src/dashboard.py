import os
import json
import pandas as pd
import plotly.express as px
import plotly.utils

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash
)

from src.detector import LogDetector

# ----------------------------
# Flask Configuration
# ----------------------------

app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

detector = LogDetector()

# Store last analysis
last_results = pd.DataFrame()


# ----------------------------
# Dashboard
# ----------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    global last_results

    if request.method == "POST":

        if "logfile" not in request.files:
            flash("No file uploaded.")
            return redirect(request.url)

        file = request.files["logfile"]

        if file.filename == "":
            flash("Please select a file.")
            return redirect(request.url)

        filepath = os.path.join(
            app.config["UPLOAD_FOLDER"],
            file.filename
        )

        file.save(filepath)

        try:

            last_results = detector.analyze(filepath)
            

            logs = []

            if not last_results.empty:
                logs = last_results.to_dict(
                    orient="records"
                )

            total_logs = len(last_results)

            anomaly_count = 0

            if "is_anomaly" in last_results.columns:
                anomaly_count = last_results["is_anomaly"].sum()
            print(logs[:3])
            return render_template(
                "index.html",
                logs=logs,
                total_logs=total_logs,
                anomalies=anomaly_count,
                normal_logs=total_logs-anomaly_count,
                model_status="Ready"
            )

        except Exception as e:
            flash(str(e))
            return redirect(request.url)

    return render_template(
        "index.html",
        logs=[],
        total_logs=0,
        anomalies=0,
        normal_logs=0,
        model_status="Not Trained"
    )


# ----------------------------
# Return alerts
# ----------------------------

@app.route("/api/alerts")
def alerts():

    return jsonify(detector.alerts)


# ----------------------------
# Analyze from URL
# ----------------------------

@app.route("/api/analyze/<path:log_path>")
def analyze(log_path):

    try:

        results = detector.analyze(log_path)

        return jsonify(
            results.to_dict(orient="records")
        )

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ----------------------------
# Plotly Chart
# ----------------------------

@app.route("/api/chart")
def chart():

    global last_results

    if last_results.empty:

        return jsonify({})

    # Preferred chart: anomaly counts
    if "is_anomaly" in last_results.columns:

        df = (
            last_results["is_anomaly"]
            .value_counts()
            .rename_axis("Status")
            .reset_index(name="Count")
        )

        df["Status"] = df["Status"].replace({
            True: "Anomaly",
            False: "Normal"
        })

        fig = px.bar(
            df,
            x="Status",
            y="Count",
            color="Status",
            title="Detected Log Events"
        )

    elif "attack_type" in last_results.columns:

        df = (
            last_results
            .groupby("attack_type")
            .size()
            .reset_index(name="Count")
        )

        fig = px.bar(
            df,
            x="attack_type",
            y="Count",
            color="attack_type",
            title="Attack Types"
        )

    else:

        return jsonify({})

    return json.dumps(
        fig,
        cls=plotly.utils.PlotlyJSONEncoder
    )


# ----------------------------
# Download results
# ----------------------------

@app.route("/api/results")
def results():

    global last_results

    if last_results.empty:
        return jsonify([])

    return jsonify(
        last_results.to_dict(orient="records")
    )


# ----------------------------
# Health check
# ----------------------------

@app.route("/health")
def health():

    return {
        "status": "running"
    }


# ----------------------------
# Run
# ----------------------------

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )