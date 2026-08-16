import os
import json
import pandas as pd
import plotly.express as px
import plotly.utils
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER


from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash,
    send_file
)

from src.detector import LogDetector



app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

detector = LogDetector()

# Store last analysis
last_results = pd.DataFrame()




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




@app.route("/api/alerts")
def alerts():

    return jsonify(detector.alerts)




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




@app.route("/api/results")
def results():

    global last_results

    if last_results.empty:
        return jsonify([])

    return jsonify(
        last_results.to_dict(orient="records")
    )




@app.route("/health")
def health():

    return {
        "status": "running"
    }


@app.route("/download-report")
def generate_report():
    global last_results

    if last_results.empty:
        flash("No analysis results available.")
        return redirect(url_for("index"))

    os.makedirs("reports", exist_ok=True)

    report_path = os.path.abspath(
        os.path.join("reports", "AI_Log_Report.pdf")
    )

    styles = getSampleStyleSheet()

    title_style = styles["Heading1"]
    title_style.alignment = TA_CENTER

    doc = SimpleDocTemplate(report_path)

    elements = []

    elements.append(
        Paragraph(
            "AI-Powered Log Anomaly Detection Report",
            title_style
        )
    )

    elements.append(Paragraph("<br/><br/>", styles["Normal"]))

    total_logs = len(last_results)
    anomaly_count = int(last_results["is_anomaly"].sum())
    normal_logs = total_logs - anomaly_count

    elements.append(Paragraph(f"<b>Total Logs:</b> {total_logs}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Normal Logs:</b> {normal_logs}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Anomalies:</b> {anomaly_count}", styles["Normal"]))

    elements.append(Paragraph("<br/><br/>", styles["Normal"]))

    data = [["Timestamp", "IP", "Message", "Score", "Status"]]

    for _, row in last_results.head(100).iterrows():

        data.append([
            str(row.get("timestamp", "")),
            str(row.get("ip", "")),
            str(row.get("message", ""))[:60],
            f"{row.get('anomaly_score', 0):.4f}",
            "Anomaly" if row.get("is_anomaly", False) else "Normal"
        ])

    table = Table(
        data,
        colWidths=[1*inch, 1.4*inch, 3.4*inch, 0.8*inch, 0.8*inch]
    )

    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.darkblue),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),0.5,colors.black),
        ("BACKGROUND",(0,1),(-1,-1),colors.beige),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("BOTTOMPADDING",(0,0),(-1,0),8),
    ]))

    elements.append(table)

    doc.build(elements)

    return send_file(
        report_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="AI_Log_Report.pdf"
    )


if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
