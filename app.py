from flask import Flask, render_template, request

from risk_engine import analyze_url

app = Flask(__name__)

urls_scanned = 0
threats_found = 0
medium_risk_found = 0


@app.route("/", methods=["GET", "POST"])
def home():

    global urls_scanned, threats_found, medium_risk_found

    analysis = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:
            analysis = analyze_url(url)

            urls_scanned += 1

            if analysis["verdict"] == "Unsafe":
                threats_found += 1
            elif analysis["verdict"] == "Medium Risk":
                medium_risk_found += 1

    safe_urls = urls_scanned - threats_found - medium_risk_found

    return render_template(
        "index.html",
        analysis=analysis,
        urls_scanned=urls_scanned,
        threats_found=threats_found,
        medium_risk_found=medium_risk_found,
        safe_urls=safe_urls,
    )


if __name__ == "__main__":
    app.run(debug=True)
