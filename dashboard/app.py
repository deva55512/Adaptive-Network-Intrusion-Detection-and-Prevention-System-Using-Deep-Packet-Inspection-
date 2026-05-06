from flask import Flask, render_template
import os

app = Flask(__name__)

LOG_FILE = "../logs/attacks.log"


def read_logs():
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r") as f:
        logs = f.readlines()

    return logs[::-1]  # newest first


@app.route("/")
def index():

    logs = read_logs()
    total_attacks = len(logs)

    return render_template(
        "dashboard.html",
        logs=logs,
        total_attacks=total_attacks
    )


if __name__ == "__main__":
    app.run(debug=True)
