import os
import sys
from flask import Flask, render_template, request

# Ensure /src root is in path for scanner import
src_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if src_root not in sys.path:
    sys.path.insert(0, src_root)

from scanner import scan_url

template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
app = Flask(__name__, template_folder=template_dir)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form["url"]
        # save_csv=True → keeps dataset for AI
        result = scan_url(url, save_csv=True)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)

    