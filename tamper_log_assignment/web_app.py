# web_app.py
from flask import Flask, render_template_string, request, jsonify
from tamper_log import add_log_entry, verify_log_chain
from log_store import create_db
import sqlite3


DB_PATH = "audit_log.db"

app = Flask(__name__)

# Create DB if not exists
create_db(DB_PATH)


@app.route("/")
def index():
    # Read all entries
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, timestamp, event_type, description, this_hash FROM log_entries ORDER BY id"
    )
    rows = cur.fetchall()
    conn.close()

    # Verify integrity
    ok, bad_ids = verify_log_chain(DB_PATH)

    # HTML template (minimal; no extra files)
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Tamper‑Evident Audit Log (Browser View)</title>
        <style>
            body { font-family: sans-serif; margin: 20px; background: #f4f4f8; }
            h1 { color: #1c1e22; }
            table { border-collapse: collapse; width: 100%; margin: 10px 0; }
            th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
            th { background: #0077b6; color: white; }
            tr:nth-child(even) { background: #f9f9f9; }
            .tampered { background: #ffdddd; }
            .ok { background: #eeffee; }
            .status { padding: 10px; border-radius: 4px; margin: 10px 0; }
            .ok-status { background: #eeffee; color: #005f20; }
            .bad-status { background: #ffe6e6; color: #8b0000; }
            .form { margin: 20px 0; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
            label { display: block; margin: 5px 0; }
            input, select { margin: 3px 0; padding: 5px; width: 300px; }
            button { margin: 5px; padding: 8px 12px; background: #0077b6; color: white; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #005f90; }
        </style>
    </head>
    <body>
        <h1>🛡️ Tamper‑Evident Audit Logger – Browser UI</h1>

        <div class="status {% if ok %}ok-status{% else %}bad-status{% endif %}">
            {% if ok %}
                ✅ Log chain integrity verified; no tampering detected.
            {% else %}
                ❌ Tampering detected around IDs: {{ bad_ids }}
            {% endif %}
        </div>

        <form class="form" method="POST" action="/add">
            <label>Event Type:</label>
            <select name="event_type">
                <option value="LOGIN_ATTEMPT">LOGIN_ATTEMPT</option>
                <option value="TRANSACTION">TRANSACTION</option>
                <option value="USER_ACTIVITY">USER_ACTIVITY</option>
            </select>

            <label>Description:</label>
            <input type="text" name="description" placeholder="Description of the event" required />

            <button type="submit">Add Log Entry</button>
        </form>

        <form class="form" method="POST" action="/verify">
            <button type="submit">Re‑Verify Integrity</button>
        </form>

        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>Event Type</th>
                    <th>Description</th>
                    <th>Hash (short)</th>
                </tr>
            </thead>
            <tbody>
                {% for row in rows %}
                    <tr class="{% if row|first in bad_ids %}tampered{% else %}ok{% endif %}">
                        <td>{{ row[0] }}</td>
                        <td>{{ row[1] }}</td>
                        <td>{{ row[2] }}</td>
                        <td>{{ row[3] }}</td>
                        <td>{{ row[4][:12] }}</td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    </body>
    </html>
    """

    return render_template_string(
        html,
        rows=rows,
        ok=ok,
        bad_ids=sorted(bad_ids) if bad_ids else None,
    )


@app.route("/add", methods=["POST"])
def add_log():
    event_type = request.form.get("event_type", "UNKNOWN")
    desc = request.form.get("description", "").strip()

    if not desc:
        return "❌ Description is required.", 400

    try:
        add_log_entry(DB_PATH, event_type, desc)
        return """✅ Log entry added. <a href="/">Back to log view</a>""", 200
    except Exception as e:
        return f"❌ Error: {str(e)}", 500


@app.route("/verify", methods=["POST"])
def verify():
    ok, bad_ids = verify_log_chain(DB_PATH)
    if ok:
        return "✅ Log chain integrity verified; no tampering detected.", 200
    else:
        return f"❌ Tampering detected around IDs: {sorted(bad_ids)}.", 200


if __name__ == "__main__":
    print("🚀 Starting Flask web UI...")
    print("Open your browser and go to: http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)
