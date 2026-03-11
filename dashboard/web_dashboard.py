"""CTTO Web Dashboard.

Flask dashboard that reads CTTO attack telemetry from SQLite and renders:
- total attack attempts
- top usernames
- top passwords
- attack methods
- Chart.js visualizations

Run:
    python3 dashboard/web_dashboard.py
"""

from collections import Counter
import json
import os
import sys

from flask import Flask, abort, jsonify, render_template_string, request, Response

# Ensure project root imports work when run directly.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from core.database import Database
from modules.fingerprinting.geoip_lookup import lookup as geoip_lookup


DB_PATH = os.path.join(PROJECT_ROOT, "data", "ctto.db")
HOST = "0.0.0.0"
PORT = 5000

app = Flask(__name__)


def _load_attacks():
    db = Database(db_path=DB_PATH)
    db.connect()
    try:
        return db.get_all_attacks()
    finally:
        db.close()


def _top_counts(values, limit=10):
    cleaned = [v for v in values if v is not None and str(v).strip()]
    counter = Counter(cleaned)
    return counter.most_common(limit)


def _mask_password(value):
    if value is None:
        return ""
    p = str(value)
    return "*" * min(len(p), 8)


def _require_admin_key():
    expected = os.environ.get("CTTO_DASHBOARD_KEY")
    if not expected:
        return  # no key configured — allow open access
    provided = request.headers.get("X-CTTO-Admin-Key")
    if provided != expected:
        abort(403)


def _build_stats():
    attacks = _load_attacks()
    usernames = _top_counts([a.get("username", "") for a in attacks], limit=10)
    passwords = _top_counts([_mask_password(a.get("password", "")) for a in attacks], limit=10)
    methods = _top_counts([a.get("method", "") for a in attacks], limit=10)

    scores = [a.get("threat_score", 0) for a in attacks]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0
    high_count = sum(1 for s in scores if s >= 60)
    critical_count = sum(1 for s in scores if s >= 80)
    score_low = sum(1 for s in scores if s < 30)
    score_med = sum(1 for s in scores if 30 <= s < 60)
    score_high = sum(1 for s in scores if 60 <= s < 80)
    score_crit = sum(1 for s in scores if s >= 80)

    locations = []
    for a in attacks:
        ip = a.get("ip_address", "")
        geo = geoip_lookup(ip)
        loc = f"{geo['city']}, {geo['country']}"
        locations.append(loc)
    top_locations = _top_counts(locations, limit=10)

    return {
        "total_attempts": len(attacks),
        "top_usernames": usernames,
        "top_passwords": passwords,
        "attack_methods": methods,
        "avg_threat_score": avg_score,
        "high_threat_count": high_count,
        "critical_threat_count": critical_count,
        "score_distribution": [score_low, score_med, score_high, score_crit],
        "top_locations": top_locations,
    }


def _build_attack_log():
    attacks = _load_attacks()
    log = []
    for a in reversed(attacks):
        ip = a.get("ip_address", "")
        geo = geoip_lookup(ip)
        log.append({
            "id": a.get("id"),
            "timestamp": a.get("timestamp", ""),
            "ip_address": ip,
            "location": f"{geo['city']}, {geo['country']}",
            "username": a.get("username", ""),
            "password": _mask_password(a.get("password", "")),
            "method": a.get("method", ""),
            "threat_score": a.get("threat_score", 0),
            "user_agent": (a.get("user_agent") or "")[:60],
        })
    return log


DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CTTO Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg: #0b1220;
      --panel: #101a2b;
      --text: #e5edf7;
      --muted: #94a3b8;
      --accent: #14b8a6;
      --accent2: #f59e0b;
      --accent3: #ef4444;
      --border: #1e293b;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background: radial-gradient(1200px 800px at 20% 0%, #172554 0%, var(--bg) 60%);
      color: var(--text);
      min-height: 100vh;
      padding: 20px;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      display: grid;
      gap: 16px;
    }

    .header {
      background: rgba(16, 26, 43, 0.95);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px 20px;
    }

    .title { margin: 0; font-size: 1.4rem; font-weight: 700; }
    .subtitle { margin: 6px 0 0; color: var(--muted); font-size: 0.95rem; }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }

    .kpi {
      background: rgba(16, 26, 43, 0.95);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
    }

    .kpi h3 {
      margin: 0;
      font-size: 0.85rem;
      color: var(--muted);
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    .kpi .value {
      margin-top: 8px;
      font-size: 2rem;
      font-weight: 800;
      color: var(--accent);
    }

    .charts {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }

    .panel {
      background: rgba(16, 26, 43, 0.95);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px;
    }

    .panel h2 {
      margin: 0 0 10px;
      font-size: 1rem;
      color: #cbd5e1;
    }

    .table-wrap {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.92rem;
    }

    th, td {
      text-align: left;
      border-bottom: 1px solid var(--border);
      padding: 8px 6px;
      color: #dbe7f5;
    }

    th { color: #93c5fd; }

    @media (max-width: 700px) {
      body { padding: 12px; }
      .kpi .value { font-size: 1.6rem; }
    }
  </style>
</head>
<body>
  <div class="container">
    <section class="header">
      <h1 class="title">CTTO Attack Intelligence Dashboard</h1>
      <p class="subtitle">Live analytics from the SQLite telemetry store</p>
    </section>

    <section class="kpi-grid">
      <div class="kpi">
        <h3>Total Attacks</h3>
        <div class="value" id="kpi-total">{{ stats.total_attempts }}</div>
      </div>
      <div class="kpi">
        <h3>Avg Threat Score</h3>
        <div class="value" id="kpi-avg" style="color:#f59e0b">{{ stats.avg_threat_score }}</div>
      </div>
      <div class="kpi">
        <h3>High Threat (60+)</h3>
        <div class="value" id="kpi-high" style="color:#ef4444">{{ stats.high_threat_count }}</div>
      </div>
      <div class="kpi">
        <h3>Critical (80+)</h3>
        <div class="value" id="kpi-crit" style="color:#dc2626">{{ stats.critical_threat_count }}</div>
      </div>
    </section>

    <section class="charts">
      <div class="panel">
        <h2>Top Usernames</h2>
        <canvas id="usernameChart"></canvas>
      </div>

      <div class="panel">
        <h2>Top Passwords</h2>
        <canvas id="passwordChart"></canvas>
      </div>

      <div class="panel">
        <h2>Attack Methods</h2>
        <canvas id="methodChart"></canvas>
      </div>

      <div class="panel">
        <h2>Threat Score Distribution</h2>
        <canvas id="threatChart"></canvas>
      </div>
    </section>

    <section class="charts">
      <div class="panel">
        <h2>Top Attacker Locations</h2>
        <div class="table-wrap">
          <table id="locations-table">
            <thead>
              <tr><th>Location</th><th>Attacks</th></tr>
            </thead>
            <tbody id="locations-body">
            {% for loc, count in stats.top_locations %}
              <tr>
                <td style="color:#a78bfa">{{ loc }}</td>
                <td>{{ count }}</td>
              </tr>
            {% else %}
              <tr><td colspan="2" style="color:var(--muted)">No data</td></tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel">
        <h2>Export Reports</h2>
        <p style="color:var(--muted);font-size:0.9rem;margin:0 0 14px">Download all captured attack data</p>
        <div style="display:flex;gap:12px;flex-wrap:wrap">
          <a href="/export/csv" style="display:inline-block;padding:10px 22px;background:#14b8a6;color:#0b1220;border-radius:8px;font-weight:700;text-decoration:none;font-size:0.95rem">Download CSV</a>
          <a href="/export/json" style="display:inline-block;padding:10px 22px;background:#3b82f6;color:#fff;border-radius:8px;font-weight:700;text-decoration:none;font-size:0.95rem">Download JSON</a>
        </div>
      </div>
    </section>

    <section class="panel">
      <h2>Top Username Table</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
          {% for username, count in stats.top_usernames %}
            <tr>
              <td>{{ username }}</td>
              <td>{{ count }}</td>
            </tr>
          {% else %}
            <tr>
              <td colspan="2">No attempts recorded</td>
            </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel" id="attack-log-section">
      <h2>All Attack Attempts <span id="live-badge" style="background:#14b8a6;color:#0b1220;padding:2px 10px;border-radius:8px;font-size:0.75rem;margin-left:10px;vertical-align:middle;">LIVE</span></h2>
      <div class="table-wrap">
        <table id="attack-log-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Time</th>
              <th>IP Address</th>
              <th>Location</th>
              <th>Username</th>
              <th>Password</th>
              <th>Method</th>
              <th>Threat Score</th>
              <th>User-Agent</th>
            </tr>
          </thead>
          <tbody id="attack-log-body">
            <tr><td colspan="9" style="color:var(--muted);">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    const stats = {{ stats_json|safe }};

    function makeBarChart(id, labels, values, color) {
      new Chart(document.getElementById(id), {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Attempts',
            data: values,
            backgroundColor: color,
            borderWidth: 0,
            borderRadius: 6
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: { ticks: { color: '#cbd5e1' }, grid: { color: '#1e293b' } },
            y: { beginAtZero: true, ticks: { color: '#cbd5e1', precision: 0 }, grid: { color: '#1e293b' } }
          }
        }
      });
    }

    const usernames = stats.top_usernames;
    const passwords = stats.top_passwords;
    const methods = stats.attack_methods;

    makeBarChart('usernameChart', usernames.map(i => i[0]), usernames.map(i => i[1]), 'rgba(20, 184, 166, 0.8)');
    makeBarChart('passwordChart', passwords.map(i => i[0]), passwords.map(i => i[1]), 'rgba(245, 158, 11, 0.8)');
    makeBarChart('methodChart', methods.map(i => i[0]), methods.map(i => i[1]), 'rgba(239, 68, 68, 0.8)');

    /* Threat Score Doughnut */
    const scoreDist = stats.score_distribution; /* [low, med, high, crit] */
    new Chart(document.getElementById('threatChart'), {
      type: 'doughnut',
      data: {
        labels: ['Low (0-29)', 'Medium (30-59)', 'High (60-79)', 'Critical (80+)'],
        datasets: [{
          data: scoreDist,
          backgroundColor: ['#14b8a6', '#f59e0b', '#ef4444', '#dc2626'],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#cbd5e1', padding: 12 } }
        }
      }
    });

    /* ---- Live attack log polling ---- */
    function scoreColor(s) {
      if (s >= 60) return '#ef4444';
      if (s >= 30) return '#f59e0b';
      return '#14b8a6';
    }

    function refreshLog() {
      fetch('/api/attacks')
        .then(r => r.json())
        .then(data => {
          const tbody = document.getElementById('attack-log-body');
          if (!data.length) { tbody.innerHTML = '<tr><td colspan="9" style="color:var(--muted)">No attacks yet</td></tr>'; return; }
          tbody.innerHTML = data.map(a => `<tr>
            <td>${a.id}</td>
            <td style="white-space:nowrap">${(a.timestamp || '').replace('T',' ').slice(0,19)}</td>
            <td>${a.ip_address}</td>
            <td style="color:#a78bfa;font-size:0.85rem;white-space:nowrap">${a.location || 'Unknown'}</td>
            <td><b>${a.username || '—'}</b></td>
            <td>${a.password || '—'}</td>
            <td>${a.method}</td>
            <td style="color:${scoreColor(a.threat_score)};font-weight:700;text-align:center">${a.threat_score}</td>
            <td style="color:var(--muted);font-size:0.82rem">${a.user_agent}</td>
          </tr>`).join('');
          /* update KPIs */
          const total = data.length;
          const scores = data.map(a => a.threat_score);
          const avg = total ? (scores.reduce((a,b)=>a+b,0)/total).toFixed(1) : 0;
          const high = scores.filter(s => s >= 60).length;
          const crit = scores.filter(s => s >= 80).length;
          const el = id => document.getElementById(id);
          if (el('kpi-total')) el('kpi-total').textContent = total;
          if (el('kpi-avg'))   el('kpi-avg').textContent = avg;
          if (el('kpi-high'))  el('kpi-high').textContent = high;
          if (el('kpi-crit'))  el('kpi-crit').textContent = crit;

          /* update locations table */
          const locCounts = {};
          data.forEach(a => { const l = a.location || 'Unknown'; locCounts[l] = (locCounts[l]||0)+1; });
          const locArr = Object.entries(locCounts).sort((a,b) => b[1]-a[1]).slice(0,10);
          const locBody = document.getElementById('locations-body');
          if (locBody) {
            locBody.innerHTML = locArr.map(([loc,c]) => `<tr><td style="color:#a78bfa">${loc}</td><td>${c}</td></tr>`).join('');
          }
        })
        .catch(() => {});
    }

    refreshLog();
    setInterval(refreshLog, 5000);
  </script>
</body>
</html>
"""


@app.get("/")
def dashboard_home():
    _require_admin_key()
    stats = _build_stats()
    return render_template_string(
        DASHBOARD_TEMPLATE,
        stats=stats,
        stats_json=json.dumps(stats),
    )


@app.get("/api/stats")
def api_stats():
    _require_admin_key()
    return jsonify(_build_stats())


@app.get("/api/attacks")
def api_attacks():
    _require_admin_key()
    return jsonify(_build_attack_log())


@app.get("/export/csv")
def export_csv():
    _require_admin_key()
    import csv
    import io
    attacks = _build_attack_log()
    si = io.StringIO()
    writer = csv.DictWriter(si, fieldnames=[
        "id", "timestamp", "ip_address", "location", "username",
        "password", "method", "threat_score", "user_agent",
    ])
    writer.writeheader()
    writer.writerows(attacks)
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=ctto_attacks.csv"},
    )


@app.get("/export/json")
def export_json():
    _require_admin_key()
    attacks = _build_attack_log()
    output = json.dumps(attacks, indent=2)
    return Response(
        output,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=ctto_attacks.json"},
    )


def serve_dashboard(host=HOST, port=PORT):
    print(f"[*] CTTO dashboard running on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    serve_dashboard(HOST, PORT)
