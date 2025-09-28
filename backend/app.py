from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import psycopg2
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import json

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        database=os.getenv('DB_NAME', 'nids_db'),
        user=os.getenv('DB_USER', 'nids_user'),
        password=os.getenv('DB_PASSWORD', 'Projectfor@life'),
        port=os.getenv('DB_PORT', '5432')
    )

@app.route("/")
def home():
    return """
    <h1>NIDS Dashboard API</h1>
    <p>Available endpoints:</p>
    <ul>
        <li><a href="/api/alerts">/api/alerts</a> - Get security alerts</li>
        <li><a href="/api/stats">/api/stats</a> - Get statistics</li>
        <li><a href="/api/all-alerts">/api/all-alerts</a> - Get all alerts with status</li>
        <li><a href="/api/analytics">/api/analytics</a> - Get analytics data</li>
        <li><a href="/api/network-map">/api/network-map</a> - Get network map data</li>
    </ul>
    <p>Frontend: <a href="/dashboard">Open Dashboard</a></p>
    """

# Serve frontend files
@app.route('/frontend/<path:path>')
def serve_frontend(path):
    return send_from_directory('../frontend', path)

# Serve the main dashboard page
@app.route('/dashboard')
def dashboard():
    return send_from_directory('../frontend', 'index.html')

# Add a route for favicon to prevent 404 errors
@app.route('/favicon.ico')
def favicon():
    return send_from_directory('../frontend', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route("/api/alerts")
def get_alerts():
    # Get query parameters for filtering
    severity_filter = request.args.get('severity', 'all')
    limit = request.args.get('limit', 100)
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Base query
    query = """
        SELECT id, timestamp, src_ip, dst_ip, protocol, alert_type, severity, details 
        FROM alerts 
    """
    
    # Add filters if specified
    if severity_filter != 'all':
        query += f" WHERE severity = '{severity_filter}' "
    
    query += " ORDER BY timestamp DESC LIMIT %s;"
    
    cur.execute(query, (limit,))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    alerts = []
    for r in rows:
        alerts.append({
            "id": r[0],
            "timestamp": r[1].isoformat() if hasattr(r[1], 'isoformat') else r[1],
            "source_ip": r[2],
            "destination_ip": r[3],
            "protocol": r[4],
            "alert_type": r[5],
            "severity": r[6],
            "details": r[7],
        })
    return jsonify(alerts)

@app.route("/api/all-alerts")
def get_all_alerts():
    # Get query parameters for filtering
    status_filter = request.args.get('status', 'all')
    severity_filter = request.args.get('severity', 'all')
    limit = request.args.get('limit', 100)
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Base query
    query = """
        SELECT id, timestamp, src_ip, dst_ip, protocol, alert_type, severity, details, status
        FROM alerts 
        WHERE 1=1
    """
    
    params = []
    
    # Add status filter if specified
    if status_filter != 'all':
        query += " AND status = %s"
        params.append(status_filter)
    
    # Add severity filter if specified
    if severity_filter != 'all':
        query += " AND severity = %s"
        params.append(severity_filter)
    
    query += " ORDER BY timestamp DESC LIMIT %s;"
    params.append(limit)
    
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()

    alerts = []
    for r in rows:
        alerts.append({
            "id": r[0],
            "timestamp": r[1].isoformat() if hasattr(r[1], 'isoformat') else r[1],
            "source_ip": r[2],
            "destination_ip": r[3],
            "protocol": r[4],
            "alert_type": r[5],
            "severity": r[6],
            "details": r[7],
            "status": r[8] if len(r) > 8 else "new"
        })
    return jsonify(alerts)

@app.route("/api/stats")
def get_stats():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Total alerts in last 24 hours
    cur.execute("""
        SELECT COUNT(*) FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '24 hours';
    """)
    total_alerts = cur.fetchone()[0]
    
    # Critical alerts
    cur.execute("""
        SELECT COUNT(*) FROM alerts 
        WHERE severity = 'Critical' AND timestamp > NOW() - INTERVAL '24 hours';
    """)
    critical_alerts = cur.fetchone()[0]
    
    # Warning alerts
    cur.execute("""
        SELECT COUNT(*) FROM alerts 
        WHERE severity = 'Warning' AND timestamp > NOW() - INTERVAL '24 hours';
    """)
    warning_alerts = cur.fetchone()[0]
    
    # Protected hosts (count distinct destination IPs)
    cur.execute("""
        SELECT COUNT(DISTINCT dst_ip) FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '24 hours';
    """)
    protected_hosts = cur.fetchone()[0]
    
    # Alert type distribution
    cur.execute("""
        SELECT alert_type, COUNT(*) 
        FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '24 hours'
        GROUP BY alert_type;
    """)
    alert_types = {row[0]: row[1] for row in cur.fetchall()}
    
    # Severity distribution
    cur.execute("""
        SELECT severity, COUNT(*) 
        FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '24 hours'
        GROUP BY severity;
    """)
    severity_dist = {row[0]: row[1] for row in cur.fetchall()}
    
    # Alerts over time (last 6 hours)
    cur.execute("""
        SELECT 
            DATE_TRUNC('hour', timestamp) as hour,
            COUNT(*)
        FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '6 hours'
        GROUP BY hour
        ORDER BY hour;
    """)
    time_data = cur.fetchall()
    
    cur.close()
    conn.close()
    
    # Format time data for chart
    time_labels = []
    time_values = []
    for row in time_data:
        time_labels.append(row[0].strftime('%H:%M'))
        time_values.append(row[1])
    
    return jsonify({
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "warning_alerts": warning_alerts,
        "protected_hosts": protected_hosts,
        "alert_types": alert_types,
        "severity_dist": severity_dist,
        "time_labels": time_labels,
        "time_values": time_values
    })

@app.route("/api/alerts/by-type")
def get_alerts_by_type():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Alert type distribution for last 24 hours
    cur.execute("""
        SELECT alert_type, COUNT(*) 
        FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '24 hours'
        GROUP BY alert_type;
    """)
    
    result = {row[0]: row[1] for row in cur.fetchall()}
    
    cur.close()
    conn.close()
    
    return jsonify(result)

@app.route("/api/alerts/by-severity")
def get_alerts_by_severity():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Severity distribution for last 24 hours
    cur.execute("""
        SELECT severity, COUNT(*) 
        FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '24 hours'
        GROUP BY severity;
    """)
    
    result = {row[0]: row[1] for row in cur.fetchall()}
    
    cur.close()
    conn.close()
    
    return jsonify(result)

@app.route("/api/alerts/by-time")
def get_alerts_by_time():
    range_filter = request.args.get('range', 'day')
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    if range_filter == 'day':
        # Last 24 hours in 1-hour intervals
        cur.execute("""
            SELECT 
                DATE_TRUNC('hour', timestamp) as hour,
                COUNT(*)
            FROM alerts 
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY hour
            ORDER BY hour;
        """)
    elif range_filter == 'week':
        # Last 7 days in 1-day intervals
        cur.execute("""
            SELECT 
                DATE_TRUNC('day', timestamp) as day,
                COUNT(*)
            FROM alerts 
            WHERE timestamp > NOW() - INTERVAL '7 days'
            GROUP BY day
            ORDER BY day;
        """)
    elif range_filter == 'month':
        # Last 30 days in 1-day intervals
        cur.execute("""
            SELECT 
                DATE_TRUNC('day', timestamp) as day,
                COUNT(*)
            FROM alerts 
            WHERE timestamp > NOW() - INTERVAL '30 days'
            GROUP BY day
            ORDER BY day;
        """)
    
    time_data = cur.fetchall()
    
    cur.close()
    conn.close()
    
    # Format time data for chart
    labels = []
    values = []
    
    for row in time_data:
        if range_filter == 'day':
            labels.append(row[0].strftime('%H:%M'))
        else:
            labels.append(row[0].strftime('%Y-%m-%d'))
        values.append(row[1])
    
    return jsonify({
        "labels": labels,
        "values": values
    })

@app.route("/api/analytics")
def get_analytics():
    period = request.args.get('period', 'week')
    data_type = request.args.get('type', 'alerts')
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    if period == 'day':
        interval = '1 hour'
        time_trunc = 'hour'
        time_interval = '24 hours'
    elif period == 'week':
        interval = '1 day'
        time_trunc = 'day'
        time_interval = '7 days'
    elif period == 'month':
        interval = '1 day'
        time_trunc = 'day'
        time_interval = '30 days'
    elif period == 'quarter':
        interval = '1 week'
        time_trunc = 'week'
        time_interval = '90 days'
    elif period == 'year':
        interval = '1 month'
        time_trunc = 'month'
        time_interval = '365 days'
    
    if data_type == 'alerts':
        # Alert volume over time
        cur.execute(f"""
            SELECT 
                DATE_TRUNC('{time_trunc}', timestamp) as time_period,
                COUNT(*)
            FROM alerts 
            WHERE timestamp > NOW() - INTERVAL '{time_interval}'
            GROUP BY time_period
            ORDER BY time_period;
        """)
        
        result = cur.fetchall()
        labels = []
        values = []
        
        for row in result:
            if time_trunc == 'hour':
                labels.append(row[0].strftime('%H:%M'))
            elif time_trunc == 'day':
                labels.append(row[0].strftime('%Y-%m-%d'))
            elif time_trunc == 'week':
                labels.append(row[0].strftime('%Y-%U'))
            elif time_trunc == 'month':
                labels.append(row[0].strftime('%Y-%m'))
            values.append(row[1])
        
        return jsonify({
            "title": f"Alert Volume - Last {time_interval}",
            "datasetLabel": "Alerts",
            "labels": labels,
            "values": values
        })
    
    cur.close()
    conn.close()
    
    return jsonify({"error": "Invalid data type"})

@app.route("/api/analytics/attack-types")
def get_attack_types_analytics():
    period = request.args.get('period', 'week')
    
    if period == 'day':
        time_interval = '24 hours'
    elif period == 'week':
        time_interval = '7 days'
    elif period == 'month':
        time_interval = '30 days'
    elif period == 'quarter':
        time_interval = '90 days'
    elif period == 'year':
        time_interval = '365 days'
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute(f"""
        SELECT alert_type, COUNT(*) 
        FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '{time_interval}'
        GROUP BY alert_type
        ORDER BY COUNT(*) DESC;
    """)
    
    result = {row[0]: row[1] for row in cur.fetchall()}
    
    cur.close()
    conn.close()
    
    return jsonify(result)

@app.route("/api/analytics/top-sources")
def get_top_sources():
    period = request.args.get('period', 'week')
    
    if period == 'day':
        time_interval = '24 hours'
    elif period == 'week':
        time_interval = '7 days'
    elif period == 'month':
        time_interval = '30 days'
    elif period == 'quarter':
        time_interval = '90 days'
    elif period == 'year':
        time_interval = '365 days'
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute(f"""
        SELECT src_ip, COUNT(*) 
        FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '{time_interval}'
        GROUP BY src_ip
        ORDER BY COUNT(*) DESC
        LIMIT 10;
    """)
    
    result = {row[0]: row[1] for row in cur.fetchall()}
    
    cur.close()
    conn.close()
    
    return jsonify(result)

@app.route("/api/network-map")
def get_network_map():
    # This is a simplified implementation - in a real system, you would
    # have a proper network inventory and topology database
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Get unique IP addresses from alerts
    cur.execute("""
        SELECT DISTINCT dst_ip FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '24 hours'
        LIMIT 20;
    """)
    
    internal_ips = [row[0] for row in cur.fetchall()]
    
    # Get top source IPs
    cur.execute("""
        SELECT src_ip, COUNT(*) 
        FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '24 hours'
        GROUP BY src_ip
        ORDER BY COUNT(*) DESC
        LIMIT 10;
    """)
    
    external_ips = [row[0] for row in cur.fetchall()]
    
    cur.close()
    conn.close()
    
    # Generate nodes for network map
    nodes = []
    node_id = 1
    
    # Add internal nodes
    for ip in internal_ips:
        nodes.append({
            "id": node_id,
            "label": f"Host {node_id}",
            "ip": ip,
            "type": "internal",
            "status": "normal",
            "x": 100 + (node_id % 5) * 150,
            "y": 100 + (node_id // 5) * 150,
            "size": 40
        })
        node_id += 1
    
    # Add external nodes
    for ip in external_ips:
        nodes.append({
            "id": node_id,
            "label": f"Ext {node_id}",
            "ip": ip,
            "type": "external",
            "status": "suspicious",
            "x": 800 + (node_id % 3) * 150,
            "y": 100 + (node_id % 4) * 100,
            "size": 35
        })
        node_id += 1
    
    # Add a server node
    nodes.append({
        "id": node_id,
        "label": "Server",
        "ip": "192.168.1.100",
        "type": "server",
        "status": "critical",
        "x": 400,
        "y": 300,
        "size": 50,
        "alerts": 15
    })
    node_id += 1
    
    # Generate connections between nodes
    connections = []
    for i in range(min(10, len(nodes))):
        for j in range(i + 1, min(i + 3, len(nodes))):
            if nodes[i]["type"] != nodes[j]["type"]:  # Connect different types
                connections.append({
                    "from": nodes[i]["id"],
                    "to": nodes[j]["id"],
                    "status": "critical" if nodes[i]["status"] == "critical" or nodes[j]["status"] == "critical" else "suspicious"
                })
    
    return jsonify({
        "nodes": nodes,
        "connections": connections
    })

@app.route("/api/network-traffic")
def get_network_traffic():
    # Simulate network traffic data
    labels = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"]
    inbound = [120, 85, 150, 220, 180, 90]
    outbound = [80, 60, 110, 180, 160, 70]
    
    return jsonify({
        "labels": labels,
        "inbound": inbound,
        "outbound": outbound
    })

@app.route("/api/network-protocols")
def get_network_protocols():
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT protocol, COUNT(*) 
        FROM alerts 
        WHERE timestamp > NOW() - INTERVAL '24 hours'
        GROUP BY protocol;
    """)
    
    result = {row[0]: row[1] for row in cur.fetchall()}
    
    cur.close()
    conn.close()
    
    return jsonify(result)

@app.route("/api/alert/<int:alert_id>", methods=['PUT'])
def update_alert(alert_id):
    data = request.get_json()
    status = data.get('status')
    
    if status not in ['new', 'in-progress', 'resolved']:
        return jsonify({"error": "Invalid status"}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            UPDATE alerts 
            SET status = %s 
            WHERE id = %s
            RETURNING id;
        """, (status, alert_id))
        
        if cur.rowcount == 0:
            return jsonify({"error": "Alert not found"}), 404
        
        conn.commit()
        return jsonify({"message": "Alert updated successfully"})
    
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    
    finally:
        cur.close()
        conn.close()

@app.route("/api/alerts/bulk-update", methods=['POST'])
def bulk_update_alerts():
    data = request.get_json()
    alert_ids = data.get('alert_ids', [])
    status = data.get('status')
    
    if status not in ['new', 'in-progress', 'resolved']:
        return jsonify({"error": "Invalid status"}), 400
    
    if not alert_ids:
        return jsonify({"error": "No alerts selected"}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Convert alert_ids to a tuple for SQL IN clause
        alert_ids_tuple = tuple(alert_ids)
        
        cur.execute(f"""
            UPDATE alerts 
            SET status = %s 
            WHERE id IN {alert_ids_tuple}
            RETURNING id;
        """, (status,))
        
        conn.commit()
        return jsonify({"message": f"Updated {cur.rowcount} alerts"})
    
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    app.run(debug=True, port=5000, host='0.0.0.0')
