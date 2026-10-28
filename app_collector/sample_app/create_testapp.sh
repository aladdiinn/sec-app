#!/bin/bash
# ==============================================================================
# BSmart SOC - Test Web Application Deployer for Tomcat 10 (testapp.war)
# ==============================================================================
# Deploys a realistic test web application to test:
# 1. Normal traffic (index, search, dashboard)
# 2. Brute Force Login attempts (HTTP 401 status)
# 3. Privilege Escalation & Admin Access Abuse (HTTP 403 on /admin/manage.jsp)
# 4. Web Attack Signatures (SQLi, XSS, Path Traversal, JNDI)
# ==============================================================================

set -e

echo "=== Deploying BSmart SOC Test Application (testapp) for Tomcat 10 ==="

# 1. Locate Tomcat webapps directory
WEBAPPS_DIR=""
CANDIDATES=(
    "/opt/tomcat/webapps"
    "/opt/tomcat10/webapps"
    "/opt/tomcat9/webapps"
    "/var/lib/tomcat10/webapps"
    "/var/lib/tomcat9/webapps"
    "/usr/local/tomcat/webapps"
    "/usr/share/tomcat/webapps"
)

for dir in "${CANDIDATES[@]}"; do
    if [ -d "$dir" ]; then
        WEBAPPS_DIR="$dir"
        break
    fi
done

if [ -z "$WEBAPPS_DIR" ]; then
    echo "[?] Could not auto-detect Tomcat webapps directory."
    read -p "Please enter your Tomcat webapps path (e.g. /opt/tomcat/webapps): " WEBAPPS_DIR
fi

if [ ! -d "$WEBAPPS_DIR" ]; then
    echo "[ERROR] Directory $WEBAPPS_DIR does not exist. Aborting."
    exit 1
fi

echo "[+] Target Tomcat webapps directory: $WEBAPPS_DIR"
APP_DIR="$WEBAPPS_DIR/testapp"
mkdir -p "$APP_DIR/WEB-INF" "$APP_DIR/admin"

# 2. Create WEB-INF/web.xml (Jakarta EE 10)
cat << 'EOF' > "$APP_DIR/WEB-INF/web.xml"
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="https://jakarta.ee/xml/ns/jakartaee https://jakarta.ee/xml/ns/jakartaee/web-app_6_0.xsd"
         version="6.0">
    <display-name>BSmart SOC Test App</display-name>
    <welcome-file-list>
        <welcome-file>index.jsp</welcome-file>
    </welcome-file-list>
</web-app>
EOF

# 3. Create index.jsp
cat << 'EOF' > "$APP_DIR/index.jsp"
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
    <title>BSmart SOC - Sample Tomcat App</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
        .card { background: #1e293b; border-radius: 10px; padding: 24px; max-width: 700px; margin: 0 auto; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        h1 { color: #38bdf8; font-size: 22px; margin-top: 0; }
        a.btn { display: inline-block; padding: 8px 16px; background: #0284c7; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600; margin-right: 8px; margin-top: 10px; }
        .attack-box { background: #0f172a; border-left: 4px solid #ef4444; padding: 12px; margin-top: 20px; font-size: 13px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ Enterprise Business App (BSmart SOC Test Bed)</h1>
        <p>This application is actively monitored by the <strong>SecurePulse Application SIEM Collector</strong>.</p>
        
        <p>Current Session User: <strong><%= session.getAttribute("user") != null ? session.getAttribute("user") : "Guest (Not Logged In)" %></strong></p>

        <a href="login.jsp" class="btn">🔑 Login Page</a>
        <a href="search.jsp?q=products" class="btn">🔍 Search Catalog</a>
        <a href="admin/manage.jsp" class="btn" style="background:#dc2626">⚠️ Restricted Admin Area</a>
        <a href="dashboard.jsp" class="btn" style="background:#475569">📊 Dashboard</a>

        <div class="attack-box">
            <strong>Security Test Targets:</strong><br>
            • Brute force login: <a href="login.jsp" style="color:#38bdf8">login.jsp</a> (returns 401 on failure)<br>
            • Admin access abuse: <a href="admin/manage.jsp" style="color:#ef4444">admin/manage.jsp</a> (returns 403 on non-admin)<br>
            • SQLi / XSS payload test: <a href="search.jsp?q=%27%20OR%201=1--" style="color:#f59e0b">search.jsp?q=' OR 1=1--</a>
        </div>
    </div>
</body>
</html>
EOF

# 4. Create login.jsp (Validates and triggers 401 for brute-force tracking)
cat << 'EOF' > "$APP_DIR/login.jsp"
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
    String error = null;
    String user = request.getParameter("username");
    String pass = request.getParameter("password");

    if ("POST".equalsIgnoreCase(request.getMethod())) {
        if (user != null && pass != null) {
            // Valid credentials: admin / admin123 OR john / user123
            if ("admin".equals(user) && "admin123".equals(pass)) {
                session.setAttribute("user", "admin");
                session.setAttribute("role", "admin");
                response.sendRedirect("admin/manage.jsp");
                return;
            } else if ("john".equals(user) && "user123".equals(pass)) {
                session.setAttribute("user", "john");
                session.setAttribute("role", "user");
                response.sendRedirect("dashboard.jsp");
                return;
            } else {
                // FAILED LOGIN -> Triggers HTTP 401 in Tomcat access log
                response.setStatus(401);
                error = "Invalid username or password!";
                System.err.println("[AUTH_FAILURE] Failed login for user: " + user + " from IP: " + request.getRemoteAddr());
            }
        }
    }
%>
<!DOCTYPE html>
<html>
<head>
    <title>Login - BSmart SOC Test App</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
        .card { background: #1e293b; border-radius: 10px; padding: 24px; max-width: 420px; margin: 40px auto; }
        input { width: 100%; box-sizing: border-box; padding: 10px; margin-bottom: 12px; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 6px; }
        button { width: 100%; padding: 10px; background: #0284c7; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
        .err { background: #ef4444; color: #fff; padding: 8px; border-radius: 4px; margin-bottom: 12px; font-size: 13px; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Sign In</h2>
        <% if (error != null) { %>
            <div class="err"><%= error %> (HTTP 401)</div>
        <% } %>
        <form method="POST">
            <label style="font-size:12px; color:#94a3b8">Username:</label>
            <input type="text" name="username" placeholder="e.g. admin or john" required>
            <label style="font-size:12px; color:#94a3b8">Password:</label>
            <input type="password" name="password" placeholder="e.g. admin123 or user123" required>
            <button type="submit">Log In</button>
        </form>
        <p style="font-size:11px; color:#94a3b8; margin-top:14px">
            Valid Users: <code>admin / admin123</code> | <code>john / user123</code><br>
            Wrong password returns HTTP 401 for brute-force detection.
        </p>
    </div>
</body>
</html>
EOF

# 5. Create dashboard.jsp
cat << 'EOF' > "$APP_DIR/dashboard.jsp"
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
    String currentUser = (String) session.getAttribute("user");
    if (currentUser == null) {
        response.sendRedirect("login.jsp");
        return;
    }
%>
<!DOCTYPE html>
<html>
<head>
    <title>User Dashboard</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
        .card { background: #1e293b; border-radius: 10px; padding: 24px; max-width: 600px; margin: 0 auto; }
        a { color: #38bdf8; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Welcome, <%= currentUser %>! (Role: <%= session.getAttribute("role") %>)</h2>
        <p>You have successfully logged in to the application.</p>
        <p><a href="admin/manage.jsp" style="color:#ef4444">Try accessing Admin Area (Will return 403 if not admin)</a></p>
        <p><a href="index.jsp">Back to Home</a></p>
    </div>
</body>
</html>
EOF

# 6. Create admin/manage.jsp (Restricted Admin Area - Triggers 403 on normal user)
cat << 'EOF' > "$APP_DIR/admin/manage.jsp"
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
    String currentUser = (String) session.getAttribute("user");
    String currentRole = (String) session.getAttribute("role");

    // Case 1: Unauthenticated user -> 401
    if (currentUser == null) {
        response.setStatus(401);
        response.sendRedirect("../login.jsp");
        return;
    }

    // Case 2: Normal user (e.g. john) -> 403 Forbidden! Triggers Admin Access Abuse rule in SIEM
    if (!"admin".equals(currentRole)) {
        response.setStatus(403);
        System.err.println("[PRIVILEGE_VIOLATION] User '" + currentUser + "' attempted restricted admin access to /admin/manage.jsp from IP: " + request.getRemoteAddr());
%>
<!DOCTYPE html>
<html>
<head>
    <title>403 Forbidden</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #ef4444; padding: 50px; text-align: center; }
        .box { background: #1e293b; padding: 30px; border-radius: 10px; max-width: 500px; margin: 0 auto; border: 1px solid #ef4444; }
    </style>
</head>
<body>
    <div class="box">
        <h2>⚠️ 403 Access Denied</h2>
        <p style="color:#f8fafc">User <strong><%= currentUser %></strong> does not have administrator privileges.</p>
        <p style="font-size:12px; color:#94a3b8">This violation has been logged and shipped to the BSmart SOC.</p>
        <a href="../index.jsp" style="color:#38bdf8">Return to Home</a>
    </div>
</body>
</html>
<%
        return;
    }
%>
<!DOCTYPE html>
<html>
<head>
    <title>Admin Console</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
        .card { background: #1e293b; border-radius: 10px; padding: 24px; max-width: 700px; margin: 0 auto; border-top: 4px solid #38bdf8; }
    </style>
</head>
<body>
    <div class="card">
        <h2>👑 Administrator Console</h2>
        <p>Welcome, Administrator <%= currentUser %>.</p>
        <p>Sensitive user databases, audit logs, and configurations can be reviewed here.</p>
        <a href="../index.jsp" style="color:#38bdf8">← Back to Home</a>
    </div>
</body>
</html>
EOF

# 7. Create search.jsp (For testing SQL Injection, XSS, Path Traversal, JNDI)
cat << 'EOF' > "$APP_DIR/search.jsp"
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
    String q = request.getParameter("q");
    if (q == null) q = "";
%>
<!DOCTYPE html>
<html>
<head>
    <title>Product Search</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
        .card { background: #1e293b; border-radius: 10px; padding: 24px; max-width: 600px; margin: 0 auto; }
        input { width: 70%; padding: 8px; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 4px; }
        button { padding: 8px 16px; background: #0284c7; color: #fff; border: none; border-radius: 4px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Product Catalog Search</h2>
        <form method="GET">
            <input type="text" name="q" value="<%= q.replace("\"", "&quot;") %>" placeholder="Search keywords...">
            <button type="submit">Search</button>
        </form>
        <div style="margin-top:20px; font-size:13px; color:#94a3b8">
            Query submitted: <code><%= q %></code>
        </div>
    </div>
</body>
</html>
EOF

# 8. Create war archive if jar command is available
if command -v jar >/dev/null 2>&1; then
    (cd "$APP_DIR" && jar -cvf "$WEBAPPS_DIR/testapp.war" * >/dev/null 2>&1)
    echo "[+] Created war archive at: $WEBAPPS_DIR/testapp.war"
elif command -v zip >/dev/null 2>&1; then
    (cd "$APP_DIR" && zip -r "$WEBAPPS_DIR/testapp.war" * >/dev/null 2>&1)
    echo "[+] Created war archive at: $WEBAPPS_DIR/testapp.war"
fi

# Set proper permissions for tomcat user
chown -R tomcat:tomcat "$APP_DIR" 2>/dev/null || chown -R www-data:www-data "$APP_DIR" 2>/dev/null || true

echo "======================================================================"
echo "[SUCCESS] Test Application successfully deployed to:"
echo "          $APP_DIR"
echo ""
echo "Test it in your browser:"
echo "http://<YOUR-TOMCAT-SERVER-IP>:8080/testapp/"
echo "======================================================================"
