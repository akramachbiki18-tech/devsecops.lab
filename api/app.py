from flask import Flask, request, jsonify
import sqlite3
import subprocess
import hashlib
import os
import ast
import hmac
import secrets

app = Flask(__name__)

# ✅ Secret stocké dans une variable d’environnement
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))


# -----------------------------
# 1. LOGIN (SQL Injection FIX)
# -----------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ✅ Requête paramétrée (anti SQL Injection)
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    )

    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify({"status": "success", "user": username})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# -----------------------------
# 2. PING (Command Injection FIX)
# -----------------------------
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    # ✅ Validation simple de l’entrée
    if not host.replace(".", "").isalnum():
        return jsonify({"error": "Invalid host"}), 400

    # ✅ shell=False + liste d’arguments
    output = subprocess.check_output(
        ["ping", "-c", "1", host],
        stderr=subprocess.STDOUT
    )

    return jsonify({"output": output.decode()})


# -----------------------------
# 3. COMPUTE (eval FIX)
# -----------------------------
@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "1+1")

    try:
        # ✅ Évaluation sûre avec ast
        node = ast.parse(expression, mode="eval")

        for n in ast.walk(node):
            if not isinstance(n, (ast.Expression, ast.BinOp, ast.Num, ast.Add, ast.Sub, ast.Mult, ast.Div)):
                raise ValueError("Invalid expression")

        result = eval(compile(node, "<expr>", "eval"))
        return jsonify({"result": result})

    except Exception:
        return jsonify({"error": "Invalid expression"}), 400


# -----------------------------
# 4. HASH (MD5 FIX)
# -----------------------------
@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "")

    # ✅ SHA-256 (beaucoup plus sûr que MD5)
    hashed = hashlib.sha256(pwd.encode()).hexdigest()

    return jsonify({"sha256": hashed})


# -----------------------------
# 5. READ FILE (Path Traversal FIX)
# -----------------------------
@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "")

    base_dir = os.path.abspath("files")
    file_path = os.path.abspath(os.path.join(base_dir, filename))

    # ✅ Vérification du chemin
    if not file_path.startswith(base_dir):
        return jsonify({"error": "Access denied"}), 403

    try:
        with open(file_path, "r") as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


# -----------------------------
# 6. DEBUG (Info Leak FIX)
# -----------------------------
@app.route("/debug", methods=["GET"])
def debug():
    return jsonify({"debug": False})


# -----------------------------
# 7. HELLO
# -----------------------------
@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Welcome to the secured DevSecOps API"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
