"""Deliberately vulnerable synthetic app (test fixture, never deployed)."""
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, render_template_string, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE = "/srv/files"


def db():
    return sqlite3.connect(":memory:")


# ---- TRUE POSITIVES -------------------------------------------------------

@app.route("/user")
def user():
    name = request.args.get("name")
    cur = db().cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")  # VULN:sql-injection
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c1 " + host, shell=True)  # VULN:command-injection


@app.route("/download")
def download():
    fname = request.args.get("f")
    return open(os.path.join(BASE, fname)).read()  # VULN:path-traversal


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text  # VULN:ssrf


@app.route("/hello")
def hello():
    who = request.args.get("who", "")
    return render_template_string("<h1>Hello " + who + "</h1>")  # VULN:xss


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))  # VULN:insecure-deserialization


@app.route("/admin/delete")
def admin_delete():
    # VULN:auth-bypass -- trusts a client-controlled header as authentication
    if request.headers.get("X-Is-Admin") == "1":
        return "deleted"
    return "forbidden", 403


# ---- FALSE-POSITIVE TRAPS (safe code that naive rules flag) ---------------

@app.route("/user_safe")
def user_safe():
    name = request.args.get("name")
    cur = db().cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))  # SAFE
    return str(cur.fetchall())


@app.route("/ping_safe")
def ping_safe():
    host = request.args.get("host")
    return subprocess.check_output(["ping", "-c1", host])  # SAFE: argv list, no shell


@app.route("/download_safe")
def download_safe():
    fname = secure_filename(request.args.get("f", ""))
    return send_file(os.path.join(BASE, fname))  # SAFE


@app.route("/report")
def report():
    limit = int(request.args.get("limit", "10"))
    cur = db().cursor()
    cur.execute(f"SELECT * FROM logs LIMIT {limit}")  # SAFE: int() sanitised
    return str(cur.fetchall())


def maintenance():
    os.system("rm -rf /tmp/cache")  # SAFE: constant command, no user input
