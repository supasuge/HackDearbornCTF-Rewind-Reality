#!/usr/bin/python3
import os
from flask import Flask, request, jsonify, redirect, url_for
from gevent import monkey; monkey.patch_all()
from gevent.pywsgi import WSGIServer
import gevent


app = Flask(__name__)
FLAG = open("flag.txt").read().strip()
SECRET_TOKEN = os.urandom(16).hex() # len() == 32

def strcmp(s1, s2):
    if len(s1) != len(s2):
        return False
    for c1, c2 in zip(s1, s2):
        if c1 != c2:
            return False
        gevent.sleep(0.0099)  
    return True


@app.route("/")
def index():
    return redirect(url_for('protected'))

@app.route("/adminpanel")
def protected():
    token = request.headers.get('TX-TOKEN')
    content_type = request.headers.get('Content-Type')
    
    if content_type != 'application/json':
        return jsonify({"error": "Invalid content type"}), 400

    if not token:
        return jsonify({"error": "Missing TX-TOKEN header"}), 400

    if strcmp(token, SECRET_TOKEN):
        return jsonify({"flag": FLAG})
    else:
        return jsonify({"error": "Invalid token"}), 403


if __name__ == "__main__":
    # WSGI server for better concurrency handling
    http_server = WSGIServer(('0.0.0.0', 8000), app)
    http_server.serve_forever()
