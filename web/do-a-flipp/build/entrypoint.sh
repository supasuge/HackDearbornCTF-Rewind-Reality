#!/bin/bash
FLASK_APP=app.py
FLASK_ENV=production

flask run --host=0.0.0.0 --port=6789 --debug=False --threaded=True