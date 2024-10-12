from flask import Flask, request, render_template, make_response, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_sqlalchemy import SQLAlchemy
from models import db, User, create_user
from cipher import AESCipher, gen_cookie

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

FLAG = open('flag.txt').read().strip()

with app.app_context():
    db.create_all()
COOKIE_KEY = os.urandom(16)

FLAG = open('flag.txt').read().strip()

    
with app.app_context():
    db.create_all()
    
cipher = AESCipher(COOKIE_KEY)

from flask import Response
class CustomResponse(Response):
    def __init__(self, response=None, status=None, headers=None, mimetype=None, content_type=None, direct_passthrough=False):
        super().__init__(response, status, headers, mimetype, content_type, direct_passthrough)
        if hasattr(self, 'session'):
            # Set the custom 'X-Session' header with the encrypted session data
            self.headers['X-Session'] = self.session

app.response_class = CustomResponse

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"Received {username}:{password} from {request.remote_addr}")
        
        # Validate input
        if not username or not password:
            return redirect(url_for('login', message="You missed a spot you silly goose."))

        # Fetch user by username
        user = User.get_by_username(username)
        if not user:
            return redirect(url_for('login', message="User not found. Please register first."))

        # Verify password
        if not user.check_password(password):
            return redirect(url_for('login', message="Invalid password. Please try again."))

        # Create session data
        session_data = f"username={username}&admin=0"
        encrypted_session = cipher.encrypt(session_data)  # Hex-encoded

        # Create response with 'X-Session' header
        resp = make_response(redirect(url_for('profile')))
        resp.session = encrypted_session  # Custom attribute for CustomResponse

        return resp

    # Handle GET request
    message = request.args.get('message', '')
    return render_template('login.html', message=message)





@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate input
        if not username or not password:
            return redirect(url_for('register', message="You missed a spot you silly goose."))

        # Prevent registering as 'admin'
        if username.lower() == 'admin':
            return redirect(url_for('register', message="Nice try, but you can't register as admin."))

        # Check if user exists
        if User.get_by_username(username):
            return redirect(url_for('register', message="User already exists"))

        # Create new user
        user = create_user(db, username, password)
        if isinstance(user, str):  # Error during user creation
            return redirect(url_for('register', message=user))
        else:
            return redirect(url_for('login', message="Registration successful. Please login."))

    # Handle GET request
    message = request.args.get('message', '')
    return render_template('register.html', message=message)



@app.route('/profile')
def profile():
    # Retrieve 'X-Session' header from the request
    encrypted_session = request.headers.get('X-Session')
    if not encrypted_session:
        return redirect(url_for('login', message="No session found. Please log in."))

    try:
        # Decrypt session data
        cookie_data = cipher.decrypt(encrypted_session)  # Decrypted string

        # Check for admin privileges
        if 'admin=1' in cookie_data:
            return redirect(url_for('flag'))
        
        # Extract username
        username = None
        for part in cookie_data.split('&'):
            if part.startswith('username='):
                username = part.split('=')[1]
                break
        
        if not username:
            return redirect(url_for('login', message="Invalid session data."))

        # Render profile
        return render_template('profile.html', username=username)

    except Exception as e:
        app.logger.error(f"Error processing profile: {str(e)}")
        return redirect(url_for('login', message="An error occurred. Please log in again."))


@app.route('/flag')
def flag():
    encrypted_session_hdr = request.headers.get('X-Session')
    if not encrypted_session_hdr:
        return redirect(url_for('login'))
    
    try:
        cookie_data = cipher.decrypt(encrypted_session_hdr)
        if 'admin=1' in cookie_data:
            return render_template('flag.html', flag=FLAG)
    
        else:
            return "Access denied. Admin privileges required.", 403
    
    except:
        return redirect(url_for('login', message="Invalid session data."))




if __name__ == '__main__':
    app.run(debug=True)