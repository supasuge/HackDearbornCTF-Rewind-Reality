from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    session = db.Column(db.String(256), nullable=True) # set to 256 in case someone uses long names and encrypted session cookie is more than 48+ chars
    
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @classmethod
    def get_by_username(cls, username):
        return cls.query.filter_by(username=username).first()


def create_user(db: SQLAlchemy, username: str, password: str, session: str =None) -> User:
    if session:
        user = User(username=username, session=session)
        user.set_password(password)
    else:
        user = User(username=username)
        user.set_password(password)
    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return "Error: " + str(e)
    return user