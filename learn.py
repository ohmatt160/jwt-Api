from datetime import datetime,time
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity, JWTManager
from sqlalchemy import create_engine, Column, DateTime, Integer, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restful import Resource, marshal_with, Api, reqparse, fields
from flask_mail import Mail,Message
from itsdangerous import URLSafeTimedSerializer
from flask_migrate import Migrate

Base= declarative_base()

app = Flask(__name__)
api = Api(app)
jwt=JWTManager(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Looking to send emails in production? Check out our Email API/SMTP product!
app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = 'd5c82933204588'
app.config['MAIL_PASSWORD'] = '48a454b81a1e63'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
# set expiration in seconds (example: 24 hours)
app.config['EMAIL_TOKEN_EXPIRATION'] = 24 * 60 * 60  # 86400 seconds
SECRET_KEY = 'your-secret-key'
JWT_SECRET_KEY = 'your-jwt-secret'
app.config['SECRET_KEY'] = SECRET_KEY
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
db=SQLAlchemy(app)
mail = Mail(app)
migrate=Migrate(app,db)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(50),unique=True, nullable=False)
    email=db.Column(db.String(50),unique=True, nullable=False)
    password=db.Column(db.String(50),nullable=False)
    db_name = db.Column(db.String(100), unique=True)
    is_verified = db.Column(db.Boolean, default=False)  # NEW

    def set_password(self,password):
        self.password=generate_password_hash(password,method='pbkdf2:sha256')
    def check_password(self,password):
        return check_password_hash(self.password,password)
args=reqparse.RequestParser()
args.add_argument('username',required=True)
args.add_argument('email',required=True)
args.add_argument('password',required=True)

class Tasks(Base):
    __tablename__='tasks'
    id=Column(Integer,primary_key=True)
    date = Column(DateTime, default=lambda:  datetime.combine(datetime.utcnow().date(), time.min))
    time = Column(DateTime, default=datetime.utcnow)
    task=Column(Text,nullable=False)

    def __repr__(self):
        return '<Task %r>' % self.task


args.add_argument('task',required=True)
args.add_argument('date',required=True)

new_task={
    'id':fields.Integer,
    'task':fields.String,
    'date':fields.DateTime,
    'time':fields.DateTime,
}

class TasksAPI(Resource):
    @jwt_required()
    def post(self):
        try:
            data=request.get_json()
            task_text = data.get('task')
            date_str = data.get('date')  # Expecting "YYYY-MM-DD"
            time_str = data.get('time')  # Expecting "HH:MM"

            # Combine and parse into datetime objects
            datetime_str = f"{date_str} {time_str}"
            task_datetime = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M")

            session = get_user_task_session()
            if not session:
                return jsonify({'message': 'Session creation failed'}), 500

            new_task = Tasks(task=task_text, date=task_datetime, time=task_datetime)
            session.add(new_task)
            session.commit()
            session.close()
            return {'message':'Task created!'}
        except Exception as e:
            return {'message': f'failed! {e}'},500
    @jwt_required()
    # @marshal_with(new_task)
    def get(self):
        try:
            session = get_user_task_session()
            tasks = session.query(Tasks).all()
            result = [{
                "id": t.id,
                "task": t.task,
                "date": t.date.isoformat() if t.date else None,
                "time": t.time.isoformat() if t.time else None
            } for t in tasks]
            session.close()
            return {"tasks": result}, 200


        except Exception as e:
            return {'message': f'failed! {e}'},500
api.add_resource(TasksAPI, '/tasks')

user_field={
    'username':fields.String,
    'email':fields.String,
    'password':fields.String,
}


class UserRegister(Resource):
    def post(self):
        try:
            data = request.get_json()
            if User.query.filter((User.username == data['username']) | (User.email == data['email'])).first():
                return {"message": "Username or email already exists"}, 400

            db_name = f"{data['username']}_tasks.db"
            new_user = User(username=data['username'], email=data['email'], db_name=db_name)
            new_user.set_password(data['password'])
            db.session.add(new_user)
            db.session.commit()




            token = generate_token(data['email'])
            send_email(data['email'], "Verify Your Account", f"Your verification token: {token}")
            return {"message": "User registered. Check your email for verification token."}, 201








        #     data = request.get_json()
        #
        #     db_name= f'{data["username"]}_tasks.db'
        #     email = data['email']
        #     token = generate_token(email)
        #     verify_url = f"http://localhost:5000/verify/{token}"
        #     send_email(email, "Verify Your Account", f"<p>Click to verify: <a href='{verify_url}'>Verify</a></p>")
        #     return jsonify({"message": "Check your email for verification link"}), 201


        #
        #
        #     new_user = User(username=data['username'], email=data['email'],db_name=db_name)
        #     new_user.set_password(data['password'])
        #     db.session.add(new_user)
        #     db.session.commit()
        #
        #     engine = create_engine(f"sqlite:///{db_name}")
        #     Base.metadata.create_all(engine)
        #     return jsonify({'message': 'User created successfully'})
        except Exception as e:
            return jsonify({'message': f'Error: {str(e)}' })
api.add_resource(UserRegister, '/register')

class VerifyAccount(Resource):
    def post(self):
        data = request.get_json()
        email = confirm_token(data.get('token'))
        if not email:
            return {"message": "Invalid or expired token"}, 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return {"message": "User not found"}, 404

        if user.is_verified:
            return {"message": "Account already verified"}, 200

        user.is_verified = True
        db.session.commit()
        return {"message": "Account verified successfully"}, 200
api.add_resource(VerifyAccount, '/verify')


class UserLogin(Resource):
    def post(self):
        try:
            data = request.get_json()
            user = User.query.filter_by(username=data['username']).first()
            if User.query.filter_by(email=data['email']).first():
                if user.check_password(data['password']):
                    access_token = create_access_token(identity=user.username)
                    return jsonify({'message': 'User login successfully'},{'access_token': access_token})
                else:
                    return jsonify({'message': 'User login failed\n username or email is incorrect'})
            else:
                return jsonify({'message': 'User login failed\n username or email is incorrect'})
        except Exception as e:
            return jsonify({'message': f'Error: {str(e)}' })
api.add_resource(UserLogin, '/login')



def get_user_task_session():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user:
        engine = create_engine(f"sqlite:///{user.db_name}")
        Session = sessionmaker(bind=engine)
        return Session()
    return None

def generate_token(email):
    return serializer.dumps(email, salt="email-confirm-salt")

def confirm_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt="email-confirm-salt", max_age=expiration)
    except Exception:
        return None
    return email

def send_email(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender=app.config['MAIL_USERNAME'])
    mail.send(msg)



class ProfileResource(Resource):
    # @marshal_with(new_task)
    @jwt_required()
    def get(self):
        current_user=get_jwt_identity()
        if not current_user:
            return {"message": "Unauthorized, no identity in token"}, 401
        user=User.query.filter_by(username=current_user).first()
        session = get_user_task_session()
        if session:
            tasks =  session.query(Tasks).all()
            result = [{
                "id": t.id,
                "task": t.task,
                "date": t.date.isoformat() if t.date else None,
                "time": t.time.isoformat() if t.time else None
            } for t in tasks]
            session.close()
            return {"user": user.username, "tasks": result}, 200

        return {'message': 'User login failed'}, 401
    @jwt_required()
    def post(self):
        try:
            data = request.get_json()
            task_text = data.get('task')
            date_str = data.get('date')
            time_str = data.get('time')

            datetime_str = f"{date_str} {time_str}"
            task_datetime = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M")

            session = get_user_task_session()
            if session:
                new_task = Tasks(task=task_text, date=task_datetime, time=task_datetime)
                session.add(new_task)
                session.commit()
                return {'message': 'Task created!'}
            else:
                return {'message': 'User login failed'}, 401
        except Exception as e:
            return {'message': f'Error: {str(e)}' }


api.add_resource(ProfileResource, '/profile')

class Users(Resource):
    @marshal_with(user_field)
    def get(self):
        users=User.query.all()
        return users, 200
api.add_resource(Users, '/')

class PasswordResetResource(Resource):
    @jwt_required()
    def post(self):
        email = request.json.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"message": "User not found"}), 404

        token = generate_token(user.email)
        # reset_url = f"http://localhost:5000/reset-password/{token}"
        send_email(user.email, "Password Reset", f"Your password reset token: {token}")

        return jsonify({"message": "Check your email for password reset link"}), 200
    def put(self):
        try:
            data = request.get_json()
            new_password = data.get('password')
            token = data.get('token')
            email = confirm_token(token)
            if not email:
                return jsonify({"message": "Reset link is invalid or expired"}), 400
            current_user = get_jwt_identity()
            user = User.query.filter_by(username=current_user).first()

            if not user:
                return {"message": "User not found"}, 404
            if not new_password:
                return jsonify({"message": "New password is required"}), 400

            user.set_password(new_password)
            db.session.commit()
            return {"message": "Password updated successfully"}, 200

        except Exception as e:
            return {"message": f"Error: {str(e)}"}, 500
api.add_resource(PasswordResetResource, '/password-reset')

with app.app_context():

    db.create_all()
if __name__ == '__main__':
    app.run(debug=True)