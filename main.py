from flask import Blueprint
from flask_bootstrap import Bootstrap
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from config import S3_BUCKET, S3_KEY, S3_SECRET, SECRET_KEY, SQL_Host, SQL_User, SQL_Password, URI
from filters import datetimeformat, file_type
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
import uuid 
import os

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    name = db.Column(db.String(1000))
    url = db.Column(db.String(1000), unique=True)
    origfilename = db.Column(db.String(1000))


# init SQLAlchemy so we can use it later in our models


app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = URI


Bootstrap(app)
app.secret_key = 'secret'
app.jinja_env.filters['datetimeformat'] = datetimeformat
app.jinja_env.filters['file_type'] = file_type


db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
 # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

main = Blueprint('main', __name__)


#app.register_blueprint(s3_blueprint)

#app.register_blueprint(auth_blueprint)

#app.register_blueprint(main)

@app.route('/')
def index():
       return render_template('index.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    # login code goes here
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)

    return redirect(url_for('profile'))

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')
        return redirect(url_for('signup'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()
    
    return redirect(url_for('login'))
    

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('index.html')
#    return redirect(url_for('login'))


@app.route('/files')
@login_required
def files():
    s3_resource = boto3.resource(
         's3',
         aws_access_key_id=S3_KEY,
         aws_secret_access_key= S3_SECRET
      )
    
    s3_client = boto3.client(
        's3',
        aws_access_key_id=S3_KEY,
        aws_secret_access_key= S3_SECRET
    )

    my_bucket = s3_resource.Bucket(S3_BUCKET)

    summaries = my_bucket.objects.all()

    # 
    # build list with entries of Tag { Key=user, Value = current.user }
    # 
    user_obj_list = []

    for entry in summaries:
        response = s3_client.get_object_tagging(
            Bucket=S3_BUCKET,
            Key=entry.key
        )
        Tag = response["TagSet"]
        for KeyValue in Tag:
            if KeyValue["Key"] == "user":
                if KeyValue["Value"] == current_user.name:
                        user_obj_list.append(entry)

    return render_template('files.html', my_bucket=my_bucket, files=user_obj_list)

@app.route('/upload')
@login_required
def upload():
    s3_resource = boto3.resource('s3',aws_access_key_id=S3_KEY,aws_secret_access_key= S3_SECRET)
    my_bucket = s3_resource.Bucket(S3_BUCKET)
    return render_template('upload.html',my_bucket=my_bucket)

@app.route('/upload', methods=['POST'])
def upload_post():
    file = request.files['file']
    
    dst_filename = str(uuid.uuid1()) + os.path.splitext(file.filename)[1]

    s3_resource = boto3.resource('s3',
      aws_access_key_id=S3_KEY,
      aws_secret_access_key=S3_SECRET
    )

    my_bucket = s3_resource.Bucket(S3_BUCKET)
    tag = 'user=' + current_user.name
    my_bucket.Object(dst_filename).put(Body=file,Tagging='user=' + current_user.name)

    flash('File uploaded successfully')
    
    url='https://' + S3_BUCKET + '.s3-ap-southeast-1.amazonaws.com/' + dst_filename
    new_entry = Entry(
                  name = current_user.name,
                  url = url,
                  origfilename = file.filename
                  )
    db.session.add(new_entry)
    db.session.commit()


    return redirect(url_for('upload'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)


def create_app():
    app = Flask(__name__)

    
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = URI


    Bootstrap(app)
    app.secret_key = 'secret'
    app.jinja_env.filters['datetimeformat'] = datetimeformat
    app.jinja_env.filters['file_type'] = file_type
    
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    from models import User
    from models import Entry 

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))


    # blueprint for s3 routes in our app
    from .s3 import s3 as s3_blueprint
    app.register_blueprint(s3_blueprint)

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app


