from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
#PySQL configurations
userpass = 'mysql+pymysql://webuser:sindhu123$@'
basedir  = '127.0.0.1'
# change to YOUR database name, with a slash added as shown
dbname   = '/votesapp_db'
# this socket is going to be very different on a Windows computer
socket   = '?unix_socket=/tmp/mysql.sock'  #Mac mini Dev
#socket   = '?unix_socket=/var/run/mysqld/mysqld.sock'  #Ubuntu
dbname   = dbname + socket


app.config['SECRET_KEY'] = 'thisissecret'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://webuser:sindhu123$@localhost/votesapp_db'
#app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://webuser:sindhu123$@localhost:3306/votesapp_db"
# put them all together as a string that shows SQLAlchemy where the database is
app.config['SQLALCHEMY_DATABASE_URI'] = userpass + basedir + dbname
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    uid = db.Column(db.String(50))
    password = db.Column(db.String(80))
    active = db.Column(db.Boolean)


def adduser(uid,password):
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), uid=uid, password=hashed_password, active=True)
    db.session.add(new_user)
    db.session.commit()
    print("User successfully added")

def updateuser(uid,password):
    hashed_password = generate_password_hash(password, method='sha256')
    user = User.query.filter_by(uid=uid).first()
    if not user:
        print("ERROR: User not found to update..")
    else:
        user.password = hashed_password
        db.session.commit()
        print("User successfully updated")
if __name__ == '__main__':
    print("****Welcome to Rest API user management***")
    operation = input("Enter your value 1 for ADDING an user, 2 for UPDATING password for an user: ")
    if operation == "1":
        userin = input("Enter the user name : ")
        passin = input("Enter the password : ")
        adduser(userin,passin)
    elif operation ==  "2":
        userin = input("Enter the user name : ")
        passin = input("Enter the new password : ")
        updateuser(userin,passin)




