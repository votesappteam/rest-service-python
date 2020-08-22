from flask import Flask, request, jsonify, make_response, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt  #we have to install pyJWT
import datetime
from functools import wraps
#import pymysql
from flask_pymongo import PyMongo
import pymongo
#import json
import re
import configparser
import pprint
#import classify
#Reference Video
# https://www.youtube.com/watch?v=WxGBoY5iNXY

app = Flask(__name__)


#Read the config file
configFile = '/var/www/votesapp-rest/config.ini'

config = configparser.ConfigParser()
config.read(configFile)


#PySQL configurations

userpass = config['MYSQLDB']['USERPASS']
basedir  = '127.0.0.1'
dbname  = '/votesapp_db'
socket = config['MYSQLDB']['SOCKET']
dbname = dbname + socket


app.config['SECRET_KEY'] = config['SECURITY']['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = userpass + basedir + dbname
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload file
UPLOAD_FOLDER = '/var/www/votesapp-rest/nsfw-images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

mongo_connect_str = 'mongodb://localhost:27017/'
mongo_db ='votesapp_db'
#Mongo configuration
app.config['MONGO_DBNAME'] = 'votesapp_db'
app.config['MONGO_URI'] = mongo_connect_str+mongo_db
mongo = PyMongo(app)

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


db = SQLAlchemy(app)

@app.route('/admin/hello')
def hello():
	return render_template('hello.html')

if __name__ == '__main__':
    app.run(debug=True)