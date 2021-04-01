import configparser
import datetime
import math
import random
# import json
import re
import string

import flask
from flask import Flask, render_template, request, redirect, url_for, session, flash
# import pymysql
from flask_pymongo import PyMongo
from flask_sqlalchemy import SQLAlchemy
from source.mail_service import sendemail

app = Flask(__name__)

# Firebase related
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

# Read the config file
configFile = '/var/www/votesapp-rest/config.ini'
firebase_key = '/var/www/votesapp-rest/testvotes-d4cd7-firebase-adminsdk-oqlux-66b40b5463.json'

config = configparser.ConfigParser()
config.read(configFile)

# PySQL configurations

userpass = config['MYSQLDB']['USERPASS']
basedir = '127.0.0.1'
dbname = '/votesapp_db'
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
mongo_db = 'votesapp_db'
# Mongo configuration
app.config['MONGO_DBNAME'] = 'votesapp_db'
app.config['MONGO_URI'] = mongo_connect_str + mongo_db
mongo = PyMongo(app)

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
session = {}
session['valid_email'] = False


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Use a service account
cred = credentials.Certificate(firebase_key)
firebase_admin.initialize_app(cred)
fire_db = firestore.client()
# https://firebase.google.com/docs/firestore/quickstart#python

db = SQLAlchemy(app)


@app.route('/about')
def about():
    return render_template('help.html')

if __name__ == '__main__':
    session_id = -1
    session_email = ''
    app.run(debug=True)