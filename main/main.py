#!/usr/bin/env python3
from flask import Flask, request
from crypt import AES
import os
import json
from uuid import uuid4
import base64

app = Flask(__name__)

SAVE_DIR = '/tmp/encfs'

def save_data(data,filename,store_dir):
    if os.path.isdir(store_dir) == False:
        os.makedirs(store_dir)
    else:
        if store_dir[-1] == '/':
            del store_dir[:-1]
        open(store_dir+'/'+filename,'wb').write(data)


@app.route('/')
def index():
    welcome_message = '''file storage API\n1) send data to /encrypt endpoint\n2) you will get a uuid and secret_key\n3) send the uuid and sceret key to /retrieve endpoint and get back your file\n'''
    return welcome_message

@app.route('/encrypt',methods=['POST'])
def encrypt():
    data = request.data
    secret = os.urandom(16)
    uniq = str(uuid4()).replace('-','')
    a = AES(secret_key=secret)
    hidden_data = a.encrypt(data)
    save_data(hidden_data,uniq,SAVE_DIR)
    resp = {'uuid':uniq,'secret_key':base64.b64encode(secret).decode()}
    return resp

@app.route('/retrieve',methods=['POST'])
def retrieve():
    try:
        json_data = request.get_json(force=True)
        uniq = json_data['uuid']
        secret_key = json_data['secret_key']
    except:
        return 'invalid json'
    if (os.path.isfile(SAVE_DIR+'/'+uniq) == False):
        return 'file does not exist on server'
    else:
        #sanitize uniq
        uniq.replace('/','')
        uniq.replace('.','')
        #decode secret
        secret = base64.b64decode(secret_key)
        ret_file_enc = open(SAVE_DIR+'/'+uniq,'rb').read()
        a = AES(secret_key=secret)
        ret_file = a.decrypt(ret_file_enc)
        return ret_file
