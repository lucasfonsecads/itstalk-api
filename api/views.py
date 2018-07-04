from api import app
import os

@app.route('/')
def index():
    credentials = os.environ['CREDENTIALS']
    return credentials