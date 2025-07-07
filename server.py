#Create a simple server that listens on port 5000 and responds with "Hello, World!" to any request

from flask import Flask, jsonify

app = Flask(__name__)  
@app.route('/')

def hello_world():
    return jsonify(message="Hello, World!")

if __name__ == '__main__':
    app.run("localhost", 8000)
