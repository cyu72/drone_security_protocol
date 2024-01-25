from flask import Flask
import subprocess

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    subprocess.Popen(["./drone"])
    return "ACK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)