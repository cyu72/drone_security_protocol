from flask import Flask
import subprocess
import os

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    print("test entered this function")
    drone_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build', 'drone')
    subprocess.Popen([drone_path])
    return "ACK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)