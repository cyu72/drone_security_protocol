from flask import Flask, request, jsonify
from rrt import MessageType, DroneType, RRT
import multiprocessing
import json
import socket
import time

app = Flask(__name__)

def start_drone(rrt_obj, queue):
    rrt_obj.start_drone()

def create_and_start_rrt(queue):
    print("Creating RRT object")
    rrt_obj = RRT(DroneType.LISTENER)
    print("RRT object created")

    rrt_process = multiprocessing.Process(target=start_drone, args=(rrt_obj, queue))

    rrt_process.start()

    return rrt_process

def send_to_socket(data, max_retries=15, retry_delay=5):
    host = '127.0.0.1'
    port = 60137

    for attempt in range(max_retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((host, port))
                time.sleep(4) 
                client_socket.sendall(json.dumps(data).encode('utf-8'))
                print(f"Sent data to socket: {data}")
                return True  # Successfully sent data
        except Exception as e:
            print(f"Attempt {attempt + 1} failed. Error: {e}")
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("Max retries reached. Failed to send data.")
    return False  # Failed to send data after all retries

@app.route('/', methods=['GET', 'POST'])
def root():
    if request.method == 'POST':
        data = request.get_json()
        is_leader = data.get('is_leader', False)
        if is_leader:
            partition = data.get('partition', [])
            print(f"Received leader info. Partition: {partition}")
            send_to_socket({'is_leader': True, 'partition': partition})
        else:
            print("Received follower info")
            send_to_socket({'is_leader': False})
        return jsonify({"status": "Info received", "is_leader": is_leader}), 200
    else:
        return jsonify({"status": "Drone service is running"}), 200

def run_flask():
    app.run(host='0.0.0.0', port=8080)

if __name__ == "__main__":
    queue = multiprocessing.Queue()

    # Create processes
    drone_process = multiprocessing.Process(target=create_and_start_rrt, args=(queue,))
    flask_process = multiprocessing.Process(target=run_flask)

    # Start processes
    flask_process.start()
    drone_process.start()

    try:
        # Wait for processes to complete
        flask_process.join()
        drone_process.join()
    finally:
        # Ensure we stop all processes
        queue.put("STOP")
        # rrt.stop_drone()