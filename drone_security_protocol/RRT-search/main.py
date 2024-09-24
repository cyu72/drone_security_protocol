from flask import Flask, request, jsonify
import rrt
import multiprocessing
import socket
import time

app = Flask(__name__)

rrt_obj = None
def handle_data(queue):
    while True:
        data = queue.get()
        process_data(data)

def recv_data(queue):
    host = '127.0.0.1'
    port = 60137

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    while True:
        conn, addr = server_socket.accept()
        data = conn.recv(1024)
        if not data:
            break

        print(f"Received data: {data.decode('utf-8')}")
        queue.put(data)
        
        conn.close()

def start_drone(rrt_obj):
    rrt_obj.start_drone()

def create_and_start_rrt():
    global rrt_obj
    print("Creating RRT object")
    rrt_obj = rrt.RRT(rrt.DroneType.LISTENER)
    print("RRT object created")

    data_queue = multiprocessing.Queue()
    receiver_process = multiprocessing.Process(target=recv_data, args=(data_queue,))
    # handler_process = multiprocessing.Process(target=handle_data, args=(data_queue,))
    rrt_process = multiprocessing.Process(target=start_drone, args=(rrt_obj,))

    receiver_process.start()
    # handler_process.start()
    rrt_process.start()

    # receiver_process.join()
    # handler_process.join()

@app.route('/', methods=['GET', 'POST'])
def root():
    global rrt_obj
    if request.method == 'POST':
        data = request.get_json()
        is_leader = data.get('is_leader', False)
        if is_leader:
            partition = data.get('partition', [])
            print(f"Received leader info. Partition: {partition}")
            rrt_obj.set_leader(partition)
        else:
            print("Received follower info")
        return jsonify({"status": "Info received", "is_leader": is_leader}), 200
    else:
        return jsonify({"status": "Drone service is running"}), 200

def run_flask():
    app.run(host='0.0.0.0', port=8080)

if __name__ == "__main__":
    # Create processes
    drone_process = multiprocessing.Process(target=create_and_start_rrt)
    flask_process = multiprocessing.Process(target=run_flask)

    # Start processes
    flask_process.start()
    drone_process.start()

    # Wait for processes to complete
    flask_process.join()
    drone_process.join()

    rrt.stop_drone()