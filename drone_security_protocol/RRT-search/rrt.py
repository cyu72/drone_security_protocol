import os
import threading
import time
from enum import Enum
from flask import Flask, request, jsonify
import requests, json
from drone_wrapper import DroneRouting

app = Flask(__name__)
controller_address = "http://149.125.39.96:8080" # Find solution to get the IP without hardcode

@app.route('/', methods=['GET', 'POST'])
def root():
    if request.method == 'POST':
        data = request.get_json()
        is_leader = data.get('is_leader', False)
        if is_leader:
            partition = data.get('partition', [])
            # Process leader information and partition data
            print(f"Received leader info. Partition: {partition}")
            # You might want to call rrt.set_leader(partition) here
        else:
            print("Received follower info")
        return jsonify({"status": "Info received", "is_leader": is_leader}), 200
    else:
        return jsonify({"status": "Drone service is running"}), 200


def run_flask():
    app.run(host='0.0.0.0', port=8080)

class DroneType(Enum):
    LEADER = 1
    LISTENER = 2

class RRT:
    def __init__(self, drone_type):
        self.drone_type = drone_type
        self.x = 0
        self.y = 0
        self.drone_id = int(os.environ["PARAM1"])
        self.drone = DroneRouting(int(os.environ["PARAM2"]), int(os.environ["PARAM3"]))
        self.drone_thread = None
        self.partition = None

    def set_leader(self, partition):
        self.drone_type = DroneType.LEADER
        self.partition = partition
        print(f"Drone {self.drone_id} set as leader with partition: {self.partition}")

    def start_drone(self):
        self.drone_thread = threading.Thread(target=self.run_drone)
        self.drone_thread.start()
        self.x, self.y = self.get_controller_coords()
        print(f"Drone started at coordinates: x={self.x}, y={self.y}")

    def get_controller_coords(self):
        data = requests.get(f"{controller_address}/coords").json()
        for i in range(len(data['matrix'])):
            for j in range(len(data['matrix'][i])):
                if data['matrix'][i][j] == self.drone_id:
                    return i, j
        return None
    
    def modify_coords(self, x, y):
        global controller_address
        message = {
            "drone-id" : self.drone_id,
            "x" : x,
            "y" : y
        }
        try:
            response = requests.post(f"{controller_address}/update_coords", json=message)
            return response.json()
        except requests.RequestException as e:
            print(f"Error sending data to controller: {e}")
            return None

    def stop_drone(self):
        if self.drone_thread:
            self.drone.stop()  # TODO: Implement stop method in DroneRouting
            self.drone_thread.join()

def interface(rrt):
    while True:
        command = input("Enter command (send_hello/get_coords/exit): ").strip().lower()
        if command == 'exit':
            break
        elif command == 'send_hello':
            x = float(input("Enter the x-coordinate: "))
            y = float(input("Enter the y-coordinate: "))
            print(rrt.modify_coords(x, y))
        elif command == 'get_coords':
            coords = rrt.get_controller_coords()
            if coords:
                print(f"Current coordinates: x={coords[0]}, y={coords[1]}")
            else:
                print("Failed to get coordinates from the controller.")
        else:
            print("Invalid command")
        time.sleep(1)

if __name__ == "__main__":
    rrt = RRT(DroneType.LISTENER)

    flask_thread = threading.Thread(target=run_flask)
    flask_thread.start()
    interface(rrt)
    flask_thread.join()
    rrt.stop_drone()