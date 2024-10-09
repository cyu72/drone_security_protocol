import os
import multiprocessing
import asyncio
import re
import time
import threading
import select
from enum import Enum
import requests, json
import socket
from drone_wrapper import DroneRouting

controller_address = "http://" + os.environ["CONTROLLER_ADDR"] + ":8080"
class DroneType(Enum):
    LEADER = 1
    LISTENER = 2

class MessageType(Enum):
    LEADER_UPDATE = "LEADER_UPDATE"
    LOCATION_UPDATE = "LOCATION_UPDATE"
    FOLLOWER_DATA = "FOLLOWER_DATA"
    TASK_ASSIGNMENT = "TASK_ASSIGNMENT"

class RRT:
    def __init__(self, drone_type):
        self.drone_type = drone_type
        self.drone_id = "drone" + str(os.environ["PARAM1"]) + "-service.default"

        self.drone = DroneRouting(int(os.environ["PARAM2"]), int(os.environ["PARAM3"]))
        start_proc = multiprocessing.Process(target=self.safe_start)
        start_proc.start()

        self.x = 0
        self.y = 0
        self.grid_size = 0
        self.partition = None
        self.followers = []

        self.data_queue = multiprocessing.Queue()

    def set_leader(self, partition):
        self.drone_type = DroneType.LEADER
        self.partition = partition
        print(f"Drone {self.drone_id} set as leader with partition: {self.partition}")

        data = json.dumps({"message_type": MessageType.LEADER_UPDATE.name, "leader_id": self.drone_id})
        while True:
            try:
                self.drone.broadcast(data)
                break
            except requests.RequestException as e:
                print(f"Error broadcasting leader establishment: {e}. Retrying in 5 seconds...")
                time.sleep(5)
        print("Leader establishment broadcasted")

    def get_controller_coords(self):
        data = requests.get(f"{controller_address}/coords").json()
        self.grid_size = len(data['matrix'])
        print(f'Grid Size: {self.grid_size}')
        for i in range(self.grid_size):
            for j in range(len(data['matrix'][i])):
                int_grid_representation = int(re.search(r'drone(\d+)', f"drone{os.environ['PARAM1']}-service.default").group(1))
                if data['matrix'][i][j] == int_grid_representation:
                    return i, j
        return None
    
    def modify_coords(self, x, y):
        message = {
            "drone-id": self.drone_id,
            "x": x,
            "y": y
        }
        try:
            response = requests.post(f"{controller_address}/update_coords", json=message)
            return response.json()
        except requests.RequestException as e:
            print(f"Error sending data to controller: {e}")
            return None
        
    def recv_data(self):
        host = '127.0.0.1'
        port = 60137

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setblocking(False)
        server_socket.bind((host, port))
        server_socket.listen(1)

        inputs = [server_socket]
        
        while True:
            readable, _, _ = select.select(inputs, [], [], 0.1)
            
            for s in readable:
                if s is server_socket:
                    try:
                        conn, addr = s.accept()
                        conn.setblocking(False)
                        inputs.append(conn)
                        print(f"New connection from {addr}")
                    except BlockingIOError:
                        pass  # No connection is ready to be accepted
                else:
                    try:
                        data = s.recv(1024)
                        if data:
                            print(f"Received data: {data.decode('utf-8')}")
                            self.data_queue.put(data)
                        else:
                            inputs.remove(s)
                            s.close()
                            print(f"Connection closed")
                    except (ConnectionResetError, BlockingIOError):
                        inputs.remove(s)
                        s.close()
                        print(f"Connection error")

        server_socket.close()

    def process_data(self):
        while True:
            if not self.data_queue.empty():
                data = self.data_queue.get(block=False)
                data = json.loads(data)
                
                if data.get('is_leader'): # temp: normalize this to MessageType
                    partition = data.get('partition', [])
                    self.set_leader(data.get('partition', partition))

                else: 
                    try: 
                        if data.get('message_type') == MessageType.LEADER_UPDATE.name:
                            print(f"Received leader update: {data.get('leader_id')}")
                            leader_id = data.get('leader_id')
                            # reply with confirmation that we are follower now
                            data = json.dumps({"message_type": MessageType.FOLLOWER_DATA.name, "follower_id": self.drone_id})
                            data = ''
                            self.drone.send(leader_id, data)

                        elif data.get('message_type') == MessageType.FOLLOWER_DATA.name:
                            print(f'Received follower data')
                            self.followers.append(leader_id)
                            print(f"Added follower: {leader_id}")

                        elif data.get('message_type') == MessageType.LOCATION_UPDATE.name:
                            # send back to leader that our current coordinates
                            print(f'Received path update')

                    except json.JSONDecodeError:
                        print(f"Error decoding JSON: {data}")
                    except Exception as e:
                        print(f"Error processing data: {e}")
            else:
                time.sleep(3)

    def logic_loop(self):
        while True: # while path coverage not covered
            print(f"Drone {self.drone_type}")
            if self.drone_type == DroneType.LEADER:
                print(f"Followers: {self.followers}")
                time.sleep(5)
                # if leader
                # await update from followers
                # await handle_failure (if follower cannot move to position we previously asked it)
                # await path planning
                # send out tasks to followers

            elif self.drone_type == DroneType.LISTENER:
                # check if we have any pending updates to attend to
                time.sleep(5)

    def safe_start(self):
        self.drone.start()

    def start_drone(self):
        self.x, self.y = self.get_controller_coords()
        print(f"Drone started at coordinates: x={self.x}, y={self.y}")
        
        recv_proc = multiprocessing.Process(target=self.recv_data)

        process_thread = threading.Thread(target=self.process_data)
        main_thread = threading.Thread(target=self.logic_loop)

        recv_proc.start()

        process_thread.start()
        main_thread.start()

    def stop_drone(self):
        # Implement stop logic if needed
        pass

    # Leader Functions
    async def request_coords(self):
        for follower in self.followers:
            data = json.dumps({"message_type": MessageType.LOCATION_UPDATE.name, "follower_id": follower})
            while True:
                try:
                    self.drone.send(follower, data)
                    break
                except requests.RequestException as e:
                    print(f"Error sending location update request: {e}. Retrying in 5 seconds...")
                    time.sleep(5)
            print(f"Location update request sent to follower {follower}")


    def update_map(self, data):
        # Update occupancy grid based on follower data
        pass

    def plan_paths(self):
        # Use RRT to generate new exploration paths
        pass

    def assign_tasks(self):
        # Distribute tasks to follower drones
        pass

    def communicate_with_mission_control(self):
        # Send high-level updates and receive commands
        pass

    # Follower Functions
    def follow_path(self):
        # Execute the assigned path
        pass

    def collect_data(self):
        # Gather sensor data
        pass

    def report_to_leader(self):
        # Send status and sensor data to leader
        pass

# First determine nodes that are connected to the leader
# Second determine routes for each node
# Third distribute those routes
# Those nodes report back eventually
# If we have completed area coverage, we are done, else recalculate new routes