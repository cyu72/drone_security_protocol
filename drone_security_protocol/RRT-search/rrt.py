import os
import time
from enum import Enum
import requests, json
from drone_wrapper import DroneRouting

controller_address = "http://" + os.environ["CONTROLLER_ADDR"] + ":8080"
class DroneType(Enum):
    LEADER = 1
    LISTENER = 2

class RRT:
    def __init__(self, drone_type):
        self.drone_type = drone_type
        self.drone_id = int(os.environ["PARAM1"])
        self.drone = DroneRouting(int(os.environ["PARAM2"]), int(os.environ["PARAM3"]))

        self.x = 0
        self.y = 0
        self.grid_size = 0
        self.partition = None
        self.followers = []

    def set_leader(self, partition):
        self.drone_type = DroneType.LEADER
        self.partition = partition
        print(f"Drone {self.drone_id} set as leader with partition: {self.partition}")

    def start_drone(self):
        self.x, self.y = self.get_controller_coords()
        print(f"Drone started at coordinates: x={self.x}, y={self.y}")
        self.drone.start()
        time.sleep(5)
        if self.drone_type == DroneType.LEADER:
            data = {"is_leader" : True, "leader_id" : self.drone_id}
            self.drone.broadcast(data)

    def get_controller_coords(self):
        data = requests.get(f"{controller_address}/coords").json()
        self.grid_size = len(data['matrix'])
        print(f'Grid Size: {self.grid_size}')
        for i in range(self.grid_size):
            for j in range(len(data['matrix'][i])):
                if data['matrix'][i][j] == self.drone_id:
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

    def stop_drone(self):
        # Implement stop logic if needed
        pass

    # Leader Functions
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