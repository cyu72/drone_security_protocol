import time, sys, random
import math
import argparse
import subprocess
import threading
import requests

from flask import Flask, request, jsonify
from kubernetes import client, config
from tabulate import tabulate
import colorama
from colorama import Fore, Back, Style
import time

app = Flask(__name__)
colorama.init(autoreset=True)
matrix = []

parser = argparse.ArgumentParser(description='TBD')
parser.add_argument('--drone_count', type=int, default=15, help='Specify number of drones in simulation')
parser.add_argument('--startup', action='store_true', help='Complete initial startup process (minikube)')
parser.add_argument('--tesla_disclosure_time', type=int, default=10, help='Disclosure period in seconds of every TESLA key disclosure message')
parser.add_argument('--max_hop_count', type=int, default=8, help='Maximium number of nodes we can route messages through')
parser.add_argument('--stable', action='store_true', help='Use stable version of the drone image')
parser.add_argument('--timeout', type=int, default=30, help='Timeout for each request')
parser.add_argument('--grid_size', type=int, default=8, help='Defines nxn sized grid.')
parser.add_argument('--grid_type', choices=['random', 'hardcoded'], default='hardcoded', help='Choose between random or hardcoded grid')
args = parser.parse_args()

def generate_random_matrix(n, numDrones):
    matrix = [[0] * n for _ in range(n)]
    drone_numbers = random.sample(range(1, numDrones + 1), numDrones)
    
    for num in drone_numbers:
        while True:
            row = random.randint(0, n - 1)
            col = random.randint(0, n - 1)
            if matrix[row][col] == 0:
                matrix[row][col] = num
                break
    
    return matrix

def generate_hardcoded_matrix(n, numDrones):
    matrix = [
        [1, 2, 4, 0, 14, 0, 0, 0],
        [3, 0, 0, 0, 15, 0, 0, 0],
        [0, 0, 0, 0, 0, 9, 0, 0],
        [5, 0, 0, 0, 0, 10, 0, 0],
        [6, 7, 8, 0, 0, 11, 13, 0],
        [0, 0, 0, 0, 0, 12, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0]
    ]
    return matrix

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    processes.append(process)
    output, error = process.communicate()
    return output.decode(), error.decode()

def partition_grid(matrix, num_leaders):
    n = len(matrix)
    partitions = []
    
    num_rows = int(math.sqrt(num_leaders))
    num_cols = math.ceil(num_leaders / num_rows)
    
    row_size = n // num_rows
    col_size = n // num_cols
    
    for i in range(num_rows):
        for j in range(num_cols):
            if len(partitions) < num_leaders:
                start_row = i * row_size
                end_row = min((i + 1) * row_size, n) - 1
                start_col = j * col_size
                end_col = min((j + 1) * col_size, n) - 1
                
                if i == num_rows - 1:
                    end_row = n - 1
                if j == num_cols - 1:
                    end_col = n - 1
                
                partition = {
                    "start_row": start_row,
                    "end_row": end_row,
                    "start_col": start_col,
                    "end_col": end_col,
                    "drones": []
                }
                
                for x in range(start_row, end_row + 1):
                    for y in range(start_col, end_col + 1):
                        if matrix[x][y] != 0:
                            partition["drones"].append((matrix[x][y], x, y))
                
                partitions.append(partition)
    
    return partitions

def select_leader_drones(matrix, num_leaders):
    drones = [(matrix[i][j], i, j) for i in range(len(matrix)) for j in range(len(matrix[i])) if matrix[i][j] != 0]
    return random.sample(drones, min(num_leaders, len(drones)))

def print_matrix(matrix):
    headers = [''] + [str(i) for i in range(len(matrix[0]))]
    
    table_data = []
    for i, row in enumerate(matrix):
        colored_row = [str(i)]
        for element in row:
            if element == 0:
                colored_row.append(f"{Fore.LIGHTBLACK_EX}{element:2}{Style.RESET_ALL}")
            else:
                colored_row.append(f"{Fore.GREEN}{Back.LIGHTWHITE_EX}{element:2}{Style.RESET_ALL}")
        table_data.append(colored_row)
    
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    print(f"\n{Fore.CYAN}Legend: {Fore.GREEN}{Back.LIGHTWHITE_EX} Drone {Style.RESET_ALL} | {Fore.LIGHTBLACK_EX}0{Style.RESET_ALL} Empty Space")

def get_neighbors(matrix, i, j):
    neighbors = []
    if i > 0 and matrix[i-1][j] != 0:
        neighbors.append(matrix[i-1][j])
    if i < len(matrix)-1 and matrix[i+1][j] != 0:
        neighbors.append(matrix[i+1][j])
    if j > 0 and matrix[i][j-1] != 0:
        neighbors.append(matrix[i][j-1])
    if j < len(matrix[i])-1 and matrix[i][j+1] != 0:
        neighbors.append(matrix[i][j+1])
    return neighbors

def create_network_policy(drone_number, neighbors):
    return f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-selector{drone_number}
spec:
  podSelector:
    matchLabels:
      app: drone{drone_number}
      tier: drone
  ingress:
  - from:
    - podSelector:
        matchExpressions:
        - {{key: app, operator: In, values: [gcs, {', '.join(['drone' + str(neighbor) for neighbor in neighbors])}]}}"""

def update_network_policies(matrix):
    policies = []
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            if matrix[i][j] != 0:
                neighbors = get_neighbors(matrix, i, j)
                policy = create_network_policy(matrix[i][j], neighbors)
                policies.append(policy)
    
    with open('etc/kubernetes/deploymentNetworkPolicy.yml', 'w') as file:
        file.write("\n---\n".join(policies))
    
    subprocess.run("kubectl apply -f etc/kubernetes/deploymentNetworkPolicy.yml", shell=True, check=True)

def move_drone(matrix, drone, to_pos):
    to_i, to_j = to_pos
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            if matrix[i][j] == drone:
                matrix[i][j] = 0
                matrix[to_i][to_j] = drone
                return matrix
    raise ValueError(f"Drone {drone} not found in the matrix")

@app.route('/coords', methods=['GET'])
def get_coords():
    return jsonify({"matrix": matrix}), 200

@app.route('/update_coords', methods=['POST'])
def update_coords():
    global matrix
    message = request.json
    try:
        drone = int(message['drone-id'])
        to_i = int(float(message['x']))
        to_j = int(float(message['y']))
        
        if to_i < 0 or to_i >= len(matrix) or to_j < 0 or to_j >= len(matrix[0]):
            return jsonify({"error": f"Position ({to_i}, {to_j}) is out of bounds"}), 400
        
        if matrix[to_i][to_j] != 0:
            return jsonify({"error": f"Position ({to_i}, {to_j}) is not empty"}), 400
        
        matrix = move_drone(matrix, drone, (to_i, to_j))
        update_network_policies(matrix)
        print(f"Drone {drone} moved to position ({to_i}, {to_j})")
        print("Matrix updated and network policies updated.")
        print_matrix(matrix)
        return jsonify({"message": "Coordinates updated successfully", "new_matrix": matrix}), 200
    except KeyError as e:
        return jsonify({"error": f"Invalid request format. Missing key: {str(e)}"}), 400
    except ValueError as e:
        return jsonify({"error": f"Invalid value: {str(e)}. Please provide valid integer values."}), 400
    except IndexError:
        return jsonify({"error": "Invalid position. Please ensure all indices are within the matrix bounds."}), 400
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

def run_flask_server():
    app.run(host='0.0.0.0', port=8080)

def setup_port_forwarding(services):
    for service in services.items:
        if service.spec.type == "LoadBalancer" and service.metadata.name.startswith("drone"):
            drone_number = int(service.metadata.name.split("drone")[1].split("-")[0])
            nodePort = 30000 + drone_number
            command = f"kubectl port-forward svc/{service.metadata.name} {nodePort}:8080"
            thread = threading.Thread(target=run_command, args=(command,))
            thread.start()
            threads.append(thread)
    
    time.sleep(5)

def main():
    flask_thread = threading.Thread(target=run_flask_server)
    flask_thread.start()
    global matrix, processes, threads

    droneNum = args.drone_count
    droneImage = "cyu72/drone:stable" if args.stable else "cyu72/drone:latest"
    gcsImage = "cyu72/gcs:latest"

    controller_addr = input("Enter the controller address: ")

    if args.startup:
        subprocess.run("minikube start --insecure-registry='localhost:5001' --network-plugin=cni --cni=calico", shell=True, check=True)
        subprocess.run("kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml", shell=True, check=True)
        subprocess.run("kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml", shell=True, check=True)
        subprocess.run("minikube addons enable metallb", shell=True, check=True)

    delim = "---\n"

    with open('etc/kubernetes/droneDeployment.yml', 'w') as file: 
        nodePort = 30001
        for num in range(1, droneNum + 1):
            drone = f"""apiVersion: v1
kind: Pod
metadata:
  name: drone{num}
  namespace: default
  labels:
    app: drone{num}
    tier: drone
spec:
  hostname: drone{num}
  containers: 
    - name: drone{num}
      image: {droneImage}
      stdin: true
      tty: true
      env:
        - name: PARAM1
          value: "{num}"
        - name: PARAM2
          value: "65456"
        - name: PARAM3
          value: "{num}"
        - name: TESLA_DISCLOSE
          value: "{args.tesla_disclosure_time}"
        - name: MAX_HOP_COUNT
          value: "{args.max_hop_count}"
        - name: CONTROLLER_ADDR
          value: "{controller_addr}"
        - name: TIMEOUT_SEC
          value: "{args.timeout}"
      ports:
        - name: action-port
          protocol: TCP
          containerPort: 65456
        - name: brdcst-port
          protocol: UDP
          containerPort: 65457
        - name: start-port
          protocol: TCP
          containerPort: 8080
"""
            service = f"""apiVersion: v1
kind: Service
metadata:
  name: drone{num}-service
spec:
  externalTrafficPolicy: Local
  type: LoadBalancer
  selector:
    app: drone{num}
    tier: drone
  ports:
  - name: drone-port
    protocol: TCP
    port: 80
    targetPort: 65456
  - name: udp-test-port
    protocol: UDP
    port: 65457
    targetPort: 65457
  - name: start-port
    protocol: TCP
    port: 8080
    targetPort: 8080 
    nodePort: {nodePort}
"""
            file.write(drone)
            file.write(delim)
            file.write(service)
            file.write(delim)
            nodePort += 1

        gcs = f"""apiVersion: v1
kind: Pod
metadata:
  name: gcs
  namespace: default
  labels:
    app: gcs
    tier: drone
spec:
  hostname: gcs
  containers: 
    - name: gcs
      image: {gcsImage}
      stdin: true
      tty: true
      ports:
        - name: main-port
          protocol: TCP
          containerPort: 65456
        - name: udp-test-port
          protocol: UDP
          containerPort: 65457"""
        
        configMap = f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: config
  namespace: metallb-system
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - 192.168.1.101-192.168.1.150
"""
        
        file.write(gcs + "\n" + delim + configMap + "\n")
        file.close()
        
    valid_config = False

    while not valid_config:
        if args.grid_type == 'random':
            matrix = generate_random_matrix(args.grid_size, droneNum)
        else:
            matrix = generate_hardcoded_matrix(args.grid_size, droneNum)

        for row in matrix:
            for element in row:
                print("{:2}".format(element), end=' ')
            print()

        user_input = input("Is this a valid configuration? (yes/no): ")
        if user_input.lower() == "yes":
            valid_config = True

    if (args.startup):
        time.sleep(45)

    with open('etc/kubernetes/deploymentNetworkPolicy.yml', 'w') as file:
        for i in range(len(matrix)):
            for j in range(len(matrix[i])):
                if matrix[i][j] != 0:
                    neighbors = []
                    if i > 0 and matrix[i-1][j] != 0:
                        neighbors.append(matrix[i-1][j])
                    if i < len(matrix)-1 and matrix[i+1][j] != 0:
                        neighbors.append(matrix[i+1][j])
                    if j > 0 and matrix[i][j-1] != 0:
                        neighbors.append(matrix[i][j-1])
                    if j < len(matrix[i])-1 and matrix[i][j+1] != 0:
                        neighbors.append(matrix[i][j+1])

                    print(f"Neighbors of drone{matrix[i][j]}: {neighbors}")
                    if neighbors:
                        networkPolicy = f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-selector{matrix[i][j]}
spec:
  podSelector:
    matchLabels:
      app: drone{matrix[i][j]}
      tier: drone
  ingress:
  - from:
    - podSelector:
        matchExpressions:
        - {{key: app, operator: In, values: [gcs, {', '.join(['drone' + str(neighbor) for neighbor in neighbors])}]}}"""
                        file.write(networkPolicy + "\n" + delim)
                    else:
                        networkPolicy = f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-selector{matrix[i][j]}
spec:
  podSelector:
    matchLabels:
      app: drone{matrix[i][j]}
      tier: drone
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: gcs"""
                        file.write(networkPolicy + "\n" + delim)

    file.close()

    command = "kubectl apply -f etc/kubernetes/droneDeployment.yml"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = "kubectl apply -f etc/kubernetes/deploymentNetworkPolicy.yml"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    time.sleep(20)

    processes = []
    threads = []

    while True:
        config.load_kube_config()
        api_instance = client.CoreV1Api()

        pods = api_instance.list_pod_for_all_namespaces(watch=False)
        services = api_instance.list_service_for_all_namespaces()

        all_running = True
        for pod in pods.items:
            if pod.status.phase != "Running":
                all_running = False
                time.sleep(10)
                break

        if all_running:
            print("All pods are running")
            time.sleep(5)
            setup_port_forwarding(services)

            num_leaders = 3
            leader_drones = select_leader_drones(matrix, num_leaders)
            partitions = partition_grid(matrix, num_leaders)

            for service in services.items:
                if service.spec.type == "LoadBalancer" and service.metadata.name.startswith("drone"):
                    drone_number = int(service.metadata.name.split("drone")[1].split("-")[0])
                    nodePort = 30000 + drone_number
                    print(f"Service: {service.metadata.name}")

                    for ingress in service.status.load_balancer.ingress:
                        url = f"http://127.0.0.1:{nodePort}"
                        print(f"Sending request to {url}")

                        is_leader = any(drone[0] == drone_number for drone in leader_drones)
                        data = {"is_leader": is_leader}

                        if is_leader:
                            leader_index = next(i for i, drone in enumerate(leader_drones) if drone[0] == drone_number)
                            partition = partitions[leader_index]
                            data["partition"] = {
                                "start_row": partition["start_row"],
                                "end_row": partition["end_row"],
                                "start_col": partition["start_col"],
                                "end_col": partition["end_col"]
                            }

                        try:
                            response = requests.post(url, json=data)
                            response.raise_for_status()
                            print(f"Sent {'leader' if is_leader else 'follower'} info to Drone {drone_number}")
                        except requests.exceptions.RequestException as e:
                            print(f"Failed to send info to Drone {drone_number}: {e}")
            for process in processes:
                process.terminate()
            break

        else:
            print("Not all pods are running")

    setup_port_forwarding(services)
    while True:
        print_matrix(matrix)
        user_input = input("Enter move (drone_number to_i to_j) or 'q' to quit: ")
        
        if user_input.lower() == 'q':
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()
            flask_thread.join()
            break
        
        try:
            drone, to_i, to_j = map(int, user_input.split())
            if matrix[to_i][to_j] != 0:
                print(f"Error: Position ({to_i}, {to_j}) is not empty")
                continue
            
            matrix = move_drone(matrix, drone, (to_i, to_j))
            update_network_policies(matrix)
            print("Network policies updated.")
        except ValueError as e:
            print(f"Error: {str(e)}")
        except IndexError:
            print("Invalid position. Please ensure all indices are within the matrix bounds.")
        
        for service in services.items:
            if service.spec.type == "LoadBalancer" and service.metadata.name.startswith("drone"):
                drone_number = int(service.metadata.name.split("drone")[1].split("-")[0])
                nodePort = 30000 + drone_number
                print(f"Service: {service.metadata.name}")

                for ingress in service.status.load_balancer.ingress:
                    url = f"http://127.0.0.1:{nodePort}"
                    print(f"Sending request to {url}")

                    try:
                        response = requests.get(url)
                        response.raise_for_status()
                    except requests.exceptions.RequestException as e:
                        print(f"Failed to send info to Drone {drone_number}: {e}")
        

if __name__ == "__main__":
    main()