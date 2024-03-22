import time, sys, random
import subprocess
from kubernetes import client, config
import subprocess
import threading

# Generate Manifest Start
droneNum = int(input("Total number of drones in swarm: "))
imagePullLocation = int(input("1): DockerHub\n2): Local\nImage pull location: "))
if imagePullLocation == 1:
    droneImage = "cyu72/drone:latest"
    gcsImage = "cyu72/gcs:latest"
elif imagePullLocation == 2:
    minikubeIP = input("Minikube IP: ")
    droneImage = f"""{minikubeIP}:6000/drone:latest
      imagePullPolicy: IfNotPresent"""
    gcsImage = f"""{minikubeIP}:6000/gcs:latest
      imagePullPolicy: IfNotPresent"""

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
      env:
        - name: PARAM1
          value: "drone{num}"
        - name: PARAM2
          value: "65456"
        - name: PARAM3
          value: "{num}"
      ports:
        - name: action-port
          protocol: UDP
          containerPort: 65456
        - name: start-port
          protocol: TCP
          containerPort: 8080
"""
        service = f"""apiVersion: v1
kind: Service
metadata:
  name: drone{num}-service
spec:
  type: LoadBalancer
  selector:
    app: drone{num}
    tier: drone
  ports:
  - name: drone-port
    protocol: UDP
    port: 80
    targetPort: 65456
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
        - protocol: UDP
          containerPort: 65456"""
    
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

# Create a matrix that is of variable size
# Randomly place each drone in the matrix, where each drone is represented by its number

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

n = 8  # size of the matrix
matrix = generate_random_matrix(n, droneNum)

for row in matrix:
  for element in row:
    print("{:2}".format(element), end=' ')
  print()

with open('etc/kubernetes/deploymentNetworkPolicy.yml', 'w') as file:
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            if matrix[i][j] != 0:
                neighbors = []
                if i > 0 and matrix[i-1][j] != 0: # Only 4 tiles around
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
# Generate Manifest End

# Apply Manifests
command = "kubectl apply -f etc/kubernetes/droneDeployment.yml"
process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
command = "kubectl apply -f etc/kubernetes/deploymentNetworkPolicy.yml"
process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

time.sleep(20) # Need to wait for command to execute all yaml files

processes = []

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    processes.append(process)
    output, error = process.communicate()
    return output.decode(), error.decode()

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
            time.sleep(10) # Wait for all pods to start
            break


    # Port forward all services to be accessible from outside the cluster
    if all_running:
        print("All pods are running")
        time.sleep(5)
        for service in services.items:
            if service.spec.type == "LoadBalancer" and service.metadata.name.startswith("drone"):
                drone_number = service.metadata.name.split("drone")[1].split("-")[0]
                nodePort = 30000 + int(drone_number)
                print(f"Service: {service.metadata.name}")
                command = f"kubectl port-forward svc/{service.metadata.name} {nodePort}:8080"
                
                thread = threading.Thread(target=run_command, args=(command,))
                thread.start()
                threads.append(thread)


        # Send a request to each service
        time.sleep(5)
        for service in services.items:
            if service.spec.type == "LoadBalancer" and service.metadata.name.startswith("drone"):
                drone_number = service.metadata.name.split("drone")[1].split("-")[0]
                nodePort = 30000 + int(drone_number)
                print(f"Service: {service.metadata.name}")

                for ingress in service.status.load_balancer.ingress:
                    url = f"http://127.0.0.1:{nodePort}"
                    print(f"Sending request to {url}")

                    process = subprocess.Popen(f"curl {url}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    print(process.stdout.read().decode())
        for process in processes:
            process.terminate()
        sys.exit(0)

    else:
        print("Not all pods are running")