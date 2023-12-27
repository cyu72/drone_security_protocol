import random

droneNum = int(input("Total number of drones in swarm: "))
imagePullLocation = int(input("1): DockerHub\n2): Local\nImage pull location: "))
if imagePullLocation == 1:
    droneImage = "cyu72/drone:latest"
    gcsImage = "cyu72/gcs:latest"
elif imagePullLocation == 2:
    droneImage = "docker.io/library/drone:latest"
    gcsImage = "docker.io/library/gcs:latest"

delim = "---\n"

with open('droneDeployment.yml', 'w') as file:
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
        - protocol: UDP
          containerPort: 65456
"""
        service = f"""apiVersion: v1
kind: Service
metadata:
  name: drone{num}-service
spec:
  selector:
    app: drone{num}
    tier: drone
  ports:
  - protocol: UDP
    port: 80
    targetPort: 65456
"""
        file.write(drone)
        file.write(delim)
        file.write(service)
        file.write(delim)

        
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
    
    file.write(gcs + "\n")

    broadcastService = """apiVersion: v1
kind: Service
metadata:
  name: drone-broadcast-service
  namespace: default
spec:
  clusterIP: None
  selector:
    tier: drone
  ports:
    - protocol: UDP
      port: 80
      targetPort: 65456"""
    
    file.write(delim)
    file.write(broadcastService)
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

n = 9  # size of the matrix
matrix = generate_random_matrix(n, droneNum)

for row in matrix:
  for element in row:
    print(element, end=' ')
  print()

with open('deploymentNetworkPolicy.yml', 'w') as file:
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
        - {{key: app, operator: In, values: [gcs, {', '.join(['drone' + str(neighbor) for neighbor in neighbors])}]}}
        - {{key: tier, operator: In, values: [drone]}}"""
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
