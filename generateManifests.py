droneNum = int(input("Total number of drones in swarm: "))

delim = "---\n"

with open('droneDeployment.yml', 'w') as file:
    for num in range(1, droneNum + 1):
        drone = f"""apiVersion: v1
kind: Pod
metadata:
  name: drone{num}
spec:
  containers: 
    - name: drone{num}
      image: cyu72/drone:latest
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
        file.write(drone)
        file.write(delim)

        
    gcs = """apiVersion: v1
kind: Pod
metadata:
  name: gcs
spec:
  containers: 
    - name: gcs
      image: cyu72/gcs:latest
      ports:
      - protocol: UDP
        containerPort: 65456"""

    file.write(gcs)