droneNum = int(input("Total number of drones in swarm: "))

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
  dnsPolicy: ClusterFirst
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

        
    gcs = """apiVersion: v1
kind: Pod
metadata:
  name: gcs
  namespace: default
  labels:
    app: gcs
    tier: drone
spec:
  hostname: gcs
  dnsPolicy: ClusterFirst
  containers: 
    - name: gcs
      image: cyu72/gcs:latest
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
  selector:
    tier: drone
  ports:
    - protocol: UDP
      port: 80
      targetPort: 65456"""
    
    file.write(delim)
    file.write(broadcastService)
    file.close()