docker network build AODV (init network bridge first)

# Steps
1) Generate docker compose file first (determines how many drones)
2) Push image to dockerhub 
3) docker compose up

# individual containers:
docker build -t cyu72/<image-name>:latest -f <path-to-dockerfile> .
docker run --name <container-name> <image-name>

# Various docker compose commands
docker compose up 
docker compose up --build
docker compose up -d && docker attach <container-name> (Makes terminal interactive and accept input into container)
docker compose up -t myapp:latest (tagging images)

# minikube calico start up (Utilizes Callico as K8s network plugin)
1) minikube start --network-plugin=cni
2) kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml 
3) [Check cluster is ready] while true; do kubectl get pods -l k8s-app=calico-node -A; sleep 2; done 
4) [Or on Linux] watch kubectl get pods -l k8s-app=calico-node -A

# kubernetes
Delete pods: kubectl delete pods --all
Check pods: kubectl get pods
Check pods description: kubectl describe pods [pods-name]
Apply Kubernetes file: kubectl apply -f [deployment.yaml]
Connect to container (-it flag if interactive): kubectl attach <container name>

