# Steps
1) Build docker image, tag & push to dockerhub
2) minikube start
3) apply manifests

# docker tag & push
docker build -t cyu72/<image-name>:latest -f <path-to-dockerfile> .
docker push cyu82/repository:tag

# minikube local registry
build image in docker
minikube image load <image:latest>

# minikube calico start up (Utilizes Callico as K8s network plugin)
1) minikube start --network-plugin=cni --cni=calico
2) kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml 
3) [Check cluster is ready] while true; do kubectl get pods -l k8s-app=calico-node -A; sleep 2; done 
4) [Or on Linux] watch kubectl get pods -l k8s-app=calico-node -A

# kubernetes
Delete pods: kubectl delete pods --all <br>
Check pods: kubectl get pods
Check pods description: kubectl describe pods [pods-name]
Apply Kubernetes file: kubectl apply -f [deployment.yaml]
Connect to container (-it flag if interactive): kubectl attach <container name>

# helpful resources
https://www.yamllint.com/

