# Steps
1) Build docker image, tag & push to dockerhub
2) minikube start
3) apply manifests

# docker tag & push
docker build -t cyu72/<image-name>:latest -f <path-to-dockerfile> .
docker push cyu82/repository:tag

# docker local registry (doesnt work)
launch local registry: docker run -d -p 6000:5000 --name local_registry registry
build image in docker: tag and push image 
pull images from local registry: docker pull localhost:6000/image_name:tag
Example: docker push localhost:6000/image:tag
docker pull localhost:6000/image:tag

# minikube calico start up (With Calico and MetalLB)
1) minikube start --network-plugin=cni --cni=calico
2) kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml 
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml 
3) minikube addons enable metallb
4) [Check cluster is ready] while true; do kubectl get pods -l k8s-app=calico-node -A; sleep 2; done 
5) [Or on Linux] watch kubectl get pods -l k8s-app=calico-node -A

# kubernetes
Delete pods: kubectl delete pods --all <br>
Check pods: kubectl get pods
Check pods description: kubectl describe pods [pods-name]
Apply Kubernetes file: kubectl apply -f [deployment.yaml]
Connect to container (-it flag if interactive): kubectl attach <container name>

# helpful resources
https://www.yamllint.com/
https://kubebyexample.com/learning-paths/metallb/install

