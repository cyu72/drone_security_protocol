import time, sys
import subprocess
from kubernetes import client, config
import subprocess
import threading

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
            time.sleep(3)
            break

    if all_running:
        print("All pods are running")
        for service in services.items:
            if service.spec.type == "LoadBalancer" and service.metadata.name.startswith("drone"):
                drone_number = service.metadata.name.split("drone")[1].split("-")[0]
                nodePort = 30000 + int(drone_number)
                print(f"Service: {service.metadata.name}")
                command = f"kubectl port-forward svc/{service.metadata.name} {nodePort}:8080"
                
                thread = threading.Thread(target=run_command, args=(command,))
                thread.start()
                threads.append(thread)

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