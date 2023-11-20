droneNum = int(input("Total number of drones in swarm: "))

with open('./docker-compose.yml', 'w') as file:
    init = """version: '3'
services:"""

    file.write(init)
    for num in range(1, droneNum + 1):
        drone = f"""
    drone{num}:
        build:
            context: ./src
            dockerfile: Dockerfile.drone
        image: drone:latest
        environment:
            PARAM1: drone{num}
            PARAM2: 65456
            PARAM3: {num}
        networks:
            - AODV
    """
        file.write(drone)
        
    gcs = """
    groundControlService:
        build:
            context: ./src
            dockerfile: Dockerfile.gcs
        image: gcs:latest
        stdin_open: true  
        tty: true  
        networks:
            - AODV\n"""
    
    network = """
networks:
    AODV:
        name: AODV
        external: true"""

    file.write(gcs + network)