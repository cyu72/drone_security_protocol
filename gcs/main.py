import socket
from enum import IntEnum
import json
from abc import ABC, abstractmethod

PORT_NUMBER = 80
BRDCST_PORT = 65467

class MESSAGE_TYPE(IntEnum):
    ROUTE_REQUEST = 0
    ROUTE_REPLY = 1
    ROUTE_ERROR = 2
    DATA = 3
    INIT_ROUTE_DISCOVERY = 4
    VERIFY_ROUTE = 5
    HELLO = 6
    INIT_AUTO_DISCOVERY = 7
    EXIT = 8

class MESSAGE(ABC):
    def __init__(self, message_type):
        self.type = message_type

    @abstractmethod
    def serialize(self):
        pass

    @abstractmethod
    def deserialize(self, j):
        pass

class GCS_MESSAGE(MESSAGE):
    def __init__(self, src_addr="NILL", dest_addr="NILL", message_type=MESSAGE_TYPE.DATA):
        super().__init__(message_type)
        self.src_addr = src_addr
        self.dest_addr = dest_addr

    def serialize(self):
        j = {
            "type": int(self.type),  # Convert enum to int
            "srcAddr": self.src_addr,
            "destAddr": self.dest_addr,
        }
        print(json.dumps(j))
        return json.dumps(j)

    def deserialize(self, j):
        data = json.loads(j)
        self.type = MESSAGE_TYPE(data["type"])
        self.src_addr = data["srcAddr"]
        self.dest_addr = data["destAddr"]

class RREQ(MESSAGE):
    def __init__(self, src_addr="", dest_addr="", src_seq_num=0, dest_seq_num=0, hash_value="", hop_count=0, herr=0):
        super().__init__(MESSAGE_TYPE.ROUTE_REQUEST)
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.src_seq_num = src_seq_num
        self.dest_seq_num = dest_seq_num
        self.hash = hash_value
        self.hop_count = hop_count
        self.HERR = herr

    def serialize(self):
        j = {
            "type": self.type,
            "srcAddr": self.src_addr,
            "destAddr": self.dest_addr,
            "srcSeqNum": self.src_seq_num,
            "destSeqNum": self.dest_seq_num,
            "hash": self.hash,
            "hopCount": self.hop_count,
            "HERR": self.HERR
        }
        return json.dumps(j)

    def deserialize(self, j):
        data = json.loads(j)
        self.type = MESSAGE_TYPE(data["type"])
        self.src_addr = data["srcAddr"]
        self.dest_addr = data["destAddr"]
        self.src_seq_num = data["srcSeqNum"]
        self.dest_seq_num = data["destSeqNum"]
        self.hash = data["hash"]
        self.hop_count = data["hopCount"]
        self.HERR = data["HERR"]

class RREP(MESSAGE):
    def __init__(self, src_addr="", dest_addr="", src_seq_num=0, dest_seq_num=0, hash_value="", hop_count=0, herr=0):
        super().__init__(MESSAGE_TYPE.ROUTE_REPLY)
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.src_seq_num = src_seq_num
        self.dest_seq_num = dest_seq_num
        self.hash = hash_value
        self.hop_count = hop_count
        self.HERR = herr

    def serialize(self):
        j = {
            "type": self.type,
            "srcAddr": self.src_addr,
            "destAddr": self.dest_addr,
            "srcSeqNum": self.src_seq_num,
            "destSeqNum": self.dest_seq_num,
            "hash": self.hash,
            "hopCount": self.hop_count,
            "HERR": self.HERR
        }
        return json.dumps(j)

    def deserialize(self, j):
        data = json.loads(j)
        self.type = MESSAGE_TYPE(data["type"])
        self.src_addr = data["srcAddr"]
        self.dest_addr = data["destAddr"]
        self.src_seq_num = data["srcSeqNum"]
        self.dest_seq_num = data["destSeqNum"]
        self.hash = data["hash"]
        self.hop_count = data["hopCount"]
        self.HERR = data["HERR"]

def send_data(container_name, msg):
    try:
        # Get address info
        addrinfo = socket.getaddrinfo(container_name, PORT_NUMBER, socket.AF_INET, socket.SOCK_STREAM)
        
        # Use the first result
        family, socktype, proto, _, sockaddr = addrinfo[0]
        
        # Create socket
        with socket.socket(family, socktype, proto) as sock:
            # Connect to the server
            sock.connect(sockaddr)
            
            # Send data
            bytes_sent = sock.send(msg.encode())
            
            if bytes_sent == 0:
                print("No data was sent")
            
    except socket.gaierror as e:
        print(f"Error resolving host: {e}")
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    try:
        # Create a socket
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Allow reuse of address/port
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind the socket to a specific address and port
        server_address = ('', PORT_NUMBER)  # '' means INADDR_ANY
        listen_sock.bind(server_address)
        
        # Listen for incoming connections
        listen_sock.listen(5)
        
        print(f"GCS Server running on port {PORT_NUMBER}")
    
    except socket.error as e:
        print(f"Error: {e}")
        exit(1)

    while True:
            print("1) Initiate Route Discovery\n2) Print Route\n3) Send UDP Message\n4) Send auto-routed message\n5) Send to IP\n6) Exit")
            user_input = input("> ")

            if not user_input:
                continue

            try:
                choice = int(user_input)
            except ValueError:
                print("Invalid input. Please enter a number.")
                continue

            if choice == 1:
                drone_id = input("Enter drone ID [number]: ")
                if not drone_id:
                    print("No input received. Returning to main menu.")
                    continue
                container_name = f"drone{drone_id}-service.default"

                dest_id = input("Enter destination ID [number]: ")
                if not dest_id:
                    print("No input received. Returning to main menu.")
                    continue
                dest_addr = f"drone{dest_id}-service.default"

                if container_name == dest_addr:
                    print("Error: Cannot send message to self")
                    continue

                msg = GCS_MESSAGE(container_name, dest_addr, MESSAGE_TYPE.INIT_ROUTE_DISCOVERY)
                json_str = msg.serialize()
                send_data(container_name, json_str)

            elif choice == 2:
                drone_id = input("Enter drone ID [number]: ")
                if not drone_id:
                    print("No input received. Returning to main menu.")
                    continue
                container_name = f"drone{drone_id}-service.default"
                msg = GCS_MESSAGE(container_name, "NILL", MESSAGE_TYPE.VERIFY_ROUTE)
                json_str = msg.serialize()
                send_data(container_name, json_str)

            elif choice == 3:
                continue
            #     drone_id = input("Enter drone ID [number]: ")
            #     if not drone_id:
            #         print("No input received. Returning to main menu.")
            #         continue
            #     container_name = f"drone{drone_id}-service.default"
            #     json_str = input("Enter UDP message: ")
            #     if not json_str:
            #         print("No message entered. Returning to main menu.")
            #         continue
            #     send_data_udp(container_name, json_str)

            elif choice == 4:
                drone_id = input("Enter drone ID [number]: ")
                if not drone_id:
                    print("No input received. Returning to main menu.")
                    continue
                container_name = f"drone{drone_id}-service.default"
                dest_id = input("Enter destination ID [number]: ")
                if not dest_id:
                    print("No input received. Returning to main menu.")
                    continue
                dest_addr = f"drone{dest_id}-service.default"
                msg = GCS_MESSAGE("NILL", dest_addr, MESSAGE_TYPE.INIT_AUTO_DISCOVERY)
                json_str = msg.serialize()
                send_data(container_name, json_str)

            elif choice == 5:
                dest_addr = input("Enter IP address: ")
                if not dest_addr:
                    print("No IP address entered. Returning to main menu.")
                    continue
                json_str = input("Enter message: ")
                if not json_str:
                    print("No message entered. Returning to main menu.")
                    continue
                send_data(dest_addr, json_str)
            elif choice == 6:
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
