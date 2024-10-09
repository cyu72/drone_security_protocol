# distutils: language = c++
# distutils: sources = /app/drone_security_protocol/src/drone.cpp /app/drone_security_protocol/src/hashTree.cpp /app/drone_security_protocol/src/tesla.cpp
# distutils: include_dirs = /app/drone_security_protocol/include /app/drone_security_protocol/include/routing /app/drone_security_protocol/include/routing/network_adapters /app/drone_security_protocol/build/_deps/nlohmann_json-src/include

from libcpp.string cimport string
from libcpp cimport bool

cdef extern from "/app/drone_security_protocol/include/routing/drone.hpp":
    cdef cppclass drone:
        drone(int port, int nodeID) except +
        void start()
        int send(const string&, string, bool)
        void broadcast(const string&)

cdef class DroneRouting:
    cdef drone* c_drone
    cdef bint owned

    def __cinit__(self, int port=0, int nodeID=0):
        self.c_drone = new drone(port, nodeID)
        self.owned = True

    def __dealloc__(self):
        if self.owned:
            del self.c_drone

    def start(self):
        self.c_drone.start()

    def send(self, str destination, str message):
        print(f"Python send: drone object at {<unsigned long>self.c_drone}")
        return self.c_drone.send(destination.encode('utf-8'), message.encode('utf-8'), True)

    def broadcast(self, str message):
        print(f"Python broadcast: drone object at {<unsigned long>self.c_drone}")
        self.c_drone.broadcast(message.encode('utf-8'))

# Additional wrapper functions for other methods can be added here as needed