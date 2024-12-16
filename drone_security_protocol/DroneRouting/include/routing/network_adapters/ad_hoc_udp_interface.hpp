#ifndef ADHOC_UDP_INTERFACE_HPP
#define ADHOC_UDP_INTERFACE_HPP

#include <string>
#include <stdexcept>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <unistd.h>
#include <cstring>

class UDPInterface {
public:
    UDPInterface(int port, const char* interface = "wlan0") {
        if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            throw std::runtime_error("Socket creation failed");
        }

        int broadcast = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
            close(sock);
            throw std::runtime_error("Failed to set broadcast option");
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
            close(sock);
            throw std::runtime_error("Failed to bind to interface");
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            throw std::runtime_error("Bind failed");
        }
    }

    ~UDPInterface() { close(sock); }

    void broadcast(const std::string& msg) {
        addr.sin_addr.s_addr = INADDR_BROADCAST;
        if (sendto(sock, msg.c_str(), msg.size(), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            throw std::runtime_error("Broadcast failed");
        }
    }

    std::string receiveFrom(struct sockaddr_in& client_addr) {
        char buffer[1024];
        socklen_t addr_len = sizeof(client_addr);
        
        int n = recvfrom(sock, buffer, sizeof(buffer)-1, 0, 
                        (struct sockaddr*)&client_addr, &addr_len);
        if (n < 0) throw std::runtime_error("Receive failed");
        
        buffer[n] = '\0';
        return std::string(buffer);
    }

private:
    int sock;
    struct sockaddr_in addr;
};

#endif