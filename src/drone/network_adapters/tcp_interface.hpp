#ifndef TCP_SOCKET_HPP
#define TCP_SOCKET_HPP

#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <stdexcept>
#include <vector>
#include <fcntl.h>

class TCPInterface {
public:
    TCPInterface(int port, bool is_server = true) : is_server(is_server) {
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            throw std::runtime_error("TCP socket creation failed");
        }

        if (is_server) {
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_addr.s_addr = INADDR_ANY;
            server_addr.sin_port = htons(port);

            if (bind(sock, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                close(sock);
                throw std::runtime_error("TCP bind failed");
            }

            if (listen(sock, 5) < 0) {
                close(sock);
                throw std::runtime_error("TCP listen failed");
            }
        }
    }

    ~TCPInterface() {
        close(sock);
    }

    int accept_connection() {
        if (!is_server) {
            throw std::runtime_error("Cannot accept connections on a client socket");
        }

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(sock, (struct sockaddr *)&client_addr, &addr_len);

        if (client_sock < 0) {
            throw std::runtime_error("TCP accept failed");
        }

        return client_sock;
    }

    void connect_to(const std::string& host, int port) {
        if (is_server) {
            throw std::runtime_error("Cannot connect using a server socket");
        }

        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
        if (status != 0) {
            throw std::runtime_error("Error resolving host: " + std::string(gai_strerror(status)));
        }

        if (connect(sock, result->ai_addr, result->ai_addrlen) < 0) {
            freeaddrinfo(result);
            throw std::runtime_error("TCP connection failed");
        }

        freeaddrinfo(result);
    }

    void send_data(const std::string& msg, int client_sock = -1) {
        int target_sock = (client_sock == -1) ? sock : client_sock;
        ssize_t bytes_sent = send(target_sock, msg.c_str(), msg.size(), 0);
        if (bytes_sent < 0) {
            throw std::runtime_error("Error sending data: " + std::string(strerror(errno)));
        }
    }

    std::string receive_data(int client_sock = -1, size_t buffer_size = 1024) {
        int target_sock = (client_sock == -1) ? sock : client_sock;
        std::vector<char> buffer(buffer_size);
        ssize_t bytes_received = recv(target_sock, buffer.data(), buffer.size(), 0);

        if (bytes_received < 0) {
            throw std::runtime_error("Error receiving data: " + std::string(strerror(errno)));
        } else if (bytes_received == 0) {
            throw std::runtime_error("Connection closed by peer");
        }

        return std::string(buffer.data(), bytes_received);
    }

    void set_non_blocking(bool non_blocking) {
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags == -1) {
            throw std::runtime_error("Error getting socket flags");
        }

        if (non_blocking) {
            flags |= O_NONBLOCK;
        } else {
            flags &= ~O_NONBLOCK;
        }

        if (fcntl(sock, F_SETFL, flags) == -1) {
            throw std::runtime_error("Error setting socket flags");
        }
    }

private:
    int sock;
    struct sockaddr_in server_addr;
    bool is_server;
};

#endif // TCP_SOCKET_HPP