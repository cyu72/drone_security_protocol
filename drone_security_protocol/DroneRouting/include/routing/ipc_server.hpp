#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <functional>

class IPCServer {
private:
    int server_fd;
    int port;
    struct sockaddr_in address;
    const int MAX_CONNECTIONS = 10;
    const int BUFFER_SIZE = 1024;
    std::thread server_thread;
    std::atomic<bool> running{false};
    std::function<void(const std::string&)> data_callback;

    void setupServer() {
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            throw std::runtime_error("Socket creation failed");
        }

        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            throw std::runtime_error("setsockopt failed");
        }

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            throw std::runtime_error("Bind failed");
        }

        if (listen(server_fd, MAX_CONNECTIONS) < 0) {
            throw std::runtime_error("Listen failed");
        }

        std::cout << "Server listening on port " << port << std::endl;
    }

    void serverLoop() {
        int addrlen = sizeof(address);
        
        while (running) {
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(server_fd, &readfds);

            int activity = select(server_fd + 1, &readfds, NULL, NULL, &timeout);
            
            if (activity < 0) {
                if (!running) break;
                throw std::runtime_error("Select error");
            }
            
            if (activity == 0) continue;

            if (FD_ISSET(server_fd, &readfds)) {
                int new_socket;
                if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
                                       (socklen_t*)&addrlen)) < 0) {
                    if (!running) break;
                    throw std::runtime_error("Accept failed");
                }

                std::cout << "Connection accepted" << std::endl;

                char buffer[BUFFER_SIZE] = {0};
                int valread = read(new_socket, buffer, BUFFER_SIZE);
                if (valread > 0) {
                    std::string received_data(buffer, valread);
                    std::cout << "Received: " << received_data << std::endl;
                    
                    // Call the callback function if it exists
                    if (data_callback) {
                        data_callback(received_data);
                    }
                    
                    // Send response
                    const char* response = "Message received";
                    send(new_socket, response, strlen(response), 0);
                }

                close(new_socket);
            }
        }
    }

public:
    IPCServer(int port, std::function<void(const std::string&)> callback = nullptr) 
        : port(port), server_fd(-1), data_callback(callback) {
        setupServer();
    }

    void setCallback(std::function<void(const std::string&)> callback) {
        data_callback = callback;
    }

    void start() {
        if (!running) {
            running = true;
            server_thread = std::thread(&IPCServer::serverLoop, this);
            std::cout << "Server thread started" << std::endl;
        }
    }

    void stop() {
        if (running) {
            running = false;
            if (server_thread.joinable()) {
                server_thread.join();
            }
            std::cout << "Server thread stopped" << std::endl;
        }
    }

    ~IPCServer() {
        stop();
        if (server_fd != -1) {
            close(server_fd);
            std::cout << "Server shutdown" << std::endl;
        }
    }
};