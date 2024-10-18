#include "rrt.hpp"

std::atomic<bool> server_running(true);

RRT::RRT() : droneRouting(std::stoi(std::getenv("PARAM2")), std::stoi(std::getenv("PARAM3"))) {
    this->type = FOLLOWER;
    this->drone_id = "drone" + std::string(std::getenv("PARAM1")) + "-service.default";
    this->x = 0;
    this->y = 0;
    this->controller_addr = "http://" + std::string(std::getenv("CONTROLLER_ADDR")) + ":8080";
    this->last_update = std::chrono::steady_clock::now() - this->update_interval;
}

RRT::~RRT() {
    server_running = false;
}

void RRT::run_server(int port) {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")
    .methods("GET"_method, "POST"_method)
    ([this](const crow::request& req) {
        if (req.method == crow::HTTPMethod::Post) {
            auto json = crow::json::load(req.body);
            if (!json) {
                return crow::response(400, "Invalid JSON");
            }

            bool is_leader = json["is_leader"].b();
            if (is_leader) {
                std::vector<int> partition;
                if (json.has("partition")) {
                    for (const auto& item : json["partition"]) {
                        partition.push_back(item.i());
                    }
                }
                std::cout << "Received leader info. Partition: ";
                for (const auto& item : partition) {
                    std::cout << item << " ";
                }
                std::cout << std::endl;

                nlohmann::json socket_data;
                socket_data["is_leader"] = true;
                socket_data["message_type"] = MessageType::LEADER_UPDATE;
                socket_data["leader_id"] = this->drone_id;

                this->type = LEADER;
                this->partition = std::make_tuple(std::make_tuple(partition[0], partition[1]), std::make_tuple(partition[2], partition[3]));
                this->droneRouting.broadcast(socket_data.dump());
            } else {
                std::cout << "Received follower info" << std::endl;
            }

            nlohmann::json response;
            response["status"] = "Info received";
            response["is_leader"] = is_leader;
            return crow::response(200, response.dump());
        } else {
            nlohmann::json response;
            response["status"] = "Drone service is running";
            return crow::response(200, response.dump());
        }
    });

    app.port(port).multithreaded().run();
}

void RRT::recv_data() {
    int port = 60137;
    int server_socket;
    int client_socket;
    const char* host = "127.0.0.1";
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(host);
    address.sin_port = htons(port);

    // Binding the socket to the port
    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listening for connections
    if (listen(server_socket, 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on " << host << ":" << port << std::endl;

    while(true) {
        // Accept a new connection
        if ((client_socket = accept(server_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        // Receive and process messages
        std::string message;
        char buffer[1024];
        ssize_t bytes_received;

        while(true) {
            bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) {
                if (bytes_received == 0) {
                    std::cout << "Client disconnected" << std::endl;
                } else {
                    perror("recv");
                }
                close(client_socket);
                break;
            }

            for (ssize_t i = 0; i < bytes_received; ++i) {
                if (buffer[i] == '\n') {
                    // End of message, process it
                    std::cout << "Received: " << message << std::endl;
                    this->message_queue.push(message);
                    message.clear();
                } else {
                    message += buffer[i];
                }
            }
        }
    }

    close(server_socket);
}

void RRT::process_messages() {
    std::string msg;
    while(this->message_queue.pop(msg)) {
        try {
            auto json = nlohmann::json::parse(msg);
            if (json["message_type"] == MessageType::LEADER_UPDATE) {
                if (this->type == LEADER) {
                    return;
                }

                if ((std::chrono::steady_clock::now() - last_update) >= update_interval) {
                    std::cout << "Received leader update" << std::endl;
                    this->last_update = std::chrono::steady_clock::now();
                    this->leader_id = json["leader_id"];

                    nlohmann::json socket_data;
                    socket_data["message_type"] = MessageType::FOLLOWER_DATA;
                    socket_data["follower_id"] = this->drone_id;
                    this->droneRouting.send(this->leader_id, socket_data.dump(), true);
                    this->droneRouting.broadcast(msg);
                }

            } else if (json["message_type"] == MessageType::FOLLOWER_DATA) {
                std::cout << "Received follower data" << std::endl;
                this->followers.insert({json["follower_id"].get<std::string>(), true});

            } else if (json["message_type"] == MessageType::LOCATION_UPDATE) {
                std::cout << "Location update received" << std::endl;
                this->last_update = std::chrono::steady_clock::now();
                cout << "We are a " << this->type << endl;

                if (this->type == LEADER) {
                    int drone_id = json["drone-id"].get<int>();
                    std::string drone_name = "drone" + std::to_string(drone_id) + "-service.default";
                    
                    if (this->followers.find(drone_name) != this->followers.end()) {
                        this->followers[drone_name] = true;
                        for (auto& row : this->grid) {
                            for (auto& cell : row) {
                                if (cell == drone_id) {
                                    cell = 0;
                                }
                            }
                        }
                        this->grid[json["x"].get<int>()][json["y"].get<int>()] = drone_id;
                        
                        std::cout << "Updated grid:" << std::endl;
                        for (const auto& row : this->grid) {
                            for (const auto& cell : row) {
                                std::cout << cell << " ";
                            }
                            std::cout << std::endl;
                        }
                    }
                } else {
                    if (json["leader-id"] == this->leader_id) {
                        nlohmann::json socket_data;
                        socket_data["message_type"] = MessageType::LOCATION_UPDATE;
                        socket_data["drone-id"] = std::atoi(std::getenv("PARAM1"));
                        socket_data["x"] = this->x;
                        socket_data["y"] = this->y;
                        this->droneRouting.send(this->leader_id, socket_data.dump(), true);
                    }
                }

            } else if (json["message_type"] == MessageType::TASK_ASSIGNMENT) {
                std::cout << "Received task assignment" << std::endl;
                this->last_update = std::chrono::steady_clock::now();
            }
        } catch (const std::exception& e) {
            std::cerr << "Error processing message: " << e.what() << std::endl;
            std::cerr << "Raw message: " << msg << std::endl;
        }
    }
}

void RRT::modify_coords(int x, int y) {
    nlohmann::json socket_data;
    socket_data["drone-id"] = std::atoi(std::getenv("PARAM1"));
    socket_data["x"] = x;
    socket_data["y"] = y;

    try {
        // Parse the controller address to get host and port
        std::string host = this->controller_addr;
        std::string path = "/update_coords";
        if (host.substr(0, 7) == "http://") {
            host = host.substr(7);
        } else if (host.substr(0, 8) == "https://") {
            host = host.substr(8);
        }

        size_t colonPos = host.find(':');
        int port = 80; // Default HTTP port
        if (colonPos != std::string::npos) {
            port = std::stoi(host.substr(colonPos + 1));
            host = host.substr(0, colonPos);
        }

        // Initialize the client
        httplib::Client cli(host, port);

        // Prepare headers
        httplib::Headers headers = {
            {"Content-Type", "application/json"}
        };

        // Perform the POST request
        auto res = cli.Post(path, headers, socket_data.dump(), "application/json");

        if (res) {
            if (res->status == 200) {
                nlohmann::json responseJson = nlohmann::json::parse(res->body);
                std::cout << responseJson << std::endl;
            } else {
                std::cerr << "Error: Received status code " << res->status << ". Message: " << res->body << std::endl;
            }
        } else {
            std::cerr << "Error: Unable to perform the request" << std::endl;
        }
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error sending data to controller: " << e.what() << std::endl;
    }
}

void RRT::get_controller_coords() {
    httplib::Client cli(this->controller_addr.c_str());

    auto res = cli.Get("/coords");
    if (res && res->status == 200) {
        json data = json::parse(res->body);
        grid_size = data["matrix"].size();
        grid = std::vector<std::vector<int>>(grid_size, std::vector<int>(grid_size, 0));

        std::cout << "Grid Size: " << grid_size << std::endl;

        std::string param1 = std::getenv("PARAM1") ? std::getenv("PARAM1") : "";
        std::regex pattern("drone(\\d+)");
        std::smatch matches;
        std::string search_string = "drone" + param1 + "-service.default";
        if (std::regex_search(search_string, matches, pattern)) {
            int int_grid_representation = std::stoi(matches[1]);

            for (int i = 0; i < grid_size; ++i) {
                for (int j = 0; j < data["matrix"][i].size(); ++j) {
                    if (data["matrix"][i][j] == int_grid_representation) {
                        this->x = i;
                        this->y = j;
                        std::cout << "Initial coordinates: (" << i << ", " << j << ")" << std::endl;
                    }
                }
            }
        }
    } else {
        std::cerr << "Error fetching data: " << (res ? res->status : 0) << std::endl;
    }
}

void RRT::logic_loop() {
    while (server_running) {
        if (this->type == LEADER) {
            // Leader logic
            nlohmann::json socket_data;
            socket_data["message_type"] = MessageType::LOCATION_UPDATE;
            socket_data["leader-id"] = this->drone_id;
            this->droneRouting.broadcast(socket_data.dump());

            std::this_thread::sleep_for(std::chrono::seconds(5)); // Wait for updates

            // iterate through followers and generate paths for those that are true
            // for (const auto& follower : this->followers) {
            //     if (follower.second) {
            //         // Generate path
            //         // Send task assignment
            //         nlohmann::json task_data;
            //         task_data["message_type"] = MessageType::TASK_ASSIGNMENT;
            //         this->droneRouting.send(follower.first, task_data.dump(), true);
            //     }
            // }
        } else {
            std::this_thread::sleep_for(std::chrono::seconds(15));
        }
    }
}

void RRT::start() {
    std::thread server_thread(&RRT::run_server, this, 8080);
    std::thread recv_thread(&RRT::recv_data, this);
    std::thread process_thread(&RRT::process_messages, this);
    this->get_controller_coords();
    std::thread logic_thread(&RRT::logic_loop, this);
    this->droneRouting.start();
    server_thread.join();
}

int main() {
    RRT rrt;
    rrt.start();

    return 0;
}