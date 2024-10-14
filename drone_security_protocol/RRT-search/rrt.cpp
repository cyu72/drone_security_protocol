#include "rrt.hpp"

std::atomic<bool> server_running(true);

RRT::RRT() : droneRouting(std::stoi(std::getenv("PARAM2")), std::stoi(std::getenv("PARAM3"))) {
    this->type = FOLLOWER;
    this->drone_id = "drone" + std::string(std::getenv("PARAM1")) + "-service.default";
    this->x = 0;
    this->y = 0;
    this->controller_addr = "http://" + std::string(std::getenv("CONTROLLER_ADDR")) + ":8080";
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
    char buffer[1024] = {0};
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

        std::cout << "New connection accepted" << std::endl;

        // Receive and print messages
        while(true) {
            int valread = read(client_socket, buffer, 1024);
            if (valread <= 0) {
                if (valread == 0) {
                    std::cout << "Client disconnected" << std::endl;
                } else {
                    perror("read");
                }
                close(client_socket);
                break;
            }
            
            std::cout << "Received: " << std::string(buffer, valread) << std::endl;
            this->message_queue.push(std::string(buffer, valread));
            memset(buffer, 0, sizeof(buffer));
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
                std::cout << "Received leader update" << std::endl;
                this->leader_id = json["leader_id"];

                nlohmann::json socket_data;
                socket_data["message_type"] = MessageType::FOLLOWER_DATA;
                socket_data["follower_id"] = this->drone_id;
                this->droneRouting.send(this->leader_id, socket_data.dump(), true);

            } else if (json["message_type"] == MessageType::FOLLOWER_DATA) {
                std::cout << "Received follower data" << std::endl;
                this->followers.push_back(json["follower_id"]);

            } else if (json["message_type"] == MessageType::LOCATION_UPDATE) {
                std::cout << "Received location update" << std::endl;
                // this->x = json["x"];
                // this->y = json["y"];

            } else if (json["message_type"] == MessageType::TASK_ASSIGNMENT) {
                std::cout << "Received task assignment" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error processing message: " << e.what() << std::endl;
        }
    }
}

void RRT::modify_coords(int x, int y) { // Need to test
    nlohmann::json socket_data;
    socket_data["drone_id"] = this->drone_id;
    socket_data["x"] = x;
    socket_data["y"] = y;

    try {
        cpr::Response response = cpr::Post(
            cpr::Url{this->controller_addr + "/update_coords"},
            cpr::Body{socket_data.dump()},
            cpr::Header{{"Content-Type", "application/json"}}
        );

        if (response.status_code == 200) {
            cout << nlohmann::json::parse(response.text) << endl;
        } else {
            std::cerr << "Error: Received status code " << response.status_code << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error sending data to controller: " << e.what() << std::endl;
    }
}

void RRT::get_controller_coords() {
        cpr::Response response = cpr::Get(cpr::Url{this->controller_addr + "/coords"});
        if (response.status_code != 200) {
            std::cerr << "Error: Received status code " << response.status_code << std::endl;
        }

        json data = json::parse(response.text);
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
                    }
                }
            }
        }
    }

void RRT::logic_loop() {
    while (server_running) {
        if (this->type == LEADER) {
            // Leader logic
        } else {
            // Follower logic
        }
    }
}

void RRT::start() {
    std::thread server_thread(&RRT::run_server, this, 8080);
    std::thread recv_thread(&RRT::recv_data, this);
    std::thread process_thread(&RRT::process_messages, this);
    this->droneRouting.start();
    server_thread.join();
}

int main() {
    RRT rrt;
    rrt.start();

    return 0;
}