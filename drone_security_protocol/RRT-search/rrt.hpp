#pragma once
#include <cstdlib>
#include "crow.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>
#include <tuple>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <cpr/cpr.h>
#include <regex>
#include <functional>
#include "../DroneRouting/include/routing/drone.hpp"

enum DRONE_TYPE {
    LEADER,
    FOLLOWER
};

enum MessageType  {
    LEADER_UPDATE,
    FOLLOWER_DATA,
    LOCATION_UPDATE,
    TASK_ASSIGNMENT
};

class MessageQueue {
private:
    std::queue<std::string> queue;
    std::mutex mutex;
    std::condition_variable cond;
    std::atomic<bool> running{true};

public:
    void push(const std::string& msg) {
        std::unique_lock<std::mutex> lock(mutex);
        queue.push(msg);
        cond.notify_one();
    }

    bool pop(std::string& msg) {
        std::unique_lock<std::mutex> lock(mutex);
        cond.wait(lock, [this] { return !queue.empty() || !running; });
        if (!running && queue.empty()) return false;
        msg = std::move(queue.front());
        queue.pop();
        return true;
    }

    void stop() {
        running = false;
        cond.notify_all();
    }
};

class RRT {
    public:
        RRT();
        ~RRT();
        void start();
    
    private:
        drone droneRouting;
        DRONE_TYPE type;
        std::string drone_id;
        std::string leader_id;
        MessageQueue message_queue;
        int x;
        int y;
        
        int grid_size;
        std::vector<std::vector<int>> grid;
        std::tuple<std::tuple<int, int>, std::tuple<int, int>> partition;
        std::vector<std::string> followers;

        std::string controller_addr;

        void run_server(int port);
        void recv_data();
        void process_messages();

        void modify_coords(int, int);
        void get_controller_coords();
        void logic_loop();

        // Leader Functions
        void update_map(); // data parameter
        void plan_path();
        void assign_task();

        // Follower Functions
        void follow_path();
        void report_location(); // is this needed?
};