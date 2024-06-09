#include <iostream>
#include <unordered_map>
#include <chrono>
#include <string>
#include "routingTableEntry.hpp"

#ifndef ROUTING_MAP_HPP
#define ROUTING_MAP_HPP

using namespace std::chrono;

template <typename Key, typename Value>
class RoutingMap {
public:
    Value& operator[](const Key& key) {
        return map[key];
    }

    bool find(const Key& key) {
        /* Returns true if key is found. Else returns false. */
        return map.find(key) != map.end();
    }

    // Clean up old entries by removing entries with expired TTLs
    void cleanup() {
        auto now = std::chrono::system_clock::now();
        for (auto it = map.begin(); it != map.end(); ) {
            if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.ttl) > seconds(5)) {
                it = map.erase(it); // erase returns the iterator to the next element
            } else {
                ++it; // increment the iterator
            }
        }
    }

    Value* get(const Key& key) {
        /* Returns pointer to value if found. Else returns nullptr. */
        auto it = map.find(key);
        if (it == map.end()) {
            return nullptr;
        }
        return &(it->second);
    }

    void print() const {
        for (const auto& pair : map) {
            std::cout << "Key: " << pair.first << ", Value: " << pair.second << std::endl;
        }
    }

private:
    std::unordered_map<Key, Value> map;
};

#endif // ROUTING_MAP_HPP
