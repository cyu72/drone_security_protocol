#include <optional>

template <typename Key, typename Value>
class MapQueue {
public:
    // Insert a key-value pair into the MapQueue
    void insert(const Key& key, const Value& value) {
        if (map.find(key) == map.end()) {
            queue.push(key);
        }
        map[key] = value;
    }

    Value& operator[](const Key& key) {
        /* Returns reference to value if found, otherwise inserts a default value and returns a reference. */
        if (map.find(key) == map.end()) {
            queue.push(key);
        }
        return map[key];
    }

    Value* get(const Key& key) {
        /* Returns pointer to value if found. Else returns nullptr. */
        auto it = map.find(key);
        if (it == map.end()) {
            return nullptr;
        }
        return &(it->second);
    }


    bool find(const Key& key) {
        /* Returns true if key is found. Else returns false. */
        return map.find(key) != map.end();
    }

    // Remove the oldest element (FIFO order)
    void dequeue() {
        if (queue.empty()) {
            throw std::out_of_range("Queue is empty");
        }
        Key key = queue.front();
        queue.pop();
        map.erase(key);
    }

    bool empty() const {
        return queue.empty();
    }

    // Get the size of the MapQueue
    size_t size() const {
        return queue.size();
    }

    // Get the front element (FIFO order)
    Value front() const {
        if (queue.empty()) {
            throw std::out_of_range("Queue is empty");
        }
        Key key = queue.front();
        return map.at(key);
    }

    void print() const {
        for (const auto& pair : map) {
            std::cout << "Key: " << pair.first << ", Value: " << pair.second << std::endl;
        }
    }

private:
    std::unordered_map<Key, Value> map;
    std::queue<Key> queue;
};
