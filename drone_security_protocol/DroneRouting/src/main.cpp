#include <memory>
#include <routing/drone.hpp>

int main() {
    try {
        auto d = std::make_unique<drone>(
            std::stoi(std::getenv("PORT")), 
            std::stoi(std::getenv("NODE_ID"))
        );
        // d->getSignal().wait();
        d->start();
        return 0;
    } catch (const std::exception& e) {
        createLogger("startup")->critical(e.what());
        return 1;
    }
}