#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/member.hpp>

struct Packet {
    uint32_t seqNum;
    std::vector<uint8_t> data;
    std::vector<uint8_t> mac;
};

using namespace boost::multi_index;

typedef multi_index_container<
    Packet,
    indexed_by<
        ordered_unique<member<Packet, uint32_t, &Packet::seqNum>>
    >
> PacketStore;