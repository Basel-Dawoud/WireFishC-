#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <getopt.h>

using namespace std;

class ApplicationProtocol {
public:
    virtual ~ApplicationProtocol() = default;
    virtual void parse(const u_char* data, size_t length) = 0;
    virtual void print() const = 0;
};

class TextProtocol : public ApplicationProtocol {
protected:
    vector<string> parseLines(const u_char* data, size_t length) {
        string payload(data, data + length);
        vector<string> lines;
        size_t pos = 0;
        while (pos < payload.length()) {
            size_t end = payload.find("\r\n", pos);
            if (end == string::npos) break;
            lines.push_back(payload.substr(pos, end - pos));
            pos = end + 2;
        }
        return lines;
    }
};

class HTTPProtocol : public TextProtocol {
    vector<string> lines;
public:
    void parse(const u_char* data, size_t length) override {
        lines = parseLines(data, length);
    }
    void print() const override {
        cout << "HTTP:" << endl;
        for (const auto& line : lines)
            cout << "  " << line << endl;
    }
};

class FTPProtocol : public TextProtocol {
    string command;
public:
    void parse(const u_char* data, size_t length) override {
        auto lines = parseLines(data, length);
        if (!lines.empty()) command = lines[0];
    }
    void print() const override {
        cout << "FTP Command: " << command << endl;
    }
};

class DNSProtocol : public ApplicationProtocol {
    struct DNSHeader {
        uint16_t id;
        uint16_t flags;
        uint16_t questions;
    } header;
public:
    void parse(const u_char* data, size_t length) override {
        if (length >= sizeof(header))
            memcpy(&header, data, sizeof(header));
    }
    void print() const override {
        cout << "DNS: ID=" << ntohs(header.id)
             << " Questions=" << ntohs(header.questions) << endl;
    }
};

class PacketProcessor {
    struct EtherHeader {
        array<u_char, 6> dst;
        array<u_char, 6> src;
        uint16_t type;
    };

    struct IPHeader {
        uint8_t ihl;
        uint8_t version;
        uint8_t ttl;
        uint8_t protocol;
        string src;
        string dst;
        const u_char* payload;
        size_t length;
    };

    struct TCPHeader {
        uint16_t src_port;
        uint16_t dst_port;
        const u_char* payload;
        size_t length;
    };

    struct UDPHeader {
        uint16_t src_port;
        uint16_t dst_port;
        const u_char* payload;
        size_t length;
    };

    void parse_eth(const u_char* data) {
        EtherHeader eth;
        memcpy(&eth, data, sizeof(eth));
        eth.type = ntohs(eth.type);
        if (eth.type != ETHERTYPE_IP) return;
        parse_ip(data + sizeof(EtherHeader));
    }

    void parse_ip(const u_char* data) {
        const ip* iph = reinterpret_cast<const ip*>(data);
        IPHeader hdr;
        hdr.ihl = iph->ip_hl * 4;
        hdr.version = iph->ip_v;
        hdr.ttl = iph->ip_ttl;
        hdr.protocol = iph->ip_p;
        hdr.src = inet_ntoa(iph->ip_src);
        hdr.dst = inet_ntoa(iph->ip_dst);
        hdr.payload = data + hdr.ihl;
        hdr.length = ntohs(iph->ip_len) - hdr.ihl;

        cout << "IP: " << hdr.src << " -> " << hdr.dst
             << " TTL:" << static_cast<int>(hdr.ttl) << endl;

        switch (hdr.protocol) {
            case IPPROTO_TCP: parse_tcp(hdr.payload, hdr.length); break;
            case IPPROTO_UDP: parse_udp(hdr.payload, hdr.length); break;
            case IPPROTO_ICMP: cout << "ICMP Packet" << endl; break;
        }
    }

    void parse_tcp(const u_char* data, size_t length) {
        const tcphdr* tcph = reinterpret_cast<const tcphdr*>(data);
        TCPHeader hdr;
        hdr.src_port = ntohs(tcph->th_sport);
        hdr.dst_port = ntohs(tcph->th_dport);
        size_t hdr_len = tcph->th_off * 4;
        hdr.payload = data + hdr_len;
        hdr.length = length - hdr_len;

        cout << "TCP: " << hdr.src_port << " -> " << hdr.dst_port << endl;

        unique_ptr<ApplicationProtocol> app;
        if (hdr.dst_port == 80 || hdr.src_port == 80)
            app = make_unique<HTTPProtocol>();
        else if (hdr.dst_port == 21 || hdr.src_port == 21)
            app = make_unique<FTPProtocol>();
        else if (hdr.dst_port == 53 || hdr.src_port == 53)
            app = make_unique<DNSProtocol>();

        if (app && hdr.length > 0) {
            app->parse(hdr.payload, hdr.length);
            app->print();
        }
    }

    void parse_udp(const u_char* data, size_t length) {
        const udphdr* udph = reinterpret_cast<const udphdr*>(data);
        UDPHeader hdr;
        hdr.src_port = ntohs(udph->uh_sport);
        hdr.dst_port = ntohs(udph->uh_dport);
        hdr.payload = data + sizeof(udphdr);
        hdr.length = length - sizeof(udphdr);

        cout << "UDP: " << hdr.src_port << " -> " << hdr.dst_port << endl;

        if (hdr.dst_port == 53 || hdr.src_port == 53) {
            DNSProtocol dns;
            dns.parse(hdr.payload, hdr.length);
            dns.print();
        }
    }

public:
    void process(const u_char* data, size_t length) {
        parse_eth(data);
    }
};

class Sniffer {
    string interface;
    string filter;
    pcap_t* handle;

    void setup_filter() {
        bpf_program fp;
        if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            cerr << "Filter error: " << pcap_geterr(handle) << endl;
            exit(1);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            cerr << "Filter set error: " << pcap_geterr(handle) << endl;
            exit(1);
        }
    }

public:
    Sniffer(string iface, string filt) : interface(move(iface)), filter(move(filt)) {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            cerr << "Couldn't open device: " << errbuf << endl;
            exit(1);
        }
        setup_filter();
    }

    void start() {
        pcap_loop(handle, 0, [](u_char*, const pcap_pkthdr* h, const u_char* bytes) {
            cout << "\nPacket captured (" << h->len << " bytes)" << endl;
            PacketProcessor().process(bytes, h->len);
        }, nullptr);
    }

    ~Sniffer() { pcap_close(handle); }
};

void usage() {
    cout << "Usage: wirefish [options]\n"
         << "Options:\n"
         << "  -i <interface> Network interface\n"
         << "  -f <filter>    BPF filter expression\n"
         << "  -h             Show this help\n";
}

int main(int argc, char* argv[]) {
    string interface = "eth0";
    string filter;

    int opt;
    while ((opt = getopt(argc, argv, "i:f:h")) != -1) {
        switch (opt) {
            case 'i': interface = optarg; break;
            case 'f': filter = optarg; break;
            case 'h': usage(); return 0;
            default: usage(); return 1;
        }
    }

    try {
        Sniffer sniffer(interface, filter);
        sniffer.start();
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}
