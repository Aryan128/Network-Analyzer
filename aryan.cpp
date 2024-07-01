#include <pcap.h>
#include <iostream>
#include <cstring>
using namespace std;
// Callback function to be called by pcap_loop() for every captured packet
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    cout << "Packet capture length: " << pkthdr->caplen << std::endl;
    cout << "Packet total length: " << pkthdr->len << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *device;
    pcap_t *handle;

    // Get the list of available devices
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    // Print available devices
    cout << "Available devices are:" << endl;
    for (device = interfaces; device != NULL; device = device->next) {
        cout<<"[*]" << device->name << endl;
    }

    // Choose the first device
    if (interfaces == NULL) {
        cerr << "No devices found." << std::endl;
        return 1;
    }

    // Open the device for packet capture
    handle = pcap_open_live(interfaces->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Could not open device " << interfaces->name << ": " << errbuf << std::endl;
        return 1;
    }

    // Capture packets
    pcap_loop(handle, 10, packetHandler, NULL);

    // Close the session
    pcap_close(handle);
    pcap_freealldevs(interfaces);

    return 0;
}

