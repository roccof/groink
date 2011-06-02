#ifndef GROINK_PCAP_UTIL
#define GROINK_PCAP_UTIL

#define CAP_SNAPLEN 65535
#define CAP_TIMEOUT 0 /* ms */

pcap_t *pcap_init(char *iface, int snaplen, int promisc, int rfmon, int cap_timeout);
void pcap_cleanup(pcap_t *pcap);

#endif /* GROINK_PCAP_UTIL */
