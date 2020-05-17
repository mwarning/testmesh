
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#include "log.h"
#include "utils.h"
#include "net.h"
#include "unix.h"
#include "other.h"
#include "main.h"


//sudo setcap cap_net_admin,cap_net_raw=eip a.out

struct config *gconf = NULL;
float g_coords[3] = {NAN};
int g_sock_raw = -1;

struct interface {
  char *ifname;
  int ifindex;
  uint8_t mac[ETH_ALEN];
  int inbound_multicast_socket;
  int outbound_multicast_socket;
  struct interface *next;
};

struct neighbor {
	IP addr; // if set, send to IP address, or just an interface
	int ifindex; // if set, send multicast packet (or put in scope id?)
	float coords[3];
	struct neighbor *next;
};

/*
send to neighbor:
- over the internet (IP address)
- send to interface
*/

struct interface *g_interfaces = NULL;
struct neighbor *g_neighbors = NULL;

void add_neighbor(int ifindex, IP *addr)
{
	struct neighbor *neighbor = (struct neighbor *) malloc(sizeof(struct neighbor));
	neighbor->ifindex = ifindex;
	memcpy(&neighbor->addr, addr, sizeof(addr));
	neighbor->coords[0] = NAN;
	neighbor->coords[1] = NAN;
	neighbor->coords[2] = NAN;

	neighbor->next = g_neighbors;
	g_neighbors = neighbor;
}

void add_interface(const char *ifname)
{
  struct interface *interface = (struct interface *) malloc(sizeof(struct interface));
  memset(interface, 0, sizeof(struct interface));
  interface->ifname = strdup(ifname);
  
  interface->next = g_interfaces;
  g_interfaces = interface;
}

struct in6_addr get_ip_addr(int sockfd, const char *ifname)
{
    struct ifreq ifr;
     
    /*AF_INET - to define network interface IPv4*/
    /*Creating soket for it.*/
    //fd = socket(AF_INET, SOCK_DGRAM, 0);
	/*AF_INET - to define IPv4 Address type.*/
    ifr.ifr_addr.sa_family = AF_INET6;
     
    /*eth0 - define the ifr_name - port name
    where network attached.*/
    memcpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
     
    /*Accessing network interface information by
    passing address using ioctl.*/
    ioctl(sockfd, SIOCGIFADDR, &ifr);
     
    /*Extract IP Address*/
    //strcpy(ip_address,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    return ((struct sockaddr_in6*)&ifr.ifr_addr)->sin6_addr;
}

struct in6_addr inet6_addr(const char* s) {
	struct in6_addr addr;
	inet_pton(AF_INET6, s, &addr);
	return addr;
}

//https://www.tenouk.com/Module41c.html
void setup_multicast_outbound_sockets6(struct interface *interface)
{
	struct in6_addr localInterface;
	struct sockaddr_in6 groupSock;

	int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
	  perror("Opening datagram socket error");
	  exit(1);
	}

	/* Initialize the group sockaddr structure with a */
	/* group address of 225.1.1.1 and port 5555. */
	memset((char *) &groupSock, 0, sizeof(groupSock));
	groupSock.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "ff12::1234", &groupSock.sin6_addr);
	groupSock.sin6_port = htons(4321);

	int loopch = 0;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch)) < 0) {
		perror("Setting IP_MULTICAST_LOOP error");
		close(fd);
		exit(1);
	}

	/* Set local interface for outbound multicast datagrams. */
	/* The IP address specified must be associated with a local, */
	/* multicast capable interface. */

	int ifindex = interface->ifindex;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
      perror("Setting local interface error");
	  exit(1);
	}

	interface->outbound_multicast_socket = fd;
}

int setup_multicast_inbound_sockets6(struct interface *interface)
{
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);

	int reuse = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
		perror("Setting SO_REUSEADDR error");
		close(fd);
		return 1;
	}

	// BIND
	struct sockaddr_in6 address = {AF_INET6, htons(4321)};
	if (bind(fd, (struct sockaddr*)&address, sizeof address) < 0) {
		perror("Binding datagram socket error");
		close(fd);
		return 1;
	}

	// JOIN MEMBERSHIP
	struct ipv6_mreq group;
	//group.ipv6mr_multiaddr = get_ip_addr(fd, interface->ifname);
	group.ipv6mr_interface = interface->ifindex;
	inet_pton(AF_INET6, "ff12::1234", &group.ipv6mr_multiaddr);
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group, sizeof group) < 0) {
		perror("Adding multicast group error");
		close(fd);
		return 1;
	}

	interface->inbound_multicast_socket = fd;
}

int setup_interface(struct interface *interface)
{
  struct ifreq if_idx;
  struct ifreq if_mac;

  /* Get the index of the interface to send on */
  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, interface->ifname, IFNAMSIZ-1);
  if (ioctl(g_sock_raw, SIOCGIFINDEX, &if_idx) < 0) {
	  perror("SIOCGIFINDEX");
	  return 1;
	}

  /* Get the MAC address of the interface to send on */
  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, interface->ifname, IFNAMSIZ-1);
  if (ioctl(g_sock_raw, SIOCGIFHWADDR, &if_mac) < 0) {
      perror("SIOCGIFHWADDR");
      return 1;
  }

  interface->ifindex = if_idx.ifr_ifindex;
  memcpy(&interface->mac, (uint8_t *)&if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

	setup_multicast_outbound_sockets6(interface);
	setup_multicast_inbound_sockets6(interface);

  return 0;
}

int setup_tun(int sockfd, const char *ifname)
{
	//int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
	ifr.ifr_mtu = 1500; // Change value if it needed
	if(!ioctl(sockfd, SIOCSIFMTU, &ifr)) {
	  // Mtu changed successfully
	  perror("SIOCSIFMTU");
      return 1;
	}
	/*
	if(!ioctl(sock, SIOCGIFMTU, &if_mtu)) {
	  ifr.ifr_mtu // Contains current mtu value
	}*/
	return 0;
}

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev, O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

static int _ioctl_v6 = -1;

static int _set_base_tunnel_up(const char* name) {
  struct ifreq ifr;
  int oldflags;

  if (_ioctl_v6 < 0) {
      _ioctl_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
      if (_ioctl_v6 == -1) {
        log_error("Node is not IPv6 capable");
        return 1;
      }
  }

  // make sure base interface is up for incoming tunnel traffic
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, name, IF_NAMESIZE);

  if (ioctl(_ioctl_v6, SIOCGIFFLAGS, &ifr) < 0) {
    log_warning("ioctl SIOCGIFFLAGS (get flags) error on device %s: %s (%d)\n", name,
      strerror(errno), errno);
    return 1;
  }

  oldflags = ifr.ifr_flags;
  ifr.ifr_flags |= IFF_UP;

  if (oldflags == ifr.ifr_flags) {
    // interface is already up/down
    return 0;
  }

  if (ioctl(_ioctl_v6, SIOCSIFFLAGS, &ifr) < 0) {
    log_warning("ioctl SIOCSIFFLAGS (set flags up) error on device %s: %s (%d)\n", name,
      strerror(errno), errno);
    return 1;
  }

  return 0;
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(const char *progname) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

void outbound_multicast(int events, int fd) {
	//printf("outbound_multicast %d\n", events);

	static time_t last = 0; 
	if (gconf->time_now == last) {
		return;
	} else {
		last = gconf->time_now;
	}

	struct sockaddr_in6 groupSock;
	memset((char *) &groupSock, 0, sizeof(groupSock));
	groupSock.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "ff12::1234", &groupSock.sin6_addr);
	groupSock.sin6_port = htons(4321);

	const char *msg = "hello";
	if (sendto(fd, msg, strlen(msg) + 1, 0, (struct sockaddr*)&groupSock, sizeof(groupSock)) > 0) {
		printf("send: hello\n");
	}

	// send raw..

	// let's try to send via raw socket
	uint8_t dmac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	struct interface* interface = g_interfaces;
	while (interface) {
		send_packet(g_sock_raw, interface->ifindex, interface->mac, dmac, msg, strlen(msg) + 1);
		interface = interface->next;
	}
}

void inbound_multicast(int events, int fd) {
	//printf("inbound_multicast %d\n", events);
	if (events <= 0) {
		return;
	}

	char buf[200];
	int n = read(fd, buf, sizeof(buf));
	if (n > 0) {
		printf("received: %.*s\n", n, buf);
	}
}

void tap_handle(int events, int fd)
{
	if (events <= 0) {
		return;
	}
}

int main(int argc, char *argv[]) {
  struct config config = {0};
  config.is_running = 1;
  config.use_syslog = 0;
  config.af = AF_INET;
  config.verbosity = VERBOSITY_DEBUG,

  gconf = &config;

  int tap_fd, option;
  int flags = IFF_TAP; // IFF_TUN;
  char entry_if[IFNAMSIZ] = "tun0";

  /* Check command line options */
  while((option = getopt(argc, argv, "i:h")) > 0) {
    switch(option) {
      case 'h':
        usage(argv[0]);
        break;
      case 'i':
      	printf("add interface: %s\n", optarg);
        add_interface(optarg);
        //strncpy(entry_if, optarg, IFNAMSIZ-1);
        break;
      default:
        log_error("Unknown option %c", option);
        usage(argv[0]);
    }
  }

  argv += optind;
  argc -= optind;

  if (argc > 0) {
    log_error("Too many options!");
    usage(argv[0]);
  }

  if (*entry_if == '\0') {
    log_error("Must specify interface name!");
    usage(argv[0]);
  }


  //socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  if ((g_sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
      perror("socket");
      return 1;
  }

  unix_signals();

	struct interface *interface = g_interfaces;
	while (interface) {
		log_info("setup %s", interface->ifname);
	  setup_interface(interface);
	  net_add_handler(interface->outbound_multicast_socket, &outbound_multicast);
	  net_add_handler(interface->inbound_multicast_socket, &inbound_multicast);
	  interface = interface->next;
	}

  /* initialize tun/tap interface */
  if ((tap_fd = tun_alloc(entry_if, flags | IFF_NO_PI)) < 0 ) {
    log_error("Error connecting to tun/tap interface %s!", entry_if);
    exit(1);
  }

  _set_base_tunnel_up(entry_if);

  log_debug("Successfully connected to interface %s", entry_if);

  net_add_handler(tap_fd, &tap_handle);

  net_loop();

  return 0;
}
