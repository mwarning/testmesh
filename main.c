
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

#include "log.h"
#include "utils.h"
#include "net.h"
#include "unix.h"
#include "main.h"


/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000

struct config *gconf = NULL;

struct interface {
  char *ifname;
  int ifindex;
  uint8_t mac[ETH_ALEN];
  int inbound_multicast_socket;
  int outbound_multicast_socket;
  struct interface *next;
};

struct interface *interfaces = NULL;

void add_interface(const char *ifname)
{
  struct interface *interface = (struct interface *) malloc(sizeof(struct interface));
  memset(interface, 0, sizeof(struct interface));
  interface->ifname = strdup(ifname);
  
  interface->next = interfaces;
  interfaces = interface;
}

struct in_addr get_ip_addr(int sockfd, const char *ifname)
{
	//unsigned char ip_address[15];
    struct ifreq ifr;
     
    /*AF_INET - to define network interface IPv4*/
    /*Creating soket for it.*/
    //fd = socket(AF_INET, SOCK_DGRAM, 0);
	/*AF_INET - to define IPv4 Address type.*/
    ifr.ifr_addr.sa_family = AF_INET;
     
    /*eth0 - define the ifr_name - port name
    where network attached.*/
    memcpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
     
    /*Accessing network interface information by
    passing address using ioctl.*/
    ioctl(sockfd, SIOCGIFADDR, &ifr);
     
    /*Extract IP Address*/
    //strcpy(ip_address,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
     return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
}

//https://www.tenouk.com/Module41c.html
void setup_multicast_outbound_sockets(struct interface *interface)
{
	struct in_addr localInterface;
	struct sockaddr_in groupSock;

	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
	  perror("Opening datagram socket error");
	  exit(1);
	}

	/* Initialize the group sockaddr structure with a */
	/* group address of 225.1.1.1 and port 5555. */
	memset((char *) &groupSock, 0, sizeof(groupSock));
	groupSock.sin_family = AF_INET;
	groupSock.sin_addr.s_addr = inet_addr("226.1.1.1");
	groupSock.sin_port = htons(4321);

	char loopch = 0;
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch)) < 0) {
		perror("Setting IP_MULTICAST_LOOP error");
		close(sd);
		exit(1);
	}

	/* Set local interface for outbound multicast datagrams. */
	/* The IP address specified must be associated with a local, */
	/* multicast capable interface. */
	struct in_addr addr = get_ip_addr(sd, interface->ifname);
	localInterface.s_addr = addr.s_addr; //inet_addr("203.106.93.94");
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localInterface, sizeof(localInterface)) < 0) {
	  perror("Setting local interface error");
	  exit(1);
	}

	interface->outbound_multicast_socket = sd;
}

int setup_multicast_inbound_sockets(struct interface *interface)
{
	struct ip_mreq group;

	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	int reuse = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
		perror("Setting SO_REUSEADDR error");
		close(sd);
		return 1;
	}
	struct sockaddr_in localSock;

	/* Bind to the proper port number with the IP address */

	/* specified as INADDR_ANY. */

	memset((char *) &localSock, 0, sizeof(localSock));
	localSock.sin_family = AF_INET;
	localSock.sin_port = htons(4321);
	localSock.sin_addr.s_addr = INADDR_ANY;

	if (bind(sd, (struct sockaddr*)&localSock, sizeof(localSock))) {
		perror("Binding datagram socket error");
		close(sd);
		return 1;
	}

	/* Join the multicast group 226.1.1.1 on the local 203.106.93.94 */
	/* interface. Note that this IP_ADD_MEMBERSHIP option must be */
	/* called for each local interface over which the multicast */
	/* datagrams are to be received. */

	group.imr_multiaddr.s_addr = inet_addr("226.1.1.1");
	struct in_addr addr = get_ip_addr(sd, interface->ifname);
	{
		char str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &addr, str, sizeof(str));
		printf("listen for inbound multicast: %s (%s)\n", str, interface->ifname);
	}
	group.imr_interface.s_addr = addr.s_addr; //inet_addr("203.106.93.94");

	if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0) {
		perror("Adding multicast group error");
		close(sd);
		return 1;
	}


	interface->inbound_multicast_socket = sd;

	return 0;
}

int setup_interface(int sockfd, struct interface *interface)
{
  struct ifreq if_idx;
  struct ifreq if_mac;

  /* Get the index of the interface to send on */
  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, interface->ifname, IFNAMSIZ-1);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
	  perror("SIOCGIFINDEX");
	  return 1;
	}

  /* Get the MAC address of the interface to send on */
  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, interface->ifname, IFNAMSIZ-1);
  if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
      perror("SIOCGIFHWADDR");
      return 1;
  }

  interface->ifindex = if_idx.ifr_ifindex;
  memcpy(&interface->mac, (uint8_t *)&if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

	setup_multicast_outbound_sockets(interface);
	setup_multicast_inbound_sockets(interface);

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

int send_packet(int sockfd, int ifindex, uint8_t smac[ETH_ALEN], uint8_t dmac[ETH_ALEN], uint8_t* payload, int payload_len)
{
  char sendbuf[BUFSIZE];

  struct ether_header *eh = (struct ether_header *) sendbuf;
  memcpy(&eh->ether_shost, smac, ETH_ALEN);
  memcpy(&eh->ether_dhost, dmac, ETH_ALEN);
  eh->ether_type = htons(ETH_P_IP);

  memcpy(sendbuf + sizeof(struct ether_header), payload, payload_len);

  struct sockaddr_ll socket_address = {
    // Index of the network device
    .sll_ifindex = ifindex,
    // Address length
    .sll_halen = ETH_ALEN,
    // Destination MAC
    .sll_addr = *dmac // does it write all elements?
  };

  // send packet
  if (sendto(sockfd, sendbuf, sizeof(struct ether_header) + payload_len, 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
      printf("Send failed\n");
  }
}

//https://stackoverflow.com/questions/12177708/raw-socket-promiscuous-mode-not-sniffing-what-i-write
int interface_socket(const char *ifname)
{
	int fd;
	struct ifreq ifr;
	struct sockaddr_ll interfaceAddr;
	struct packet_mreq mreq;

	if ((fd = socket(PF_PACKET,SOCK_RAW, htons(ETH_P_ALL))) < 0)
	    return -1;

	memset(&interfaceAddr,0,sizeof(interfaceAddr));
	memset(&ifr,0,sizeof(ifr));
	memset(&mreq,0,sizeof(mreq));

	memcpy(&ifr.ifr_name,ifname,IFNAMSIZ);
	ioctl(fd,SIOCGIFINDEX,&ifr);

	interfaceAddr.sll_ifindex = ifr.ifr_ifindex;
	interfaceAddr.sll_family = AF_PACKET;

	if (bind(fd, (struct sockaddr *)&interfaceAddr,sizeof(interfaceAddr)) < 0)
	    return -2;

	mreq.mr_ifindex = ifr.ifr_ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 6;

	if (setsockopt(fd,SOL_PACKET,PACKET_ADD_MEMBERSHIP,
	     (void*)&mreq,(socklen_t)sizeof(mreq)) < 0)
	        return -3;

	return fd;
}

/*
unsigned char buf[1500];
struct sockaddr_ll addr;
socklen_t addr_len = sizeof(addr);
n = recvfrom(fd, buf, 2000, 0, (struct sockaddr*)&addr, &addr_len);
if (n <= 0)
{
    //Error reading
}
else if (addr.sll_pkttype == PACKET_OUTGOING)
{
    //The read data are not writing by me.
    //Use only this data to copy in the other network.
}
*/

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

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
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

void parse_ip(uint8_t *buf, int len)
{
  if (len <= 40) {
    printf("packet too small: %d", len);
    return;
  }

	hexDump (NULL, buf, len);

	// check IP version
  if (((buf[0] >> 4) & 0xff) != 6) {
    printf("not an IPv6 packet\n");
    return;
  }

    struct ip6_hdr *hdr = (struct ip6_hdr*) buf;

    int payload_len = ntohs(*((uint16_t*) &buf[4]));
    uint8_t *payload = (uint8_t*) &buf[40];
    uint8_t next_header = buf[7];
    char srcip[INET6_ADDRSTRLEN];
    char dstip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &buf[8], srcip, sizeof(srcip));
    inet_ntop(AF_INET6, &buf[24], dstip, sizeof(dstip));
    log_info("%s => %s (%d)", srcip, dstip, payload_len);

    if (40 + payload_len != len) {
      printf("size mismatch\n");
      return;
    }

  switch (next_header) {
    case 0:
      printf("HOPOPT\n");
      break;
    case 1:
      printf("ICMP\n");
      break;
    case 6:
      printf("TCP\n");
      break;
    case 17:
      printf("UDP\n");
      break;
    case 58:
      printf("HOPOPT\n");
    case 255:
      printf("Reserved\n");
    default:
      printf("%d\n", next_header);
      break;
  }

  switch (payload[0]) {
    case 133:
      printf("Router Solicitation\n");
      break;
    case 134:
      printf("Router Advertisement\n");
      break;
    case 135:
      printf("Neighbor Solicitation\n");
      break;
    case 136:
      printf("Neighbor Advertisement\n");
      break;
    case 137:
      printf("Redirect\n");
      break;
  }

  hexDump(NULL, payload, payload_len);

//if (payload[0] == 133) {
//	nwrite = cwrite(tap_fd, buf, nread);
//	}
}

void parse_ether(uint8_t *buf, int len)
{
	hexDump (NULL, buf, len);

	int ether_type = ntohs(*((uint16_t*) &buf[12]));
  	printf("mac %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx => %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
  		buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
  		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);

  	if (ether_type == 0x86DD) {
  		printf("ipv6 ether type\n");
  	} else {
  		printf("unknown ether_type\n");
  	}

  	parse_ip(buf + 14, len - 14);
}

void outbound_multicast(int events, int fd) {
	//printf("outbound_multicast %d\n", events);

	static time_t last = 0; 
	if (gconf->time_now == last) {
		return;
	} else {
		last = gconf->time_now;
	}

	struct sockaddr_in groupSock;
	memset((char *) &groupSock, 0, sizeof(groupSock));
	groupSock.sin_family = AF_INET;
	groupSock.sin_addr.s_addr = inet_addr("226.1.1.1");
	groupSock.sin_port = htons(4321);

	if (sendto(fd, "hello", 6, 0, (struct sockaddr*)&groupSock, sizeof(groupSock)) > 0) {
		printf("send: hello\n");
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
  int maxfd;
  uint16_t nwrite, plength;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

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

  int sockfd;
  //socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
      perror("socket");
      return 1;
  }

  unix_signals();

	struct interface *interface = interfaces;
	while (interface) {
		log_info("setup %s", interface->ifname);
	  setup_interface(sockfd, interface);
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

  net_loop();

  return 0;

  maxfd = tap_fd;

  while (1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set);
    //FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR) {
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if (FD_ISSET(tap_fd, &rd_set)) {
      /* data from tun/tap: just read it and write it to the network */
      
      int nread = cread(tap_fd, buffer, BUFSIZE);

      if (flags & IFF_TAP) {
      	parse_ether(buffer, nread);
      } else {
      	parse_ip(buffer, nread);
      }

      /* write length + packet */
      //plength = htons(nread);
      //nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
      //nwrite = cwrite(net_fd, buffer, nread);

      //do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

#if 0
    if(FD_ISSET(net_fd, &rd_set)) {
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      /* Read length */      
      nread = read_n(net_fd, (char *)&plength, sizeof(plength));
      if(nread == 0) {
        /* ctrl-c at the other end */
        break;
      }

      net2tap++;

      /* read packet */
      nread = read_n(net_fd, buffer, ntohs(plength));
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, nread);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
#endif
  }
  
  return(0);
}
