


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

/*
      int nread = cread(tap_fd, buffer, BUFSIZE);

      if (flags & IFF_TAP) {
      	parse_ether(buffer, nread);
      } else {
      	parse_ip(buffer, nread);
      }
      */

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