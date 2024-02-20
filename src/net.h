
#ifndef _NET_H
#define _NET_H


// Callback for event loop
typedef void net_callback(int revents, int fd);

// Set non blocking
int net_set_nonblocking(int fd);

// Add callback with file descriptor to listen for packets
void net_add_handler(int fd, net_callback *callback);

// Remove callback
void net_remove_handler(int fd, net_callback *callback);

// Start loop for all network events
void net_loop(void);

// Close sockets
void net_free(void);

int net_socket(const char name[], const char ifname[], const int protocol, const int af);
int net_bind(const char name[], const char addr[], const int port, const char ifname[], const int protocol);

#endif // _NET_H
