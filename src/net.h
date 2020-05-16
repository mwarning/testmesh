
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

#endif // _NET_H
