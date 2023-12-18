
#ifndef _CONSOLE_H
#define _CONSOLE_H

enum {
	CONSOLE_COMMAND_STATUS,
	CONSOLE_COMMAND_NEIGHBORS,
	CONSOLE_COMMAND_ROUTES,
};

// called from log.c
void console_log_message(const char *message);

void console_server_handler(int rc, int serversock);
void console_client_handler(int rc, int clientsock);

bool console_setup(void);
void console_free(void);

#endif // _CONSOLE_H
