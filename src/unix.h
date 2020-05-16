
#ifndef _UNIX_H_
#define _UNIX_H_

void unix_signals(void);
void unix_fork(void);
int unix_create_unix_socket(const char path[], int *sock_out);
void unix_remove_unix_socket(const char path[], int sock_in);

#endif /* _UNIX_H_ */
