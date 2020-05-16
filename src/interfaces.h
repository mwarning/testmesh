#ifndef _INTERFACES_H_
#define _INTERFACES_H_

#include "utarray.h"

struct interface {
    int ifindex;
    const char *ifname;
    void *data;
};

void interfaces_init();
UT_array *get_interfaces();
int add_interface(const char *ifname);

void send_mcasts(const void* data, int data_len);
int send_mcast(int ifindex, const void* data, int data_len);

#endif /* _INTERFACES_H_ */