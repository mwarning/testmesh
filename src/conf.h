
#ifndef _CONF_H_
#define _CONF_H_

const char *verbosity_str(int verbosity);
int verbosity_int(const char *verbosity);

int conf_setup(int argc, char **argv);

#endif // _CONF_H_
