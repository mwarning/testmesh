
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>


// Number of elements in an array
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Size of a struct element
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

// Make a symbol into a string literal
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

// for convenience to store MAC addresses
#define AF_MAC 99

struct mac {
    uint8_t data[6];
};

struct macaddr {
    sa_family_t family;
    struct mac addr;
    uint32_t ifindex;
};

// wrapper for MAC and IP addresses
typedef union {
    sa_family_t family;
    struct macaddr mac;
    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;
} Address;

typedef struct {
	const char *name;
	uint16_t num_args;
	uint16_t code;
} option_t;

const option_t *find_option(const option_t options[], const char name[]);
int setargs(const char **argv, int argv_size, char *args);

int decrease_ip_ttl(const void *data, size_t length);
bool match(const char *argv[], const char *pattern); // matches a single argument
int levenshtein(const uint8_t *s1, size_t s1len, const uint8_t *s2, size_t s2len);
uint32_t adler32(const void *buf, size_t buflen); // a hash method
bool hex_dump(char *dst, size_t dstlen, const void *buf, size_t buflen);
ssize_t bytes_random(void *buffer, size_t size); // get random bytes
uint32_t get_ip_connection_fingerprint(const uint8_t *buf, size_t buflen); // get unique id for IP connection pair
bool is_newer_seqnum(uint16_t cur, uint16_t new);
bool parse_hex(uint64_t *ret, const char *val, int bytes);
char *bytes_to_base16(char dst[], size_t dstsize, const uint8_t src[], size_t srcsize);

uint64_t time_millis_now();
uint32_t time_millis_resolution();

uint16_t address_scope(const Address *addr);
bool address_is_null(const Address *addr);
bool address_is_unicast(const Address *addr);
bool address_is_multicast(const Address *addr);
bool address_is_broadcast(const Address *addr);
bool address_equal(const Address *a, const Address *b);
uint32_t address_ifindex(const Address *addr);

const char *str_af(int af);
const char *str_onoff(bool value);
const char *str_yesno(bool value);
const char *str_bool(bool value);
const char *str_mac(const struct mac *addr);
const char *str_bytes(uint64_t bytes);
const char *str_time(uint64_t ms);
const char *str_duration(uint64_t from_ms, uint64_t to_ms);
const char *str_since(uint64_t ms);
const char *str_until(uint64_t ms);
const char *str_addr(const Address *addr);
const char *str_addr6(const struct sockaddr_in6 *addr);

const char *str_in4(const struct in_addr *addr);
const char *str_in6(const struct in6_addr *addr);

uint32_t addr_cmp_subnet(const struct sockaddr *addr1, const struct sockaddr *addr2, uint32_t subnet_len);
bool addr_is_localhost(const struct sockaddr *addr);
bool addr_is_multicast(const struct sockaddr *addr);
bool addr_is_linklocal(const struct sockaddr *addr);
bool addr_parse(struct sockaddr *addr, const char full_addr_str[], const char default_port[], uint32_t af);
uint16_t addr_port_get(const struct sockaddr *addr);
bool addr_port_set(struct sockaddr *addr, uint16_t port);
socklen_t addr_length(const struct sockaddr *addr);

#endif // _UTILS_H_
