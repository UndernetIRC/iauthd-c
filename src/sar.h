/* sar.h - srvx asynchronous resolver
 *
 * Copyright 2005 Michael Poole <mdpoole@troilus.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(SAR_H_f8daebef_2041_478f_9c01_b302c5e1521d)

/** Multiple-inclusion guard for "src/sar.h". */
#define SAR_H_f8daebef_2041_478f_9c01_b302c5e1521d

#if !defined(HAVE_STRUCT_ADDRINFO)

struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};

#endif /* !defined(HAVE_STRUCT_ADDRINFO) */

#if !defined(HAVE_STRUCT_SOCKADDR_STORAGE)

# define sockaddr_storage sockaddr_in
# define ss_family sin_family

#endif /* !defined(HAVE_STRUCT_SOCKADDR_STORAGE) */

#define SAI_NUMERICHOST 0x01 /* simply translate address from text form */
#define SAI_CANONNAME   0x02 /* fill in canonical name of host */
#define SAI_PASSIVE     0x04 /* if node==NULL, use unspecified address */
#define SAI_V4MAPPED    0x08 /* accept v4-mapped IPv6 addresses */
#define SAI_ALL         0x10 /* return both IPv4 and IPv6 addresses */
#define SAI_NOSRV       0x20 /* suppress SRV even if default is to use it */
#define SAI_FORCESRV    0x40 /* force SRV request even if questionable */

#define SNI_NOFQDN      0x01 /* omit domain name for local hosts */
#define SNI_NUMERICHOST 0x02 /* do not resolve address, just translate to text */
#define SNI_NAMEREQD    0x04 /* indicate error if no name exists */
#define SNI_NUMERICSERV 0x08 /* return service in numeric form */
#define SNI_DGRAM       0x10 /* return service names for UDP use */
#define SNI_PARANOID    0x20 /* confirm forward resolution of name */

enum sar_errcode {
    SAI_SUCCESS,
    SAI_FAMILY,
    SAI_SOCKTYPE,
    SAI_BADFLAGS,
    SAI_NONAME,
    SAI_SERVICE,
    SAI_ADDRFAMILY,
    SAI_NODATA,
    SAI_MEMORY,
    SAI_FAIL,
    SAI_AGAIN,
    SAI_MISMATCH,
    SAI_SYSTEM
};

struct sar_request;

void sar_init(void);
const char *sar_strerror(enum sar_errcode errcode);
void sar_abort(struct sar_request *cookie);

int sar_get_port(const struct sockaddr *sa, unsigned int socklen);
int sar_set_port(struct sockaddr *sa, unsigned int socklen, unsigned short port);
unsigned int sar_pton(struct sockaddr *sa, unsigned int socklen, unsigned int *bits, const char *input);
typedef void (*sar_addr_cb)(void *ctx, struct addrinfo *res, enum sar_errcode errcode);
struct sar_request *sar_getaddr(const char *node, const char *service, const struct addrinfo *hints, sar_addr_cb cb, void *cb_ctx) MALLOC_LIKE;
void sar_free(struct addrinfo *ai);

/** Maximum value returnable by sar_ntop(). */
#define SAR_NTOP_MAX 40
unsigned int sar_ntop(char *output, unsigned int out_size, const struct sockaddr *sa, unsigned int socklen);
typedef void (*sar_name_cb)(void *ctx, const char *host, const char *serv, enum sar_errcode errcode);
struct sar_request *sar_getname(const struct sockaddr *sa, socklen_t salen, int flags, sar_name_cb cb, void *cb_ctx) MALLOC_LIKE;

#endif /* !defined(SAR_H_f8daebef_2041_478f_9c01_b302c5e1521d) */
