/* sar.c - srvx asynchronous resolver
 *
 * Copyright 2005, 2011 Michael Poole <mdpoole@troilus.org>
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

#include "src/common.h"

static const char hexdigits[] = "0123456789abcdef";

struct dns_rr;
struct sar_getaddr_state;
struct sar_getname_state;

struct sar_family_helper {
    const char *localhost_addr;
    const char *unspec_addr;
    unsigned int socklen;
    unsigned int family;

    unsigned int (*ntop)(char *output, unsigned int out_size, const struct sockaddr *sa, unsigned int socklen);
    unsigned int (*pton)(struct sockaddr *sa, unsigned int socklen, unsigned int *bits, const char *input);
    int (*get_port)(const struct sockaddr *sa, unsigned int socklen);
    int (*set_port)(struct sockaddr *sa, unsigned int socklen, unsigned short port);
    unsigned int (*build_addr_request)(struct sar_request *req, const char *node, const char *srv_node, unsigned int flags);
    void (*build_ptr_name)(struct sar_getname_state *state, const struct sockaddr *sa, unsigned int socklen);
    int (*decode_addr)(struct sar_getaddr_state *state, struct dns_rr *rr, unsigned char *raw, unsigned int raw_size);

    struct sar_family_helper *next;
};

#define MAX_FAMILY AF_INET
static struct sar_family_helper sar_ipv4_helper;

#if defined(AF_INET6)
# if AF_INET6 > MAX_FAMILY
#  undef MAX_FAMILY
#  define MAX_FAMILY AF_INET6
# endif
static struct sar_family_helper sar_ipv6_helper;
#endif

static struct sar_family_helper *sar_helpers[MAX_FAMILY+1];
static struct sar_family_helper *sar_first_helper;

unsigned int sar_ntop(char *output, unsigned int out_size, const struct sockaddr *sa, unsigned int socklen)
{
    unsigned int pos;

    assert(output != NULL);
    assert(sa != NULL);
    assert(out_size > 0);

    if (sa->sa_family <= MAX_FAMILY && sar_helpers[sa->sa_family]) {
        pos = sar_helpers[sa->sa_family]->ntop(output, out_size, sa, socklen);
        if (pos)
            return pos;
    }
    *output = '\0';
    return 0;
}

unsigned int sar_pton(struct sockaddr *sa, unsigned int socklen, unsigned int *bits, const char *input)
{
    struct sar_family_helper *helper;
    unsigned int len;

    assert(sa != NULL);
    assert(input != NULL);

    memset(sa, 0, socklen);
    if (bits)
        *bits = ~0;
    for (helper = sar_first_helper; helper; helper = helper->next) {
        if (socklen < helper->socklen)
            continue;
        len = helper->pton(sa, socklen, bits, input);
        if (len) {
            sa->sa_family = helper->family;
            return len;
        }
    }
    return 0; /* parse failed */
}

int sar_get_port(const struct sockaddr *sa, unsigned int socklen)
{
    if (sa->sa_family <= MAX_FAMILY
        && sar_helpers[sa->sa_family]
        && socklen >= sar_helpers[sa->sa_family]->socklen)
        return sar_helpers[sa->sa_family]->get_port(sa, socklen);
    else return -1;
}

int sar_set_port(struct sockaddr *sa, unsigned int socklen, unsigned short port)
{
    if (sa->sa_family <= MAX_FAMILY
        && sar_helpers[sa->sa_family]
        && socklen >= sar_helpers[sa->sa_family]->socklen)
        return sar_helpers[sa->sa_family]->set_port(sa, socklen, port);
    else return 1;
}

const char *sar_strerror(enum sar_errcode errcode)
{
    switch (errcode) {
    case SAI_SUCCESS: return "Resolution succeeded.";
    case SAI_FAMILY: return "The requested address family is not supported.";
    case SAI_SOCKTYPE: return "The requested socket type is not supported.";
    case SAI_BADFLAGS: return "Invalid flags value.";
    case SAI_NONAME: return "Unknown name or service.";
    case SAI_SERVICE: return "The service is unavailable for that socket type.";
    case SAI_ADDRFAMILY: return "The host has no address in the requested family.";
    case SAI_NODATA: return "The host has no addresses at all.";
    case SAI_MEMORY: return "Unable to allocate memory.";
    case SAI_FAIL: return "The nameserver indicated a permanent error.";
    case SAI_AGAIN: return "The nameserver indicated a temporary error.";
    case SAI_MISMATCH: return "Mismatch between reverse and forward resolution.";
    case SAI_SYSTEM: return strerror(errno);
    default: return "Unknown resolver error code.";
    }
}

void sar_free(struct addrinfo *ai)
{
    struct addrinfo *next;
    for (; ai; ai = next) {
        next = ai->ai_next;
        xfree(ai);
    }
}

/** Global variables to support DNS name resolution. */
static struct {
    struct conf_node_object *sar_root;
    struct conf_node_string *sar_timeout;
    struct conf_node_string *sar_retries;
    struct conf_node_string *sar_ndots;
    struct conf_node_string *sar_edns0;
    struct conf_node_string *sar_localdomain;
    struct conf_node_inaddr *sar_bind_address;
    struct conf_node_string_list *sar_search;
    struct conf_node_string_list *sar_nslist;
} conf;
static struct log_type *sar_log;

/* Except as otherwise noted, constants and formats are from RFC1035.
 * This resolver is believed to implement the behaviors mandated (and
 * in many cases those recommended) by these standards: RFC1035,
 * RFC2671, RFC2782, RFC3596, RFC3597.
 *
 * Update queries (including RFC 2136) seems a likely candidate for
 * future support.
 * DNSSEC (including RFCs 2535, 3007, 3655, etc) is less likely until
 * a good application is found.
 * Caching (RFC 2308) and redirection (RFC 2672) are much less likely,
 * since most users will have a separate local, caching, recursive
 * nameserver.
 * Other DNS extensions (at least through RFC 3755) are believed to be
 * too rare or insufficiently useful to bother supporting.
 *
 * The following are useful Reasons For Concern:
 * RFC1536, RFC1912, RFC2606, RFC3363, RFC3425, RFC3467
 * http://www.iana.org/assignments/dns-parameters
 * http://www.ietf.org/html.charters/dnsext-charter.html
 */

struct sar_nameserver {
    char *name;
    unsigned int valid;
    unsigned int req_sent;
    unsigned int resp_used;
    unsigned int resp_ignored;
    unsigned int resp_servfail;
    unsigned int resp_fallback;
    unsigned int resp_failures;
    unsigned int resp_scrambled;
    unsigned int ss_len;
    struct sockaddr_storage ss;
};

/** DNS message (request and response) header. */
struct dns_header {
    uint16_t id;
    uint16_t flags;
#define REQ_FLAG_QR           0x8000 /* response */
#define REQ_FLAG_OPCODE_MASK  0x7800 /* opcode mask */
#define REQ_FLAG_OPCODE_SHIFT 11     /* opcode shift count */
#define REQ_OPCODE_QUERY      (0 << REQ_FLAG_OPCODE_SHIFT)
#define REQ_FLAG_AA           0x0400 /* authoritative answer */
#define REQ_FLAG_TC           0x0200 /* truncated message */
#define REQ_FLAG_RD           0x0100 /* recursion desired */
#define REQ_FLAG_RA           0x0080 /* recursion available */
/* 0x0040 bit currently reserved and must be zero; 0x0020 and 0x0010
 * used by DNSSEC. */
#define REQ_FLAG_RCODE_MASK   0x000f /* response code mask */
#define REQ_FLAG_RCODE_SHIFT  0      /* response code shift count */
#define RCODE_NO_ERROR        0
#define RCODE_FORMAT_ERROR    1
#define RCODE_SERVER_FAILURE  2
#define RCODE_NAME_ERROR      3  /* aka NXDOMAIN (since RFC2308) */
#define RCODE_NOT_IMPLEMENTED 4
#define RCODE_REFUSED         5
#define RCODE_BAD_OPT_VERSION 16 /* RFC 2671 */
    uint16_t qdcount;  /* count of questions */
    uint16_t ancount;  /* count of answer RRs */
    uint16_t nscount;  /* count of NS (authority) RRs */
    uint16_t arcount;  /* count of additional RRs */
};

/* EDNS0 uses 12 bit RCODEs, TSIG/TKEY use 16 bit RCODEs.
 * Declare local RCODE failures here.*/
enum {
    RCODE_TIMED_OUT = 65536,
    RCODE_QUERY_TOO_LONG,
    RCODE_LABEL_TOO_LONG,
    RCODE_SOCKET_FAILURE,
    RCODE_DESTROYED,
};

/** DNS resource record. */
struct dns_rr {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint16_t rd_start;
    char *name;
};

#define DNS_NAME_LENGTH 256

#define REQ_TYPE_A     1
#define REQ_TYPE_NS    2
#define REQ_TYPE_CNAME 5
#define REQ_TYPE_SOA   6
#define REQ_TYPE_PTR   12
#define REQ_TYPE_MX    15
#define REQ_TYPE_TXT   16
#define REQ_TYPE_AAAA  28  /* RFC 3596 */
#define REQ_TYPE_SRV   33  /* RFC 2782 */
#define REQ_TYPE_OPT   41  /* RFC 2671 */
#define REQ_QTYPE_ALL  255
#define REQ_CLASS_IN   1
#define REQ_QCLASS_ALL 255

#define RES_SIZE_FLAGS 0xc0
#define RES_SF_LABEL   0x00
#define RES_SF_POINTER 0xc0

/** Pending request structure. */
struct sar_request {
    int id;
    struct timeval expiry;
    void (*cb_ok)(struct sar_request *req, struct dns_header *hdr, struct dns_rr *rr, unsigned char *raw, unsigned int raw_size);
    void (*cb_fail)(struct sar_request *req, unsigned int rcode);
    unsigned char *body;
    unsigned int body_len;
    unsigned char retries;
};

static struct set sar_requests;
static struct set sar_nameservers;
static struct event sar_fd;
static struct event sar_timeout;
static int sar_fd_fd;

#define TV_LESS(A, B) evutil_timercmp(&(A), &(B), <)

static void sar_request_send(struct sar_request *req);

const char *sar_rcode_text(unsigned int rcode)
{
    switch (rcode) {
    case RCODE_NO_ERROR: return "No error";
    case RCODE_FORMAT_ERROR: return "Format error";
    case RCODE_SERVER_FAILURE: return "Server failure";
    case RCODE_NAME_ERROR: return "Name error";
    case RCODE_NOT_IMPLEMENTED: return "Feature not implemented";
    case RCODE_REFUSED: return "Query refused";
    case RCODE_BAD_OPT_VERSION: return "Unsupported EDNS option version";
    case RCODE_TIMED_OUT: return "Request timed out";
    case RCODE_QUERY_TOO_LONG: return "Query too long";
    case RCODE_LABEL_TOO_LONG: return "Label too long";
    case RCODE_SOCKET_FAILURE: return "Resolver socket failure";
    case RCODE_DESTROYED: return "Request unexpectedly destroyed";
    default: return "Unknown rcode";
    }
}

static void sar_request_fail(struct sar_request *req, unsigned int rcode)
{
    log_message(sar_log, LOG_DEBUG, "sar_request_fail({id=%d}, rcode=%d)", req->id, rcode);
    req->expiry.tv_sec = 0;
    req->expiry.tv_usec = 0;
    if (req->cb_fail) {
        req->cb_fail(req, rcode);
        if (evutil_timerisset(&req->expiry))
            return;
    }
    sar_abort(req);
}

static void sar_timeout_cb(UNUSED_ARG(int fd), UNUSED_ARG(short event), void *timer)
{
    struct set_node *it;
    struct set_node *next;
    struct timeval next_timeout;
    struct timeval now;

    gettimeofday(&now, NULL);
    next_timeout.tv_sec = INT_MAX;
    next_timeout.tv_usec = 999999;
    for (it = set_first(&sar_requests); it; it = next) {
        struct sar_request *req;

        req = set_node_data(it);
        next = set_next(it);
        if (TV_LESS(next_timeout, req->expiry))
            continue;
        else if (TV_LESS(now, req->expiry))
            next_timeout = req->expiry;
        else if (req->retries >= conf.sar_retries->parsed.p_integer)
            sar_request_fail(req, RCODE_TIMED_OUT);
        else
            sar_request_send(req);
    }
    if (next_timeout.tv_sec < INT_MAX)
        evtimer_add(timer, &next_timeout);
}

static void sar_check_timeout(struct timeval when)
{
    if (!evutil_timerisset(&sar_timeout.ev_timeout))
    {
        evtimer_add(&sar_timeout, &when);
    }
    else if (TV_LESS(when, sar_timeout.ev_timeout))
    {
        evtimer_del(&sar_timeout);
        evtimer_add(&sar_timeout, &when);
    }
    /* else existing timeout is sooner */
}

static void sar_request_cleanup(void *d)
{
    struct sar_request *req = d;
    log_message(sar_log, LOG_DEBUG, "sar_request_cleanup({id=%d})", req->id);
    xfree(req->body);
    if (req->cb_fail)
        req->cb_fail(req, RCODE_DESTROYED);
}

static void sar_dns_init(const char *resolv_conf_path)
{
    FILE *resolv_conf;
    char *domain;
    char *timeout;
    char *retries;
    char *ndots;
    char *edns0;
    struct string_vector ns_sv, ds_sv;

    /* Initialize non-configuration values. */
    sar_requests.compare = set_compare_int;
    sar_requests.cleanup = sar_request_cleanup;
    sar_nameservers.compare = set_compare_charp;

    /* Initialize configuration defaults. */
    domain = NULL;
    timeout = xstrdup("3");
    retries = xstrdup("3");
    ndots = xstrdup("1");
    edns0 = xstrdup("0");
    string_vector_init(&ns_sv, 4);
    string_vector_init(&ds_sv, 4);

    /* Scan resolver configuration file.  */
    resolv_conf = fopen(resolv_conf_path, "r");
    if (resolv_conf) {
        char *arg, *opt;
        unsigned int len;
        char linebuf[LINE_MAX], ch;

        while (fgets(linebuf, sizeof(linebuf), resolv_conf)) {
            ch = linebuf[len = strcspn(linebuf, " \t\r\n")];
            linebuf[len] = '\0';
            arg = linebuf + len + 1;
            if (!strcmp(linebuf, "nameserver")) {
                while (ch == ' ') {
                    ch = arg[len = strcspn(arg, " \t\r\n")];
                    arg[len] = '\0';
                    string_vector_append(&ns_sv, xstrdup(arg));
                    arg += len + 1;
                }
            } else if (!strcmp(linebuf, "domain")) {
                if (ch == ' ') {
                    xfree(domain);
                    domain = xstrdup(arg);
                }
            } else if (!strcmp(linebuf, "search")) {
                while (ch == ' ') {
                    ch = arg[len = strcspn(arg, " \t\r\n")];
                    arg[len] = '\0';
                    string_vector_append(&ds_sv, xstrdup(arg));
                    arg += len + 1;
                }
            } else if (!strcmp(linebuf, "options")) {
                while (ch == ' ') {
                    ch = arg[len = strcspn(arg, " \t\r\n")];
                    arg[len] = '\0';
                    opt = strchr(arg, ':');
                    if (opt) {
                        *opt++ = '\0';
                        if (!strcmp(arg, "timeout")) {
                            xfree(timeout);
                            timeout = xstrdup(opt);
                        } else if (!strcmp(arg, "attempts")) {
                            xfree(retries);
                            retries = xstrdup(opt);
                        } else if (!strcmp(arg, "ndots")) {
                            xfree(ndots);
                            ndots = xstrdup(opt);
                        } else if (!strcmp(arg, "edns0")) {
                            xfree(edns0);
                            edns0 = xstrdup(opt);
                        }
                    } else if (!strcmp(arg, "edns0")) {
                        xfree(edns0);
                        edns0 = xstrdup("1440");
                    }
                    arg += len + 1;
                }
            }
        }
        fclose(resolv_conf);
    } else {
        /* This is apparently what BIND defaults to using. */
        string_vector_append(&ns_sv, "127.0.0.1");
    }

    /* Set default search path if domain is set. */
    if (domain != NULL && ds_sv.used == 0)
        string_vector_append(&ds_sv, xstrdup(domain));

    /* Register configuration entries. */
    conf.sar_timeout = conf_register_string(conf.sar_root, CONF_STRING_INTERVAL, "timeout", timeout);
    conf.sar_retries = conf_register_string(conf.sar_root, CONF_STRING_INTEGER, "retries", retries);
    conf.sar_ndots = conf_register_string(conf.sar_root, CONF_STRING_INTEGER, "ndots", ndots);
    conf.sar_edns0 = conf_register_string(conf.sar_root, CONF_STRING_INTEGER, "edns0", edns0 ? edns0 : "0");
    conf.sar_localdomain = conf_register_string(conf.sar_root, CONF_STRING_PLAIN, "domain", domain);
    conf.sar_bind_address = conf_register_inaddr(conf.sar_root, "bind_address", NULL, NULL);
    conf.sar_search = conf_register_string_list_sv(conf.sar_root, "search", &ds_sv);
    conf.sar_nslist = conf_register_string_list_sv(conf.sar_root, "nameservers", &ns_sv);

    /* Clean up temporary allocations. */
    string_vector_clear_int(&ds_sv);
    string_vector_clear_int(&ns_sv);
    xfree(domain);
    xfree(timeout);
    xfree(retries);
    xfree(ndots);
    xfree(edns0);
}

void sar_abort(struct sar_request *cookie)
{
    struct sar_request *req;
    if (!cookie)
        return;
    req = cookie;
    assert(set_find(&sar_requests, req) == req);
    log_message(sar_log, LOG_DEBUG, "sar_abort({id=%d})", req->id);
    req->cb_ok = NULL;
    req->cb_fail = NULL;
    set_remove(&sar_requests, req, 0);
}

static struct sar_nameserver *sar_our_server(const struct sockaddr_storage *ss, unsigned int ss_len)
{
    struct set_node *it;

    for (it = set_first(&sar_nameservers); it; it = set_next(it)) {
        struct sar_nameserver *ns;

        ns = set_node_data(it);
        if (ns->ss_len == ss_len && !memcmp(ss, &ns->ss, ss_len))
            return ns;
    }
    return NULL;
}

static char *sar_extract_name(const unsigned char *buf, unsigned int size, unsigned int *ppos)
{
    struct char_vector cv;
    unsigned int jumped;
    unsigned int pos;

    pos = *ppos;
    jumped = 0;
    char_vector_init(&cv, 64);
    while (1) {
        if (pos >= size)
            goto fail;
        if (!buf[pos]) {
            if (!jumped)
                *ppos = pos + 1;
            if (cv.used)
                cv.vec[cv.used - 1] = '\0'; /* chop off terminating '.' */
            else
                char_vector_append(&cv, '\0');
            return cv.vec;
        }
        switch (buf[pos] & RES_SIZE_FLAGS) {
        case RES_SF_LABEL: {
            unsigned int len = buf[pos];
            if (pos + len + 1 >= size)
                goto fail;
            char_vector_append_count(&cv, (char*)buf + pos + 1, len);
            char_vector_append(&cv, '.');
            pos += buf[pos] + 1;
            break;
        }
        case RES_SF_POINTER:
            if ((pos + 1 >= size) || (cv.used >= size))
                goto fail;
            if (!jumped)
                *ppos = pos + 2;
            pos = (buf[pos] & ~RES_SIZE_FLAGS) << 8 | buf[pos+1];
            jumped = 1;
            break;
        default:
            goto fail;
        }
    }
 fail:
    xfree(cv.vec);
    return NULL;
}

static int sar_decode_answer(struct sar_request *req, struct dns_header *hdr, unsigned char *buf, unsigned int size)
{
    struct dns_rr *rr;
    unsigned int rr_count;
    unsigned int pos;
    unsigned int ii;
    int res;

    /* Skip over query section. */
    for (ii = 0, pos = 12; ii < hdr->qdcount; ++ii) {
        /* Skip over compressed names. */
        while (1) {
            if (pos >= size)
                return 2;
            if (!buf[pos])
                break;
            switch (buf[pos] & RES_SIZE_FLAGS) {
            case RES_SF_LABEL:
                pos += buf[pos] + 1;
                break;
            case RES_SF_POINTER:
                if (pos + 1 >= size)
                    return 2;
                pos = (buf[pos] & ~RES_SIZE_FLAGS) << 8 | buf[pos+1];
                if (pos >= size)
                    return 3;
                break;
            default:
                return 4;
            }
        }
        /* Skip over null terminator, type and class part of question. */
        pos += 5;
    }

    /* Parse each RR in the answer. */
    rr_count = hdr->ancount + hdr->nscount + hdr->arcount;
    rr = xmalloc(rr_count * sizeof(rr[0]));
    for (ii = 0; ii < rr_count; ++ii) {
        rr[ii].name = sar_extract_name(buf, size, &pos);
        if (!rr[ii].name) {
            res = 5;
            goto out;
        }
        if (pos + 10 > size) {
            res = 6;
            goto out;
        }
        rr[ii].type = buf[pos+0] << 8 | buf[pos+1];
        rr[ii].class = buf[pos+2] << 8 | buf[pos+3];
        rr[ii].ttl = buf[pos+4] << 24 | buf[pos+5] << 16 | buf[pos+6] << 8 | buf[pos+7];
        rr[ii].rdlength = buf[pos+8] << 8 | buf[pos+9];
        rr[ii].rd_start = pos + 10;
        pos = pos + rr[ii].rdlength + 10;
        if (pos > size) {
            res = 7;
            goto out;
        }
    }
    res = 0;
    req->expiry.tv_sec = 0;
    req->expiry.tv_usec = 0;
    req->cb_ok(req, hdr, rr, buf, size);
    if (!evutil_timerisset(&req->expiry)) {
        req->cb_ok = NULL;
        req->cb_fail = NULL;
        set_remove(&sar_requests, req, 0);
    }

out:
    while (ii > 0)
        xfree(rr[--ii].name);
    xfree(rr);
    return res;
}

static const unsigned char *sar_extract_rdata(struct dns_rr *rr, unsigned int len, unsigned char *raw, unsigned int raw_size)
{
    if (len > rr->rdlength)
        return NULL;
    if (rr->rd_start + len > raw_size)
        return NULL;
    return raw + rr->rd_start;
}

static void sar_fd_cb(int fd, short event, void *arg)
{
    struct sockaddr_storage ss;
    struct dns_header hdr;
    struct sar_nameserver *ns;
    struct sar_request *req;
    unsigned char *buf;
    socklen_t ss_len;
    int id, res, rcode, buf_len;

    assert(fd == sar_fd_fd);
    assert(arg == &sar_fd);
    if (event != EV_READ)
        return;
    buf_len = conf.sar_edns0->parsed.p_integer;
    if (!buf_len)
        buf_len = 512;
    buf = alloca(buf_len);
    ss_len = sizeof(ss);
    res = recvfrom(sar_fd_fd, buf, buf_len, 0, (struct sockaddr*)&ss, &ss_len);
    if (res < 12 || !(ns = sar_our_server(&ss, ss_len)))
        return;
    hdr.id = buf[0] << 8 | buf[1];
    hdr.flags = buf[2] << 8 | buf[3];
    hdr.qdcount = buf[4] << 8 | buf[5];
    hdr.ancount = buf[6] << 8 | buf[7];
    hdr.nscount = buf[8] << 8 | buf[9];
    hdr.arcount = buf[10] << 8 | buf[11];

    id = hdr.id;
    req = set_find(&sar_requests, &id);
    log_message(sar_log, LOG_DEBUG, "sar_fd_cb(%d, EV_READ, %p): hdr {id=%d, flags=0x%x, qdcount=%d, ancount=%d, nscount=%d, arcount=%d} -> req %p", fd, arg, hdr.id, hdr.flags, hdr.qdcount, hdr.ancount, hdr.nscount, hdr.arcount, req);
    if (!req || !req->retries || !(hdr.flags & REQ_FLAG_QR)) {
        ns->resp_ignored++;
        return;
    }
    rcode = hdr.flags & REQ_FLAG_RCODE_MASK;
    if (rcode != RCODE_NO_ERROR) {
        sar_request_fail(req, rcode);
    } else if (sar_decode_answer(req, &hdr, (unsigned char*)buf, res)) {
        ns->resp_scrambled++;
        sar_request_fail(req, RCODE_FORMAT_ERROR);
    }
}

static void sar_build_nslist(struct conf_node_string_list *nslist)
{
    struct set_node *it;
    struct set_node *next;
    struct sar_nameserver *ns;
    unsigned int ii;

    for (it = set_first(&sar_nameservers); it; it = set_next(it)) {
        ns = set_node_data(it);
        ns->valid = 0;
    }

    for (ii = 0; ii < nslist->value.used; ++ii) {
        const char *name;

        name = nslist->value.vec[ii];
        ns = set_find(&sar_nameservers, &name);
        if (!ns) {
            it = set_node_alloc(sizeof(*ns) + strlen(name) + 1);
            ns = set_node_data(it);
            ns->name = (char*)(ns + 1);
            strcpy(ns->name, name);
            ns->ss_len = sizeof(ns->ss);
            if (!sar_pton((struct sockaddr*)&ns->ss, sizeof(ns->ss), NULL, name)) {
                xfree(it);
                continue;
            }
            sar_set_port((struct sockaddr*)&ns->ss, sizeof(ns->ss), 53);
            ns->ss_len = sar_helpers[ns->ss.ss_family]->socklen;
            set_insert(&sar_nameservers, it);
        }
        ns->valid = 1;
    }

    for (it = set_first(&sar_nameservers); it; it = next) {
        next = set_next(it);
        ns = set_node_data(it);
        if (!ns->valid)
            set_remove(&sar_nameservers, ns, 0);
    }
}

static int sar_open_fd(void)
{
    int res;

    /* Build list of nameservers. */
    sar_build_nslist(conf.sar_nslist);

    if (conf.sar_bind_address->hostname
        && conf_inaddr_validate(conf.sar_bind_address) == CA_VALID) {
        struct addrinfo *ai;

        ai = conf.sar_bind_address->addr;
        sar_fd_fd = socket(ai->ai_family, SOCK_DGRAM, 0);
        if (sar_fd_fd < 0) {
            log_message(sar_log, LOG_FATAL, "Unable to create resolver socket: %s", strerror(errno));
            return 1;
        }

        res = bind(sar_fd_fd, ai->ai_addr, ai->ai_addrlen);
        if (res < 0)
            log_message(sar_log, LOG_ERROR, "Unable to bind resolver socket to address [%s]:%s: %s", conf.sar_bind_address->hostname, conf.sar_bind_address->service, strerror(errno));
    } else {
        struct set_node *node;
        struct sar_nameserver *ns;

        node = set_first(&sar_nameservers);
        assert(node != NULL);
        ns = set_node_data(node);
        sar_fd_fd = socket(ns->ss.ss_family, SOCK_DGRAM, 0);
        if (sar_fd_fd < 0) {
            log_message(sar_log, LOG_FATAL, "Unable to create resolver socket: %s", strerror(errno));
            return 1;
        }
    }

    event_set(&sar_fd, sar_fd_fd, EV_READ, sar_fd_cb, &sar_fd);
    if (event_add(&sar_fd, NULL)) {
        log_message(sar_log, LOG_FATAL, "Unable to register resolver socket with event loop.");
        return 1;
    }
    return 0;
}

struct name_ofs {
    const char *name;
    unsigned int ofs;
};

/** Append \a name to \a cv in compressed form. */
static int sar_append_name(struct char_vector *cv, const char *name, struct name_ofs *ofs, unsigned int *used, unsigned int alloc)
{
    struct name_ofs *pofs;
    unsigned int len;

    while (1) {
        pofs = bsearch(&name, ofs, *used, sizeof(ofs[0]), set_compare_charp);
        if (pofs) {
            char_vector_reserve(cv, cv->used + 2);
            cv->vec[cv->used++] = RES_SF_POINTER | (pofs->ofs >> 8);
            cv->vec[cv->used++] = pofs->ofs & 255;
            return 0;
        }
        len = strcspn(name, ".");
        if (len > 63)
            return 1;
        if (*used < alloc) {
            ofs[*used].name = name;
            ofs[*used].ofs = cv->used;
            qsort(ofs, (*used)++, sizeof(ofs[0]), set_compare_charp);
        }
        char_vector_reserve(cv, cv->used + len + 1);
        cv->vec[cv->used] = RES_SF_LABEL | len;
        memcpy(cv->vec + cv->used + 1, name, len);
        cv->used += len + 1;
        if (name[len] == '.')
            name += len + 1;
        else if (name[len] == '\0')
            break;
    }
    char_vector_append(cv, '\0');
    return 0;
}

/** Build a DNS question packet.  After \a body, there is at least one
 * pair consisting of const char *name and unsigned int qtype.  A null
 * name argument terminates the list.
 */
static unsigned int sar_request_build(struct sar_request *req, unsigned char **body, ...)
{
    struct name_ofs suffixes[32];
    struct char_vector cv;
    va_list args;
    const char *name;
    unsigned int suf_used;
    unsigned int val;
    unsigned int qdcount;

    char_vector_init(&cv, 512);
    suf_used = 0;
    va_start(args, body);
    val = REQ_OPCODE_QUERY | REQ_FLAG_RD;
    cv.vec[0] = req->id >> 8;
    cv.vec[1] = req->id & 255;
    cv.vec[2] = val >> 8;
    cv.vec[3] = val & 255;
    cv.vec[6] = cv.vec[7] = cv.vec[8] = cv.vec[9] = cv.vec[10] = 0;
    cv.used = 12;
    for (qdcount = 0; (name = va_arg(args, const char*)); ++qdcount) {
        if (sar_append_name(&cv, name, suffixes, &suf_used, ARRAY_LENGTH(suffixes))) {
            char_vector_clear(&cv);
            goto out;
        }
        char_vector_reserve(&cv, cv.used + 4);
        val = va_arg(args, unsigned int);
        cv.vec[cv.used++] = val >> 8;
        cv.vec[cv.used++] = val & 255;
        cv.vec[cv.used++] = REQ_CLASS_IN >> 8;
        cv.vec[cv.used++] = REQ_CLASS_IN & 255;
    }
    cv.vec[4] = qdcount >> 8;
    cv.vec[5] = qdcount & 255;
    val = conf.sar_edns0->parsed.p_integer;
    if (val) {
        char_vector_reserve(&cv, cv.used + 11);
        cv.vec[cv.used +  0] = '\0'; /* empty name */
        cv.vec[cv.used +  1] = REQ_TYPE_OPT >> 8;
        cv.vec[cv.used +  2] = REQ_TYPE_OPT & 255;
        cv.vec[cv.used +  3] = val >> 8;
        cv.vec[cv.used +  4] = val & 255;
        cv.vec[cv.used +  5] = 0; /* extended-rcode */
        cv.vec[cv.used +  6] = 0; /* version */
        cv.vec[cv.used +  7] = 0; /* reserved */
        cv.vec[cv.used +  8] = 0; /* reserved */
        cv.vec[cv.used +  9] = 0; /* msb rdlen */
        cv.vec[cv.used + 10] = 0; /* lsb rdlen */
        cv.used += 11;
        cv.vec[11] = 1; /* update arcount */
    } else cv.vec[11] = 0;

out:
    if (body)
        *body = (unsigned char*)cv.vec;
    else {
        xfree(req->body);
        req->body = (unsigned char*)cv.vec;
        req->body_len = cv.used;
    }
    va_end(args);
    return cv.used;
}

static void sar_request_send(struct sar_request *req)
{
    struct timeval interval;
    struct set_node *it;

    /* make sure we have our local socket */
    if (!event_initialized(&sar_fd) && sar_open_fd()) {
        sar_request_fail(req, RCODE_SOCKET_FAILURE);
        return;
    }

    log_message(sar_log, LOG_DEBUG, "sar_request_send({id=%d})", req->id);

    /* send query to each configured nameserver */
    for (it = set_first(&sar_nameservers); it; it = set_next(it)) {
        struct sar_nameserver *ns;
        int res;

        ns = set_node_data(it);
        res = sendto(sar_fd_fd, req->body, req->body_len, 0, (struct sockaddr*)&ns->ss, ns->ss_len);
        if (res > 0) {
            ns->req_sent++;
            log_message(sar_log, LOG_DEBUG, "Sent %u bytes to %s.", res, ns->name);
        } else if (res < 0)
            log_message(sar_log, LOG_ERROR, "Unable to send %u bytes to nameserver %s: %s", req->body_len, ns->name, strerror(errno));
        else /* res == 0 */
            assert(0 && "resolver sendto() unexpectedly returned zero");
    }

    /* Check that query timeout is soon enough. */
    interval.tv_sec = conf.sar_timeout->parsed.p_interval << ++req->retries;
    interval.tv_usec = 0;
    evutil_timeradd(&req->expiry, &interval, &req->expiry);
    sar_check_timeout(req->expiry);
}

static struct sar_request *sar_request_alloc(unsigned int data_len)
{
    struct set_node *node;
    struct sar_request *req;

    node = set_node_alloc(sizeof(*req) + data_len);
    req = set_node_data(node);
    do {
        req->id = rand() & 0xffff;
    } while (set_find(&sar_requests, req));
    set_insert(&sar_requests, set_node(req));
    log_message(sar_log, LOG_DEBUG, "sar_request_alloc(%d) -> {id=%d}", data_len, req->id);
    return req;
}

enum service_proto {
    SERVICE_UDP,
    SERVICE_TCP,
    SERVICE_NUM_PROTOS
};

struct service_byname {
    const char *name; /* service name */
    struct {
        /* note: if valid != 0, port == 0, check canonical entry */
        struct service_byname *canon; /* if NULL, this is canonical */
        uint16_t port;
        unsigned int valid : 1;
        unsigned int srv : 1;
    } protos[SERVICE_NUM_PROTOS];
};

struct service_byport {
    unsigned int port;
    struct service_byname *byname[SERVICE_NUM_PROTOS];
};

static struct set services_byname; /* contains struct service_byname */
static struct set services_byport; /* contains struct service_byport */

static struct service_byname *sar_service_byname(const char *name, int autocreate)
{
    struct service_byname *byname;

    byname = set_find(&services_byname, &name);
    if (!byname && autocreate) {
        struct set_node *node;

        node = set_node_alloc(sizeof(*byname) + strlen(name) + 1);
        byname = set_node_data(node);
        byname->name = strcpy((char*)(byname + 1), name);
        set_insert(&services_byname, node);
    }
    return byname;
}

static struct service_byport *sar_service_byport(unsigned int port, int autocreate)
{
    struct service_byport *byport;

    byport = set_find(&services_byport, &port);
    if (!byport && autocreate) {
        struct set_node *node;

        node = set_node_alloc(sizeof(*byport));
        byport = set_node_data(node);
        byport->port = port;
        set_insert(&services_byport, node);
    }
    return byport;
}

static void sar_services_load_file(const char *etc_services)
{
    static const char *whitespace = " \t\r\n";
    struct service_byname *canon;
    struct service_byport *byport;
    char *name;
    char *port;
    char *alias;
    char *ptr;
    FILE *file;
    unsigned int pnum;
    enum service_proto proto;
    char linebuf[LINE_MAX];

    file = fopen(etc_services, "r");
    if (!file)
        return;
    while (fgets(linebuf, sizeof(linebuf), file)) {
        ptr = strchr(linebuf, '#');
        if (ptr)
            *ptr = '\0';
        /* Tokenize canonical service name and port number. */
        name = strtok_r(linebuf, whitespace, &ptr);
        if (name == NULL)
            continue;
        port = strtok_r(NULL, whitespace, &ptr);
        if (port == NULL)
            continue;
        pnum = strtoul(port, &port, 10);
        if (pnum == 0 || *port++ != '/')
            continue;
        if (!strcmp(port, "udp"))
            proto = SERVICE_UDP;
        else if (!strcmp(port, "tcp"))
            proto = SERVICE_TCP;
        else continue;

        /* Set up canonical name-indexed service entry. */
        canon = sar_service_byname(name, 1);
        if (canon->protos[proto].valid) {
            log_message(sar_log, LOG_INFO, "Service %s/%s listed twice.", name, port);
            continue;
        }
        canon->protos[proto].canon = NULL;
        canon->protos[proto].port = pnum;
        canon->protos[proto].valid = 1;

        /* Set up port-indexed service entry. */
        byport = sar_service_byport(pnum, 1);
        if (!byport->byname[proto])
            byport->byname[proto] = canon;

        /* Add alias entries. */
        while ((alias = strtok_r(NULL, whitespace, &ptr))) {
            struct service_byname *byname;

            byname = sar_service_byname(alias, 1);
            if (byname->protos[proto].valid) {
                /* We do not log this since there are a lot of
                 * duplicate aliases, some only differing in case. */
                continue;
            }
            byname->protos[proto].canon = canon;
            byname->protos[proto].port = pnum;
            byname->protos[proto].valid = 1;
        }
    }
    fclose(file);
}

static void sar_services_init(const char *etc_services)
{
    /* These are a portion of the services listed at
     * http://www.dns-sd.org/ServiceTypes.html.
     */
    static const char *tcp_srvs[] = { "cvspserver", "distcc", "ftp", "http",
        "imap", "ipp", "irc", "ldap", "login", "nfs", "pop3", "postgresql",
        "rsync", "sftp-ssh", "soap", "ssh", "telnet", "webdav", "xmpp-client",
        "xmpp-server", "xul-http", NULL };
    static const char *udp_srvs[] = { "bootps", "dns-update", "domain", "nfs",
        "ntp", "tftp", NULL };
    struct service_byname *byname;
    unsigned int ii;

    sar_services_load_file(etc_services);

    for (ii = 0; tcp_srvs[ii]; ++ii) {
        byname = sar_service_byname(tcp_srvs[ii], 1);
        byname->protos[SERVICE_TCP].srv = 1;
    }

    for (ii = 0; udp_srvs[ii]; ++ii) {
        byname = sar_service_byname(udp_srvs[ii], 1);
        byname->protos[SERVICE_UDP].srv = 1;
    }
}

static void sar_register_helper(struct sar_family_helper *helper)
{
    assert(helper->family <= MAX_FAMILY);
    sar_helpers[helper->family] = helper;
    helper->next = sar_first_helper;
    sar_first_helper = helper;
}

static unsigned int sar_addrlen(unsigned short family, UNUSED_ARG(unsigned int size))
{
    return family <= MAX_FAMILY && sar_helpers[family]
        ? sar_helpers[family]->socklen : 0;
}

struct sar_getaddr_state {
    struct sar_family_helper *helper;
    struct addrinfo *ai_head;
    struct addrinfo *ai_tail;
    sar_addr_cb cb;
    void *cb_ctx;
    unsigned int search_pos;
    unsigned int flags;
    unsigned int socktype;
    unsigned int protocol;
    unsigned int port;
    unsigned int srv_ofs;
    char full_name[DNS_NAME_LENGTH];
};

static unsigned int sar_getaddr_append(struct sar_getaddr_state *state, struct addrinfo *ai, int copy)
{
    unsigned int count;

    log_message(sar_log, LOG_DEBUG, "sar_getaddr_append({full_name=%s}, ai=%p, copy=%d)", state->full_name, ai, copy);

    /* Set the appropriate pointer to the new element(s). */
    if (state->ai_tail)
        state->ai_tail->ai_next = ai;
    else
        state->ai_head = ai;

    /* Find the end of the list. */
    if (copy) {
        /* Make sure we copy fields for both the first and last entries. */
        count = 1;
        while (1) {
            if (!ai->ai_addrlen) {
                assert(sar_helpers[ai->ai_family]);
                ai->ai_addrlen = sar_helpers[ai->ai_family]->socklen;
            }
#if defined(HAVE_SOCKADDR_SA_LEN)
            ai->ai_addr->sa_len = ai->ai_addrlen;
#endif
            ai->ai_addr->sa_family = ai->ai_family;
            ai->ai_socktype = state->socktype;
            ai->ai_protocol = state->protocol;
            if (!ai->ai_next)
                break;
            count++;
            ai = ai->ai_next;
        }
    } else {
        for (count = 1; ai->ai_next; ++count, ai = ai->ai_next)
            ;
    }

    /* Set the tail pointer and return count of appended items. */
    state->ai_tail = ai;
    return count;
}

static struct sar_request *sar_getaddr_request(struct sar_request *req)
{
    struct sar_getaddr_state *state;
    unsigned int len;
    char full_name[DNS_NAME_LENGTH];

    state = (struct sar_getaddr_state*)(req + 1);

    /* If we can and should, append the current search domain. */
    if (state->search_pos < conf.sar_search->value.used) {
        int len = snprintf(full_name, sizeof(full_name), "%s.%s", state->full_name, conf.sar_search->value.vec[state->search_pos]);
        if (len < 0 || (size_t)len >= sizeof(full_name)) {
            log_message(sar_log, LOG_ERROR, "sar_getaddr_request({id=%d}): name too long to append search domain(s)", req->id);
            return NULL;
        }
    } else if (state->search_pos == conf.sar_search->value.used)
        strlcpy(full_name, state->full_name, sizeof(full_name));
    else {
        log_message(sar_log, LOG_DEBUG, "sar_getaddr_request({id=%d}): failed", req->id);
        state->cb(state->cb_ctx, NULL, SAI_NONAME);
        return NULL;
    }

    /* Build the appropriate request for DNS record(s). */
    if (state->flags & SAI_ALL)
        len = sar_request_build(req, NULL, full_name + state->srv_ofs, REQ_QTYPE_ALL, NULL);
    else if (state->srv_ofs)
        len = state->helper->build_addr_request(req, full_name + state->srv_ofs, full_name, state->flags);
    else
        len = state->helper->build_addr_request(req, full_name, NULL, state->flags);

    log_message(sar_log, LOG_DEBUG, "sar_getaddr_request({id=%d}): full_name=%s, srv_ofs=%d", req->id, full_name, state->srv_ofs);

    /* Check that the request could be built. */
    if (!len) {
        state->cb(state->cb_ctx, NULL, SAI_NODATA);
        return NULL;
    }

    /* Send the request. */
    sar_request_send(req);
    return req;
}

static int sar_getaddr_decode(struct sar_request *req, struct dns_header *hdr, struct dns_rr *rr, unsigned char *raw, unsigned int raw_size, unsigned int rr_idx)
{
    struct sar_getaddr_state *state;
    char *cname;
    unsigned int pos;
    unsigned int hit;
    unsigned int jj;

    log_message(sar_log, LOG_DEBUG, "  sar_getaddr_decode(id=%d, <hdr>, {type=%d, rdlength=%d, name=%s}, <data>, %u, <idx>)", hdr->id, rr[rr_idx].type, rr[rr_idx].rdlength, rr[rr_idx].name, raw_size);
    state = (struct sar_getaddr_state*)(req + 1);

    switch (rr[rr_idx].type) {
    case REQ_TYPE_A:
        if (state->flags & SAI_ALL)
            return sar_ipv4_helper.decode_addr(state, rr + rr_idx, raw, raw_size);
#if defined(AF_INET6)
        else if (state->flags & SAI_V4MAPPED)
            return sar_ipv6_helper.decode_addr(state, rr + rr_idx, raw, raw_size);
#endif
        return state->helper->decode_addr(state, rr + rr_idx, raw, raw_size);

    case REQ_TYPE_AAAA:
#if defined(AF_INET6)
        if (state->flags & SAI_ALL)
            return sar_ipv6_helper.decode_addr(state, rr + rr_idx, raw, raw_size);
        return state->helper->decode_addr(state, rr + rr_idx, raw, raw_size);
#else
        return 0;
#endif

    case REQ_TYPE_CNAME:
        /* there should be the canonical name next */
        pos = rr[rr_idx].rd_start;
        cname = sar_extract_name(raw, raw_size, &pos);
        if (!cname)
            return 0; /* XXX: eventually log the unhandled body */
        /* and it should correspond to some other answer in the response */
        for (jj = hit = 0; jj < hdr->ancount; ++jj) {
            if (strcasecmp(cname, rr[jj].name))
                continue;
            hit += sar_getaddr_decode(req, hdr, rr, raw, raw_size, jj);
        }
        /* XXX: if (!hit) handle or log the incomplete recursion; */
        return hit;

    case REQ_TYPE_SRV:
        /* TODO: decode the SRV record */

    default:
        return 0;
    }
}

static void sar_getaddr_ok(struct sar_request *req, struct dns_header *hdr, struct dns_rr *rr, unsigned char *raw, unsigned int raw_size)
{
    struct sar_getaddr_state *state;
    unsigned int ii;

    state = (struct sar_getaddr_state*)(req + 1);

    log_message(sar_log, LOG_DEBUG, "sar_getaddr_ok({id=%d}, {id=%d}, <rr>, <data>, %u)", req->id, hdr->id, raw_size);
    for (ii = 0; ii < hdr->ancount; ++ii)
        sar_getaddr_decode(req, hdr, rr, raw, raw_size, ii);

    /* If we found anything, report it, else try again. */
    if (state->ai_head)
        state->cb(state->cb_ctx, state->ai_head, SAI_SUCCESS);
    else
        sar_getaddr_request(req);
}

static void sar_getaddr_fail(struct sar_request *req, UNUSED_ARG(unsigned int rcode))
{
    struct sar_getaddr_state *state;

    log_message(sar_log, LOG_DEBUG, "sar_getaddr_fail({id=%d}, rcode=%u)", req->id, rcode);
    state = (struct sar_getaddr_state*)(req + 1);
    state->cb(state->cb_ctx, NULL, SAI_FAIL);
}

struct sar_request *sar_getaddr(const char *node, const char *service, const struct addrinfo *hints_, sar_addr_cb cb, void *cb_ctx)
{
    struct sockaddr_storage ss;
    struct addrinfo hints;
    struct sar_family_helper *helper;
    struct service_byname *svc;
    char *end;
    unsigned int portnum;
    unsigned int pos;
    enum service_proto proto;

    if (!node && !service) {
        cb(cb_ctx, NULL, SAI_NONAME);
        return NULL;
    }

    /* Initialize local hints structure. */
    if (hints_)
        memcpy(&hints, hints_, sizeof(hints));
    else
        memset(&hints, 0, sizeof(hints));

    /* Translate socket type to internal protocol. */
    switch (hints.ai_socktype) {
    case 0: hints.ai_socktype = SOCK_STREAM; /* fall through */
    case SOCK_STREAM: proto = SERVICE_TCP; break;
    case SOCK_DGRAM: proto = SERVICE_UDP; break;
    default:
        cb(cb_ctx, NULL, SAI_SOCKTYPE);
        return NULL;
    }

    /* Figure out preferred socket size. */
    if (hints.ai_family == AF_UNSPEC)
        hints.ai_family = AF_INET;
    if (hints.ai_family > MAX_FAMILY
        || !(helper = sar_helpers[hints.ai_family])) {
        cb(cb_ctx, NULL, SAI_FAMILY);
        return NULL;
    }
    hints.ai_addrlen = helper->socklen;

    /* If \a node is NULL, figure out the correct default from the
     * requested family and SAI_PASSIVE flag.
     */
    if (node == NULL)
        node = (hints.ai_flags & SAI_PASSIVE) ? helper->unspec_addr : helper->localhost_addr;

    /* Try to parse (failing that, look up) \a service. */
    if (!service)
        portnum = 0, svc = NULL;
    else if ((portnum = strtoul(service, &end, 10)), *end == '\0')
        svc = NULL;
    else if ((svc = sar_service_byname(service, 0)) != NULL)
        portnum = svc->protos[proto].port;
    else {
        cb(cb_ctx, NULL, SAI_SERVICE);
        return NULL;
    }

    /* Try to parse \a node as a numeric hostname.*/
    pos = sar_pton((struct sockaddr*)&ss, sizeof(ss), NULL, node);
    if (pos && node[pos] == '\0') {
        struct addrinfo *ai;
        char canonname[SAR_NTOP_MAX];

        /* we have a valid address; use it */
        sar_set_port((struct sockaddr*)&ss, sizeof(ss), portnum);
        hints.ai_addrlen = sar_addrlen(ss.ss_family, sizeof(ss));
        if (!hints.ai_addrlen) {
            cb(cb_ctx, NULL, SAI_FAMILY);
            return NULL;
        }
        pos = sar_ntop(canonname, sizeof(canonname), (struct sockaddr*)&ss, hints.ai_addrlen);

        /* allocate and fill in the addrinfo response */
        ai = xmalloc(sizeof(*ai) + hints.ai_addrlen + pos + 1);
        ai->ai_family = ss.ss_family;
        ai->ai_socktype = hints.ai_socktype;
        ai->ai_protocol = hints.ai_protocol;
        ai->ai_addrlen = hints.ai_addrlen;
        ai->ai_addr = memcpy(ai + 1, &ss, ai->ai_addrlen);
        ai->ai_canonname = strcpy((char*)ai->ai_addr + ai->ai_addrlen, canonname);
        cb(cb_ctx, ai, SAI_SUCCESS);
        return NULL;
    } else if (hints.ai_flags & SAI_NUMERICHOST) {
        cb(cb_ctx, NULL, SAI_NONAME);
        return NULL;
    } else {
        struct sar_request *req;
        struct sar_getaddr_state *state;
        unsigned int len, ii;

        req = sar_request_alloc(sizeof(*state));
        req->cb_ok = sar_getaddr_ok;
        req->cb_fail = sar_getaddr_fail;

        state = (struct sar_getaddr_state*)(req + 1);
        state->helper = helper;
        state->ai_head = state->ai_tail = NULL;
        state->cb = cb;
        state->cb_ctx = cb_ctx;
        state->flags = hints.ai_flags;
        state->socktype = hints.ai_socktype;
        state->protocol = hints.ai_protocol;
        state->port = portnum;

        if ((state->flags & SAI_NOSRV) || !svc)
            state->srv_ofs = 0;
        else if (svc->protos[proto].srv)
            state->srv_ofs = snprintf(state->full_name, sizeof(state->full_name), "_%s._%s.", svc->name, (proto == SERVICE_UDP ? "udp" : "tcp"));
        else if (state->flags & SAI_FORCESRV)
            state->srv_ofs = snprintf(state->full_name, sizeof(state->full_name), "_%s._%s.", service, (proto == SERVICE_UDP ? "udp" : "tcp"));
        else
            state->srv_ofs = 0;

        if (state->srv_ofs < sizeof(state->full_name))
            strlcpy(state->full_name + state->srv_ofs, node, sizeof(state->full_name) - state->srv_ofs);

        for (ii = len = 0; node[ii]; ++ii)
            if (node[ii] == '.')
                len++;
        if (len >= (unsigned int)conf.sar_ndots->parsed.p_integer)
            state->search_pos = conf.sar_search->value.used;
        else
            state->search_pos = 0;

        /* XXX: fill in *state with any other fields needed to parse responses. */

        if (!sar_getaddr_request(req)) {
            xfree(req);
            return NULL;
        }
        return req;
    }
}

struct sar_getname_state {
    sar_name_cb cb;
    void *cb_ctx;
    char *hostname;
    unsigned int flags;
    unsigned int family;
    enum service_proto proto;
    unsigned short port;
    unsigned int doing_arpa : 1; /* checking .ip6.arpa vs .ip6.int */
    unsigned char original[16]; /* original address data */
    /* name must be long enough to hold "0.0.<etc>.ip6.arpa" */
    char name[74];
};

static void sar_getname_fail(struct sar_request *req, UNUSED_ARG(unsigned int rcode))
{
    struct sar_getname_state *state;
    unsigned int len;

    state = (struct sar_getname_state*)(req + 1);
    if (state->doing_arpa) {
        len = strlen(state->name);
        assert(len == 73);
        strcpy(state->name + len - 4, "int");
        len = sar_request_build(req, NULL, state->name, REQ_TYPE_PTR, NULL);
        if (len) {
            sar_request_send(req);
            return;
        }
    }
    state->cb(state->cb_ctx, NULL, NULL, SAI_FAIL);
    xfree(state->hostname);
}

static const char *sar_getname_port(unsigned int port, unsigned int flags, char *tmpbuf, unsigned int tmpbuf_len)
{
    struct service_byport *service;
    enum service_proto proto;

    proto = (flags & SNI_DGRAM) ? SERVICE_UDP : SERVICE_TCP;
    if (!(flags & SNI_NUMERICSERV)
        && (service = set_find(&services_byport, &port))
        && service->byname[proto])
        return service->byname[proto]->name;
    snprintf(tmpbuf, tmpbuf_len, "%d", port);
    return tmpbuf;
}

static void sar_getname_confirm(struct sar_request *req, struct dns_header *hdr, struct dns_rr *rr, unsigned char *raw, unsigned int raw_size)
{
    struct sar_getname_state *state;
    const unsigned char *data;
    const char *portname;
    char servbuf[16];
    unsigned int nbr;
    unsigned int ii;

    state = (struct sar_getname_state*)(req + 1);
    for (ii = 0; ii < hdr->ancount; ++ii) {
        /* Is somebody confused or trying to play games? */
        if (rr[ii].class != REQ_CLASS_IN
            || strcasecmp(state->hostname, rr[ii].name))
            continue;
        switch (rr[ii].type) {
        case REQ_TYPE_A: nbr = 4; break;
        case REQ_TYPE_AAAA: nbr = 16; break;
        default: continue;
        }
        data = sar_extract_rdata(rr, nbr, raw, raw_size);
        if (data && !memcmp(data, state->original, nbr)) {
            portname = sar_getname_port(state->port, state->flags, servbuf, sizeof(servbuf));
            state->cb(state->cb_ctx, state->hostname, portname, SAI_SUCCESS);
            xfree(state->hostname);
            return;
        }
    }
    state->cb(state->cb_ctx, NULL, NULL, SAI_MISMATCH);
    xfree(state->hostname);
}

static void sar_getname_ok(struct sar_request *req, struct dns_header *hdr, struct dns_rr *rr, unsigned char *raw, unsigned int raw_size)
{
    struct sar_getname_state *state;
    const char *portname;
    unsigned int pos;
    unsigned int ii;
    char servbuf[16];

    state = (struct sar_getname_state*)(req + 1);
    for (ii = 0; ii < hdr->ancount; ++ii) {
        if (rr[ii].type != REQ_TYPE_PTR
            || rr[ii].class != REQ_CLASS_IN
            || strcasecmp(rr[ii].name, state->name))
            continue;
        pos = rr[ii].rd_start;
        state->hostname = sar_extract_name(raw, raw_size, &pos);
        break;
    }

    if (!state->hostname) {
        state->cb(state->cb_ctx, NULL, NULL, SAI_NONAME);
        return;
    }

    if (state->flags & SNI_PARANOID) {
        req->cb_ok = sar_getname_confirm;
        pos = sar_helpers[state->family]->build_addr_request(req, state->hostname, NULL, 0);
        if (pos)
            sar_request_send(req);
        else {
            xfree(state->hostname);
            state->cb(state->cb_ctx, NULL, NULL, SAI_FAIL);
        }
        return;
    }

    portname = sar_getname_port(state->port, state->flags, servbuf, sizeof(servbuf));
    state->cb(state->cb_ctx, state->hostname, portname, SAI_SUCCESS);
    xfree(state->hostname);
}

struct sar_request *sar_getname(const struct sockaddr *sa, socklen_t salen, int flags, sar_name_cb cb, void *cb_ctx)
{
    struct sar_family_helper *helper;
    struct sar_request *req;
    struct sar_getname_state *state;
    unsigned int len;
    int port;

    if (sa->sa_family > MAX_FAMILY
        || !(helper = sar_helpers[sa->sa_family])) {
        cb(cb_ctx, NULL, NULL, SAI_FAMILY);
        return NULL;
    }

    port = helper->get_port(sa, salen);

    if (flags & SNI_NUMERICHOST) {
        const char *servname;
        unsigned int len;
        char host[SAR_NTOP_MAX], servbuf[16];

        /* If appropriate, try to look up service name. */
        servname = sar_getname_port(port, flags, servbuf, sizeof(servbuf));
        len = sar_ntop(host, sizeof(host), sa, salen);
        assert(len != 0);
        cb(cb_ctx, host, servname, SAI_SUCCESS);
        return NULL;
    }

    req = sar_request_alloc(sizeof(*state));
    req->cb_ok = sar_getname_ok;
    req->cb_fail = sar_getname_fail;

    state = (struct sar_getname_state*)(req + 1);
    state->cb = cb;
    state->cb_ctx = cb_ctx;
    state->flags = flags;
    state->family = sa->sa_family;
    state->port = port;

    helper->build_ptr_name(state, sa, salen);
    assert(strlen(state->name) < sizeof(state->name));
    len = sar_request_build(req, NULL, state->name, REQ_TYPE_PTR, NULL);
    if (!len) {
        cb(cb_ctx, NULL, NULL, SAI_NODATA);
        xfree(req);
        return NULL;
    }

    sar_request_send(req);
    return req;
}

static unsigned int ipv4_ntop(char *output, unsigned int out_size, const struct sockaddr *sa, UNUSED_ARG(unsigned int socklen))
{
    struct sockaddr_in *sin;
    unsigned int ip4;
    unsigned int pos;

    sin = (struct sockaddr_in*)sa;
    ip4 = ntohl(sin->sin_addr.s_addr);
    pos = snprintf(output, out_size, "%u.%u.%u.%u", (ip4 >> 24), (ip4 >> 16) & 255, (ip4 >> 8) & 255, ip4 & 255);
    return (pos < out_size) ? pos : 0;
}

static unsigned int sar_pton_ip4(const char *input, unsigned int *bits, uint32_t *output)
{
    unsigned int dots = 0;
    unsigned int pos = 0;
    unsigned int part = 0;
    unsigned int ip = 0;

    /* Intentionally no support for bizarre IPv4 formats (plain
     * integers, octal or hex components) -- only vanilla dotted
     * decimal quads, optionally with trailing /nn.
     */
    if (input[0] == '.')
        return 0;
    while (1) {
        if (isdigit(input[pos])) {
            part = part * 10 + input[pos++] - '0';
            if (part > 255)
                return 0;
            if ((dots == 3) && !isdigit(input[pos])) {
                *output = htonl(ip | part);
                *bits = 32;
                return pos;
            }
        } else if (input[pos] == '.') {
            if (input[++pos] == '.')
                return 0;
            ip |= part << (24 - 8 * dots++);
            part = 0;
        } else if (bits && input[pos] == '/' && isdigit(input[pos + 1])) {
            unsigned int len;
            char *term;

            len = strtoul(input + pos + 1, &term, 10);
            if (term <= input + pos + 1) {
                *bits = 32;
                return pos;
            } else if (len > 32)
                return 0;
            *bits = len;
            return term - input;
        } else return 0;
    }
}

static unsigned int ipv4_pton(struct sockaddr *sa, UNUSED_ARG(unsigned int socklen), unsigned int *bits, const char *input)
{
    unsigned int pos;

    pos = sar_pton_ip4(input, bits, &((struct sockaddr_in*)sa)->sin_addr.s_addr);
    if (!pos)
        return 0;
    sa->sa_family = AF_INET;
    return pos;
}

static int ipv4_get_port(const struct sockaddr *sa, UNUSED_ARG(unsigned int socklen))
{
    return ntohs(((const struct sockaddr_in*)sa)->sin_port);
}

static int ipv4_set_port(struct sockaddr *sa, UNUSED_ARG(unsigned int socklen), unsigned short port)
{
    ((struct sockaddr_in*)sa)->sin_port = htons(port);
    return 0;
}

static unsigned int ipv4_addr_request(struct sar_request *req, const char *node, const char *srv_node, UNUSED_ARG(unsigned int flags))
{
    unsigned int len;
    if (srv_node)
        len = sar_request_build(req, NULL, node, REQ_TYPE_A, srv_node, REQ_TYPE_SRV, NULL);
    else
        len = sar_request_build(req, NULL, node, REQ_TYPE_A, NULL);
    return len;
}

static void ipv4_ptr_name(struct sar_getname_state *state, const struct sockaddr *sa, UNUSED_ARG(unsigned int socklen))
{
    const uint8_t *bytes;

    bytes = (uint8_t*)&((struct sockaddr_in*)sa)->sin_addr.s_addr;
    memcpy(state->original, bytes, 4);
    snprintf(state->name, sizeof(state->name),
             "%u.%u.%u.%u.in-addr.arpa",
             bytes[3], bytes[2], bytes[1], bytes[0]);
}

static int ipv4_decode(struct sar_getaddr_state *state, struct dns_rr *rr, unsigned char *raw, UNUSED_ARG(unsigned int raw_size))
{
    struct sockaddr_in *sa;
    struct addrinfo *ai;

    if (rr->rdlength != 4)
        return 0;

    if (state->flags & SAI_CANONNAME) {
        ai = xmalloc(sizeof(*ai) + sizeof(*sa) + strlen(rr->name) + 1);
        sa = (struct sockaddr_in*)(ai->ai_addr = (struct sockaddr*)(ai + 1));
        ai->ai_canonname = strcpy((char*)(sa + 1), rr->name);
    } else {
        ai = xmalloc(sizeof(*ai) + sizeof(*sa));
        sa = (struct sockaddr_in*)(ai->ai_addr = (struct sockaddr*)(ai + 1));
        ai->ai_canonname = NULL;
    }

    ai->ai_family = AF_INET;
    sa->sin_port = htons(state->port);
    memcpy(&sa->sin_addr.s_addr, raw + rr->rd_start, 4);
    return sar_getaddr_append(state, ai, 1);
}

static struct sar_family_helper sar_ipv4_helper = {
    "127.0.0.1",
    "0.0.0.0",
    sizeof(struct sockaddr_in),
    AF_INET,
    ipv4_ntop,
    ipv4_pton,
    ipv4_get_port,
    ipv4_set_port,
    ipv4_addr_request,
    ipv4_ptr_name,
    ipv4_decode,
    NULL
};

#if defined(AF_INET6)

static unsigned int ipv6_ntop(char *output, unsigned int out_size, const struct sockaddr *sa, UNUSED_ARG(unsigned int socklen))
{
    struct sockaddr_in6 *sin6;
    unsigned int pos, part, max_start, max_zeros, curr_zeros, ii;
    unsigned short addr16;

    sin6 = (struct sockaddr_in6*)sa;
    /* Find longest run of zeros. */
    for (max_start = max_zeros = curr_zeros = ii = 0; ii < 8; ++ii) {
        addr16 = (sin6->sin6_addr.s6_addr[ii * 2] << 8) | sin6->sin6_addr.s6_addr[ii * 2 + 1];
        if (!addr16)
            curr_zeros++;
        else if (curr_zeros > max_zeros) {
            max_start = ii - curr_zeros;
            max_zeros = curr_zeros;
            curr_zeros = 0;
        }
    }
    if (curr_zeros > max_zeros) {
        max_start = ii - curr_zeros;
        max_zeros = curr_zeros;
    }

    /* Is it an IPv4-compatible or -mapped IPv6 address? */
    if ((max_start == 0)
        && (((max_zeros == 5)
             && (sin6->sin6_addr.s6_addr[10] == 255)
             && (sin6->sin6_addr.s6_addr[11] == 255))
            || ((max_zeros == 6)
                && (sin6->sin6_addr.s6_addr[10] == 0)
                && (sin6->sin6_addr.s6_addr[11] == 0)))) {
        output[0] = ':';
        output[1] = ':';

        if (max_zeros == 5) {
            output[2] = 'f';
            output[3] = 'f';
            output[4] = 'f';
            output[5] = 'f';
            output[6] = ':';
            pos = 7;
        } else {
            pos = 2;
        }

        pos += sprintf(output + pos, "%d.%d.%d.%d",
                       sin6->sin6_addr.s6_addr[12],
                       sin6->sin6_addr.s6_addr[13],
                       sin6->sin6_addr.s6_addr[14],
                       sin6->sin6_addr.s6_addr[15]);

        return pos;
    }

    /* Print out address. */
#define APPEND(CH) do { output[pos++] = (CH); if (pos >= out_size) return 0; } while (0)
    for (pos = 0, ii = 0; ii < 8; ++ii) {
        if ((max_zeros > 0) && (ii == max_start)) {
            if (ii == 0)
                APPEND(':');
            APPEND(':');
            ii += max_zeros - 1;
            continue;
        }
        part = (sin6->sin6_addr.s6_addr[ii * 2] << 8) | sin6->sin6_addr.s6_addr[ii * 2 + 1];
        if (part >= 0x1000)
            APPEND(hexdigits[part >> 12]);
        if (part >= 0x100)
            APPEND(hexdigits[(part >> 8) & 15]);
        if (part >= 0x10)
            APPEND(hexdigits[(part >> 4) & 15]);
        APPEND(hexdigits[part & 15]);
        if (ii < 7)
            APPEND(':');
    }
    APPEND('\0');
#undef APPEND

    return pos - 1;
}

static unsigned int ipv6_pton(struct sockaddr *sa, UNUSED_ARG(unsigned int socklen), unsigned int *bits, const char *input)
{
    const char *part_start = NULL;
    struct sockaddr_in6 *sin6;
    char *colon;
    char *dot;
    unsigned int part = 0, pos = 0, ii = 0, cpos = 8, n_bits = 128;

    if (!(colon = strchr(input, ':')))
        return 0;
    dot = strchr(input, '.');
    if (dot && dot < colon)
        return 0;
    sin6 = (struct sockaddr_in6*)sa;
    /* Parse IPv6, possibly like ::127.0.0.1.
     * This is pretty straightforward; the only trick is borrowed
     * from Paul Vixie (BIND): when it sees a "::" continue as if
     * it were a single ":", but note where it happened, and fill
     * with zeros afterwards.
     */
    if (input[pos] == ':') {
        if ((input[pos+1] != ':') || (input[pos+2] == ':'))
            return 0;
        cpos = 0;
        pos += 2;
        part_start = input + pos;
    }
    while (ii < 8) {
        if (ct_isxdigit(input[pos])) {
            part = (part << 4) | ct_xdigit_val(input[pos]);
            if (part > 0xffff)
                return 0;
            pos++;
        } else if (input[pos] == ':') {
            part_start = input + ++pos;
            if (input[pos] == '.')
                return 0;
            sin6->sin6_addr.s6_addr[ii * 2] = part >> 8;
            sin6->sin6_addr.s6_addr[ii * 2 + 1] = part & 255;
            ii++;
            part = 0;
            if (input[pos] == ':') {
                if (cpos < 8)
                    return 0;
                cpos = ii;
                pos++;
            }
        } else if (input[pos] == '.') {
            uint32_t ip4;
            unsigned int len;
            len = sar_pton_ip4(part_start, &n_bits, &ip4);
            if (!len || (ii > 6))
                return 0;
            memcpy(sin6->sin6_addr.s6_addr + ii * 2, &ip4, sizeof(ip4));
            n_bits += ii * 16;
            ii += 2;
            pos = part_start + len - input;
            break;
        } else if (bits && input[pos] == '/' && isdigit(input[pos + 1])) {
            unsigned int len;
            char *term;

            len = strtoul(input + pos + 1, &term, 10);
            if (term <= input + pos + 1)
                break;
            else if (len > 128)
                return 0;
            n_bits = len;
            pos = term - input;
            break;
        } else if (cpos <= 8) {
            sin6->sin6_addr.s6_addr[ii * 2] = part >> 8;
            sin6->sin6_addr.s6_addr[ii * 2 + 1] = part & 255;
            ii++;
            break;
        } else return 0;
    }
    /* Shift stuff after "::" up and fill middle with zeros. */
    if (cpos < 8) {
        unsigned int jj;
        ii <<= 1;
        cpos <<= 1;
        n_bits = 128;
        for (jj = 0; jj < ii - cpos; jj++)
            sin6->sin6_addr.s6_addr[15 - jj] = sin6->sin6_addr.s6_addr[ii - jj - 1];
        for (jj = 0; jj < 16 - ii; jj++)
            sin6->sin6_addr.s6_addr[cpos + jj] = 0;
    }
    if (bits)
        *bits = n_bits;
    sa->sa_family = AF_INET6;
    return pos;
}

static int ipv6_get_port(const struct sockaddr *sa, UNUSED_ARG(unsigned int socklen))
{
    return ntohs(((const struct sockaddr_in6*)sa)->sin6_port);
}

static int ipv6_set_port(struct sockaddr *sa, UNUSED_ARG(unsigned int socklen), unsigned short port)
{
    ((struct sockaddr_in6*)sa)->sin6_port = htons(port);
    return 0;
}

static unsigned int ipv6_addr_request(struct sar_request *req, const char *node, const char *srv_node, unsigned int flags)
{
    unsigned int len;
    if (flags & SAI_V4MAPPED) {
        if (srv_node)
            len = sar_request_build(req, NULL, node, REQ_TYPE_AAAA, node, REQ_TYPE_A, srv_node, REQ_TYPE_SRV, NULL);
        else
            len = sar_request_build(req, NULL, node, REQ_TYPE_AAAA, node, REQ_TYPE_A, NULL);
    } else {
        if (srv_node)
            len = sar_request_build(req, NULL, node, REQ_TYPE_AAAA, srv_node, REQ_TYPE_SRV, NULL);
        else
            len = sar_request_build(req, NULL, node, REQ_TYPE_AAAA, NULL);
    }
    return len;
}

static void ipv6_ptr_name(struct sar_getname_state *state, const struct sockaddr *sa, UNUSED_ARG(unsigned int socklen))
{
    const uint8_t *bytes;
    unsigned int ii, jj;

    bytes = ((struct sockaddr_in6*)sa)->sin6_addr.s6_addr;
    memcpy(state->original, bytes, 16);
    for (jj = 0, ii = 16; ii > 0; ) {
        state->name[jj++] = hexdigits[bytes[--ii] & 15];
        state->name[jj++] = hexdigits[bytes[ii] >> 4];
        state->name[jj++] = '.';
    }
    strcpy(state->name + jj, ".ip6.arpa");
    state->doing_arpa = 1;
}

static int ipv6_decode(struct sar_getaddr_state *state, struct dns_rr *rr, unsigned char *raw, UNUSED_ARG(unsigned int raw_size))
{
    struct sockaddr_in6 *sa;
    struct addrinfo *ai;

    if (state->flags & SAI_CANONNAME) {
        ai = xmalloc(sizeof(*ai) + sizeof(*sa) + strlen(rr->name) + 1);
        sa = (struct sockaddr_in6*)(ai->ai_addr = (struct sockaddr*)(ai + 1));
        ai->ai_canonname = strcpy((char*)(sa + 1), rr->name);
    } else {
        ai = xmalloc(sizeof(*ai) + sizeof(*sa));
        sa = (struct sockaddr_in6*)(ai->ai_addr = (struct sockaddr*)(ai + 1));
        ai->ai_canonname = NULL;
    }

    if (rr->rdlength == 4) {
        sa->sin6_addr.s6_addr[10] = sa->sin6_addr.s6_addr[11] = 0xff;
        memcpy(sa->sin6_addr.s6_addr + 12, raw + rr->rd_start, 4);
    } else if (rr->rdlength == 16) {
        memcpy(sa->sin6_addr.s6_addr, raw + rr->rd_start, 16);
    } else {
        xfree(ai);
        return 0;
    }

    ai->ai_family = AF_INET6;
    sa->sin6_port = htons(state->port);
    return sar_getaddr_append(state, ai, 1);
}

static struct sar_family_helper sar_ipv6_helper = {
    "::1",
    "::",
    sizeof(struct sockaddr_in6),
    AF_INET6,
    ipv6_ntop,
    ipv6_pton,
    ipv6_get_port,
    ipv6_set_port,
    ipv6_addr_request,
    ipv6_ptr_name,
    ipv6_decode,
    NULL
};

#endif /* defined(AF_INET6) */

static void sar_cleanup(void)
{
    event_del(&sar_fd);
    set_clear(&sar_nameservers, 0);
    set_clear(&services_byname, 0);
    set_clear(&services_byport, 0);
}

void sar_init(void)
{
    reg_exit_func(sar_cleanup);
    sar_log = log_type_register("resolver", NULL);
    conf.sar_root = conf_register_object(NULL, "resolver");
    services_byname.compare = set_compare_charp;
    services_byport.compare = set_compare_int;
    evtimer_set(&sar_timeout, sar_timeout_cb, &sar_timeout);

    sar_register_helper(&sar_ipv4_helper);
#if defined(AF_INET6)
    sar_register_helper(&sar_ipv6_helper);
#endif

    sar_dns_init("/etc/resolv.conf");
    sar_services_init("/etc/services");
}
