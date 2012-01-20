/* iauth.h - IAuth interface declarations
 *
 * Copyright 2011 Michael Poole <mdpoole@troilus.org>
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

#if !defined(IAUTH_H_23889f60_9ad5_4674_8c67_ee44f53cbc74)

/** Multiple-inclusion guard for "src/iauth.h". */
#define IAUTH_H_23889f60_9ad5_4674_8c67_ee44f53cbc74

#include "src/common.h"

typedef union irc_inaddr {
    uint16_t in6[8]; /* each part in network byte order */
    uint8_t  in6_8[16];
    uint16_t in6_16[8];
    uint32_t in6_32[4];
} irc_inaddr;

/** Evaluates to non-zero if ADDR looks valid. */
#define irc_inaddr_is_valid(ADDR) (((ADDR).in6[0] && (ADDR).in6[0] != 65535) \
                                   || (ADDR).in6_32[1] != (ADDR).in6_32[0] \
                                   || (ADDR).in6_32[2] != (ADDR).in6_32[0] \
                                   || (ADDR).in6_32[3] != (ADDR).in6_32[0])
/** Evaluates to non-zero if ADDR looks like an IPv4 address. */
#define irc_inaddr_is_ipv4(ADDR) (!(ADDR).in6_32[0] && !(ADDR).in6_32[1] \
                                  && !(ADDR).in6[4] && (ADDR).in6[6] \
                                  && (!(ADDR).in6[5] || (ADDR).in6[5] == 65535))
/** Evaluates to non-zero if ADDR looks like an IPv6 address. */
#define irc_inaddr_is_ipv6(ADDR) !irc_inaddr_is_ipv4(ADDR)
/** Compares two irc_inaddr structs; suitable as a set comparator. */
int irc_inaddr_cmp(const void *a_, const void *b_);

/** Maximum number of characters needed for irc_ntop() output buffer. */
#define IRC_NTOP_MAX 40
/** Converts an irc_inaddr to text and returns number of characters
 * needed, not including terminating nul character.
 */
unsigned int irc_ntop(char *output, unsigned int out_size, const irc_inaddr *addr);
/** Converts text to an irc_inaddr and returns number of characters
 * read (0 on error).  If bits != NULL, allows a trailing CIDR-style
 * netmask specifier and wildcard notation; if one is present, also
 * accepts slightly misformed addresses (missing trailing bits, as in
 * 192.168/16).  If "allow_trailing" is non-zero, allows there to be
 * other trailing characters.
 */
unsigned int irc_pton(irc_inaddr *addr, unsigned int *bits, const char *input, int allow_trailing);
/** Indicates whether the most significant N bits of an address match a mask.
 *  Returns non-zero if the leading bits match.
 */
unsigned int irc_check_mask(const irc_inaddr *check, const irc_inaddr *mask, unsigned int bits);

/** Number of bytes allowed in a client's nickname. */
#define NICKLEN 30

/** Number of bytes allowed in a stamped account identifier.  This is
 * larger than IRC's normal value to allow the account timestamp and
 * serial number to be included in the text form (two ':'s and up to
 * 32 digits).
 */
#define ACCOUNTLEN 64

/** Number of bytes allowed in a client's user name (ident). */
#define USERLEN 10

/** Number of bytes allowed in a client host name. */
#define HOSTLEN 63

/** Number of bytes allowed in the user-supplied information (GECOS or
 * real name).
 */
#define REALLEN 50

/** Number of bytes allowed in the connection class. */
#define CLASSLEN 63

/** Possible states for a client (with respect to IAuth). */
enum iauth_client_state {
    IAUTH_REGISTER,
    IAUTH_HURRY,
    IAUTH_NORMAL,
    IAUTH_GONE
};

/** Yes/no flags that describe the state of a request. */
enum iauth_flags {
    /** Set when we have made a decision for this request. */
    IAUTH_RESPONDED,
    /** Set when we have sent a "soft done" for this request. */
    IAUTH_SOFT_DONE,
    /** Set when we get an 'N' or 'd' message. */
    IAUTH_GOT_HOSTNAME,
    /** Set when we get a 'u' message. */
    IAUTH_GOT_IDENT,
    /** Set when we get a 'n' message. */
    IAUTH_GOT_NICK,
    /** Set when we get a 'U' message. */
    IAUTH_GOT_USER_INFO,
    IAUTH_NUM_FLAGS
};

/** Helper typedef for IAuth request flags. */
DECLARE_BITSET(iauth_flagset, IAUTH_NUM_FLAGS);

/** Describes a single IAuth request.
 */
struct iauth_request {
    /** IAuth identifier for the client. */
    int client;

    /** Number of "holds" on the client.  IAuth will send a "Done
     * Checking" message if the holds is less than one and it has
     * received all of the standard client information (hostname,
     * username, nickname and realname).
     */
    int holds;

    /** Number of "soft holds" on the client.  IAuth will send a "Soft
     * Done" message when the number of holds less than one but this
     * is positive.
     */
    int soft_holds;

    /** Boolean flags of the request state.
     * Indexed by enum iauth_flags.
     */
    struct iauth_flagset flags;

    /** Current connection state. */
    enum iauth_client_state state;

    /** Remote IP address. */
    union irc_inaddr remote_addr;

    /* Local IP address. */
    union irc_inaddr local_addr;

    /** Remote port number. */
    unsigned short remote_port;

    /** Local port number. */
    unsigned short local_port;

    /** DNS host name for the client. */
    char hostname[HOSTLEN + 1];

    /** Raw ident result for the client. */
    char username[USERLEN + 1];

    /** Client's requested nickname. */
    char nickname[NICKLEN + 1];

    /** Client-supplied real name. */
    char realname[REALLEN + 1];

    /** Pre-authenticated account name (set by plug-ins). */
    char account[ACCOUNTLEN + 1];

    /** Name of connection class to use. */
    char class[CLASSLEN + 1];

    /** Contains submodule-specific data.
     *
     * No special cleanup of the data is performed.  The first element
     * of the data must be a pointer that is unique to the submodule
     * (e.g. to the iauth_module structure).
     */
    struct set data;
};

enum iauth_policies {
    /** IAuth 'A' policy (username and password). */
    IAUTH_SEND_USER_AND_PASS,
    /** IAuth 'R' policy (IAuth approval required). */
    IAUTH_PRIOR_APPROVAL,
    /** IAuth 'T' policy (statistics for 'R' policy refusals). */
    IAUTH_APPROVAL_DIAGNOSTICS,
    /** IAuth 'U' policy (nickname, confirmed username and hurry) */
    IAUTH_SEND_NICKNAME_ETC,
    /** IAuth 'W' policy (allow IAuth extra time based on hostname). */
    IAUTH_EXTRA_TIME,
    /** Number of supported IAuth policies. */
    IAUTH_NUM_POLICIES
};

DECLARE_BITSET(iauth_policyset, IAUTH_NUM_POLICIES);

/** Describes a single IAuth handling plug-in.
 *
 * The owner field must be set; the other fields may be left as zero
 * or null values (except as listed below).
 *
 * Modules that keep per-request state \em must implement the
 * disconnect() and registered() methods; the IAuth core destroys the
 * iauth_request structure after calling either of those methods.
 */
struct iauth_module {
    /** Node used to store IAuth modules */
    struct set_node node;

    /** Name of the module that owns this plug-in. */
    const char *owner;

    /** Bitset of IAuth policy requests by this plug-in. */
    struct iauth_policyset policies;

    /** Bitmask of flags that IAuth should require clients to have
     * before accepting them.  (This can simplify "hold"-like logic
     * for decision modules.)
     */
    struct iauth_flagset need_flags;

    /* Please keep the method list in alphabetical order! */

    /** Handler function for disconnected clients (ircd 'D' message). */
    void (*disconnect)(struct iauth_request *req);
    /** Handler function to request configuration.  The module should
     * report them by calling iauth_report_config().
     */
    void (*get_config)(void);
    /** Handler function to request statistics.  The module should
     * report them by calling iauth_report_stats().
     */
    void (*get_stats)(void);
    /** Handler function for errors (ircd 'E' message).  The request
     * may be null if the message is not associated with any client.
     */
    void (*got_error)(struct iauth_request *req, const char type[], const char info[]);
    /** Handler function for client hostnames (ircd 'N' message).
     * The new hostname is stored in \a req->hostname before entry.
     */
    void (*got_hostname)(struct iauth_request *req);
    /** Handler function for ident responses (ircd 'u' message).
     * The username is stored in \a req->username before entry.
     */
    void (*got_ident)(struct iauth_request *req);
    /** Handler function for client nicknames (ircd 'n' message).
     * The nickname is stored in \a req->nickname before entry.
     */
    void (*got_nick)(struct iauth_request *req);
    /** Handler function for server info (ircd 'M' message).
     * Capacity will be -1 if the server did not send it.
     */
    void (*got_server_info)(const char server[], int capacity);
    /** Handler function for an extension query reply. */
    void (*got_x_reply)(const char server[], const char routing[], const char reply[]);
    /** Handler function for the extension server not being linked. */
    void (*got_x_unlinked)(const char server[], const char routing[], const char message[]);
    /** Handler function to hurry up (ircd 'H' message). */
    void (*hurry_up)(struct iauth_request *req, const char class[]);
    /** Handler function for new clients (ircd 'C' message). */
    void (*new_client)(struct iauth_request *req);
    /** Handler function for hostname timeouts (ircd 'd' message).
     * \a req->hostname is cleared before entry.
     */
    void (*no_hostname)(struct iauth_request *req);
    /** Handler function for client passwords (ircd 'P' message). */
    void (*password)(struct iauth_request *req, const char password[]);
    /** Handler function for a registered client (ircd 'T' message),
     * or after IAuth accepts the client.
     */
    void (*registered)(struct iauth_request *req, int from_ircd);
    /** Handler function for client user info (ircd 'U' message).
     * The client user info (if any) is stored in \a req->realname
     * before entry.
     */
    void (*user_info)(struct iauth_request *req, const char username[], const char hostname[], const char server[]);
};

/* These functions are used to (un-)register IAuth decision modules. */
void iauth_register_module(struct iauth_module *plugin);
void iauth_unregister_module(struct iauth_module *plugin);

/* These functions generate IAuth messages to the server. */
void iauth_accept(struct iauth_request *req);
void iauth_soft_done(struct iauth_request *req);
void iauth_challenge(struct iauth_request *req, const char text[]);
void iauth_force_username(struct iauth_request *req, const char username[]);
void iauth_kill(struct iauth_request *req, const char reason[]);
void iauth_quietly_kill(struct iauth_request *req, const char reason[]);
void iauth_report_config(struct iauth_module *module, const char fmt[], ...);
void iauth_report_stats(struct iauth_module *module, const char fmt[], ...);
void iauth_send_opers(const char msg[]);
void iauth_set_debug_level(int level);
void iauth_set_hostname(struct iauth_request *req, const char hostname[]);
void iauth_set_ip(struct iauth_request *req, const union irc_inaddr *addr);
void iauth_trust_username(struct iauth_request *req, const char username[]);
void iauth_user_mode(struct iauth_request *req, const char modes[]);
void iauth_weak_username(struct iauth_request *req, const char username[]);
void iauth_x_query(const char server[], const char routing[], const char fmt[], ...);

/* Asynchronous event handlers can look up requests with this function. */
struct iauth_request *iauth_find_request(int client_id);

/* Asynchronous event handlers that directly change request fields
 * should call this function when they are done.  (It is also called
 * by selected functions that generate IAuth messages, and after
 * broadcasting most state-update messages from the server.)
 */
void iauth_check_request(struct iauth_request *request);

#endif /* !defined(IAUTH_H_23889f60_9ad5_4674_8c67_ee44f53cbc74) */
