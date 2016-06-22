/* iauth_xquery.c - IAuth interface to XQUERY-based auth services
 *
 * Copyright 2013-2014 Michael Poole <mdpoole@troilus.org>
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

/* Intended use cases:
 *
 * One or more services answer to XQUERY and use XREPLY to handle
 * authentication and/or authorization decisions for the network.  For
 * example, a login service can provide login-on-connect (account
 * stamps) based on a password that the client sends, and an
 * anti-proxy service could check blacklists or other data to reject
 * clients that appear to be unwanted bots.
 *
 * Functional specification:
 *
 * As the client's registration process gets enough data for each
 * configured service, this module sends an XQUERY to the service(s)
 * and places a hold on the client.  When this module gets a final
 * response from each service ("OK", "NO" or unlinked), it releases
 * the hold, and performs other command-specific processing.
 *
 * A PASS from the client is only processed if it looks like:
 *  PASS :<mode> <accountname> <password>
 * where <mode> matches the regular expression ([+-][x!]*)+.  If the
 * "net effect" of <mode> is to include +x, this module sends a +x
 * user mode to ircd for the client; if the net effect of <mode>
 * includes +!, this module will only accept the client after
 * assigning an account stamp for them.  The +! modifier allows the
 * user to ensure that their non-masked hostname is not visible to
 * other (non-oper) clients.
 *
 * The XREPLY responses that this module recognizes are:
 *  AGAIN <text>
 *   - Passes <text> to the IRC client as an error message
 *  MORE <text>
 *   - Passes <text> to the IRC client as a challenge
 *  NO <message>
 *   - Rejects the client, with the specified message (may be empty)
 *  OK [account[:12345]]
 *   - Accepts the client, with an optional account stamp
 *  service unlinked ('x' IAuth response)
 *   - Accepts the client, no account stamp applied
 *
 * Only the first account stamp is kept, and any NO message will
 * veto the client.  In addition, account stamps are only accepted
 * from login and login-ipr services.
 *
 * The XQUERY syntax is controlled by the service type, which is
 * selected by the right-hand side of each entry in this module's
 * config file block.
 *
 * The supported service types are:
 *  login - LOGIN <accountname password>
 *  login-ipr - LOGIN2 <ip-addr> <hostname> <username> <accountname password>
 *  dronecheck - CHECK <nickname> <username> <ip-addr> <hostname> <realname>
 *  combined - CHECK <nickname> <username> <ip-addr> <hostname> <realname>,
 *   then LOGIN <accountname password>
 *
 * Account stamps are ignored for "dronecheck" services' OK messages.
 *
 * Because both the "realname" field and the "password" field can
 * contain spaces, they must be at the end of the line, which means a
 * combined login+drone-checking service needs at least two lines from
 * IAuth.
 */

#include "modules/iauth.h"

enum iauth_xquery_mode {
    /** +x user mode: mask real hostname using account name */
    IAUTH_XQUERY_HIDDEN_HOST,
    /** +! pseudo-mode: require account stamp for approval */
    IAUTH_XQUERY_HIDDEN_ONLY,
    /** Number of iauth_xquery modes. */
    IAUTH_XQUERY_NUM_MODES
};

DECLARE_BITSET(iauth_xquery_modes, IAUTH_XQUERY_NUM_MODES);

struct iauth_xquery_client {
    /** Pointer to #iauth_xquery. */
    void *key;

    /** Modes that this user has selected. */
    struct iauth_xquery_modes modes;

    /** Bitmask of services this client has been reported to. */
    uint32_t sent_mask;

    /** Bitmask of services this client needs final responses from. */
    uint32_t ref_mask;

    /** Bitmask of services that sent MORE responses to this client. */
    uint32_t more_mask;

    /** Account name concatenated with password; empty if unknown.
     *
     * This is the value passed by the client in its *first* PASSWORD
     * message.  Later PASSWORD messages are assumed to be responses
     * to MORE challenges, and are sent back to the server(s) with
     * bits set in #more_mask.
     */
    char password[512];
};

enum iauth_xquery_type {
    LOGIN,
    LOGIN_IPR,
    DRONECHECK,
    COMBINED
};

/* This MUST be indexed the same as the #iauth_xquery_type enum. */
static const char *type_names[] = {
    "login",
    "login-ipr",
    "dronecheck",
    "combined"
};

struct iauth_xquery_service {
    /** Number of clients who need reponses from this service. */
    unsigned int refs;

    /** Type of service, from configuration file. */
    enum iauth_xquery_type type;

    /** If non-zero, this service is (still) mentioned in the config file. */
    int configured;

    /** Total number of queries sent to this service. */
    unsigned int queries;

    /** Number of "OK" responses from this service with account stamps. */
    unsigned int good_acct;

    /** Number of simple "OK" responses from this service. */
    unsigned int good_no_acct;

    /** Number of "NO" responses from this service. */
    unsigned int bad;

    /** Number of "NO" responses received for a client that got an
     * account stamp.
     */
    unsigned int bad_acct;

    /** Number of unlinked responses for this service. */
    unsigned int unlinked;

    /** Name of the service. */
    char name[1];
};

DECLARE_VECTOR(iauth_xquery_services, struct iauth_xquery_service *);

static struct {
    struct conf_node_object *root;
} conf;

static struct iauth_module iauth_xquery;
static struct log_type *iauth_xquery_log;
static struct iauth_xquery_services iauth_xquery_services;
static struct iauth_flagset iauth_xquery_flags[4];

DEFINE_VECTOR(iauth_xquery_services, struct iauth_xquery_service *);

static const char *type_text(enum iauth_xquery_type t)
{
    unsigned idx = t;
    if (idx < sizeof(type_names) / sizeof(type_names[0]))
	return type_names[idx];
    return "unknown";
}

static void iauth_xquery_report_config(void)
{
    unsigned int ii;

    for (ii = 0; ii < iauth_xquery_services.used; ++ii) {
	struct iauth_xquery_service *srv = iauth_xquery_services.vec[ii];

	if (!srv)
	    continue;
	iauth_report_config(&iauth_xquery, "%c%s %s",
			    srv->configured ? ' ' : '-',
			    srv->name, type_text(srv->type));
    }
}

static void iauth_xquery_report_stats(void)
{
    unsigned int ii;

    for (ii = 0; ii < iauth_xquery_services.used; ++ii) {
	struct iauth_xquery_service *srv = iauth_xquery_services.vec[ii];

	if (!srv)
	    continue;
	iauth_report_stats(&iauth_xquery, "%c%s %u %u %u %u %u %u",
			   srv->configured ? ' ' : '-',
			   srv->name, srv->queries,
			   srv->good_acct, srv->good_no_acct,
			   srv->bad, srv->bad_acct, srv->unlinked);
    }
}

static void iauth_xquery_unref(unsigned int ii)
{
    struct iauth_xquery_service *srv;

    /* Does this service (still) exist? */
    if (ii >= iauth_xquery_services.used)
	return;
    srv = iauth_xquery_services.vec[ii];
    if (!srv || (srv->refs > 0) || srv->configured)
	return;

    /* If not, free it. */
    iauth_xquery_services.vec[ii] = NULL;
    xfree(srv);
}

static void iauth_xquery_set_account(struct iauth_request *req,
				     const char account[])
{
    int ii;

    for (ii = 0; (account[ii] != ' ') && (account[ii] != '\0') && (ii < ACCOUNTLEN); ++ii)
	req->account[ii] = account[ii];
    for (; ii < ACCOUNTLEN+1; ++ii)
	req->account[ii] = '\0';
}

static void iauth_xquery_x_reply(const char service[], const char routing[],
				 const char reply[])
{
    struct iauth_xquery_client *cli;
    struct iauth_xquery_service *srv = NULL;
    struct iauth_request *req;
    void *ptr;
    unsigned int ii;

    /* Find the client. */
    req = iauth_validate_request(routing);
    if (!req)
        return;
    ptr = &iauth_xquery;
    cli = set_find(&req->data, &ptr);
    if (!cli)
	return;

    /* See if this is a response from a service that we are waiting for. */
    for (ii = 0; ii < iauth_xquery_services.used; ++ii) {
	if ((cli->ref_mask & (1u << ii)) == 0)
	    continue;
	srv = iauth_xquery_services.vec[ii];
	if ((srv != NULL) && (0 == strcmp(service, srv->name)))
	    break;
    }
    if (!srv)
	return;

    /* Update both the client's record and the service's. */
    cli->ref_mask &= ~(1u << ii);
    if (--srv->refs == 0)
	iauth_xquery_unref(ii);

    /* Handle the response. */
    if (!reply) {
	srv->unlinked++;
        if (srv->type != DRONECHECK)
            iauth_challenge(req, "The login server is currently disconnected.  Please excuse the inconvenience.");
    } else if (reply[0] == 'O' && reply[1] == 'K'
	       && (reply[2] == '\0' || reply[2] == ' ')) {
	if (reply[2] != ' ') {
	    srv->good_no_acct++;
	} else if ((srv->type == LOGIN)
		   || (srv->type == LOGIN_IPR)
		   || (srv->type == COMBINED)) {
	    iauth_xquery_set_account(req, reply + 3);
	    if (BITSET_GET(cli->modes, IAUTH_XQUERY_HIDDEN_ONLY))
		req->holds--;
	    /* TODO: maybe count clients who get account stamps *and*
	     * NO responses (this would require different refcounting
	     * on NO responses).
	     */
	    srv->good_acct++;
	} else {
	    log_message(iauth_xquery_log, LOG_WARNING,
			"Ignoring OK <account> from non-login service %s",
			srv->name);
	    srv->good_no_acct++;
	}

	if (cli->ref_mask == 0) {
	    --req->soft_holds;
	    if (BITSET_GET(cli->modes, IAUTH_XQUERY_HIDDEN_HOST))
		iauth_user_mode(req, "+x");
	    iauth_check_request(req);
	}
    } else if (0 == memcmp(reply, "NO ", 3)) {
	srv->bad++;
	if (req->account[0] != '\0')
	    srv->bad_acct++;
	iauth_kill(req, reply + 3);
    } else if (0 == memcmp(reply, "AGAIN ", 6)) {
        iauth_challenge(req, reply + 6);
    } else if (0 == memcmp(reply, "MORE ", 5)) {
        cli->more_mask |= 1u << ii;
        iauth_challenge(req, reply + 5);
    } else {
        log_message(iauth_xquery_log, LOG_WARNING, "Unexpected XR reply: %s", reply);
    }
}

static void iauth_xquery_x_unlinked(const char service[], const char routing[],
				    UNUSED_ARG(const char message[]))
{
    iauth_xquery_x_reply(service, routing, NULL);
}

static void iauth_xquery_new_client(struct iauth_request *req)
{
    struct iauth_xquery_client *cli;
    struct set_node *node;

    node = set_node_alloc(sizeof(*cli));
    cli = set_node_data(node);
    cli->key = &iauth_xquery;
    set_insert(&req->data, node);
}

static void iauth_xquery_check(struct iauth_request *req,
			       enum iauth_flags flag)
{
    struct iauth_xquery_client *cli;
    struct iauth_xquery_service *srv;
    const char *hostname;
    void *ptr;
    unsigned int ii;
    char routing[ROUTINGLEN];
    char username[USERLEN+1];

    /* Find the client's state struct. */
    ptr = &iauth_xquery;
    cli = set_find(&req->data, &ptr);
    if (!cli)
	return;

    /* Send the request off to the xquery services. */
    routing[0] = '\0';
    username[0] = '\0';
    for (ii = 0; ii < iauth_xquery_services.used; ++ii) {
	srv = iauth_xquery_services.vec[ii];
	if (!srv || !srv->configured)
	    continue; /* empty or disabled server slot */

	if ((cli->sent_mask & (1u << ii))
            && ((flag != IAUTH_GOT_PASSWORD)
                || (srv->type == DRONECHECK)))
	    continue; /* already asked this server */

	if (BITSET_H_ANDNOT(iauth_xquery_flags[srv->type], req->flags))
	    continue; /* missing necessary information */

	if (routing[0] == '\0')
	    iauth_routing(req, routing, sizeof(routing));

	/* Populate username (if we need it). */
	if ((srv->type != LOGIN) && (username[0] == '\0')) {
	    if (req->auth_username[0] != '\0') {
		strncpy(username, req->auth_username, USERLEN);
	    } else if (req->cli_username[0] != '\0') {
		username[0] = '~';
		strncpy(username + 1, req->cli_username, USERLEN-1);
	    }
	}

	hostname = req->hostname[0] ? req->hostname : req->text_addr;

	if (srv->type == DRONECHECK || srv->type == COMBINED)
	    iauth_x_query(srv->name, routing,
			  "CHECK %s %s %s %s :%s",
			  req->nickname, username, req->text_addr,
			  hostname, req->realname);

	if (srv->type == LOGIN || srv->type == COMBINED)
	    iauth_x_query(srv->name, routing, "LOGIN :%s", cli->password);
	else if (srv->type == LOGIN_IPR)
	    iauth_x_query(srv->name, routing, "LOGIN2 %s %s %s :%s",
			  req->text_addr, hostname, username,
			  cli->password);

	srv->queries++;
	srv->refs++;
	if (!cli->ref_mask)
	    req->soft_holds++;
	cli->ref_mask |= 1u << ii;
	cli->sent_mask |= 1u << ii;
    }
}

static void iauth_xquery_check_password(struct iauth_request *req,
                                        struct iauth_xquery_client *cli,
                                        const char password[])
{
    struct iauth_xquery_modes m_set;
    struct iauth_xquery_modes m_clr;
    const char *pw = password;
    int was_hidden_only;
    int is_hidden_only;
    int no_account;
    int set = 0;

    BITSET_ZERO(m_set);
    BITSET_ZERO(m_clr);

    /* Parse the <mode> part of 'password'. */
    if ((*pw != '-') && (*pw != '+'))
	return;
    while (*pw != ' ') {
	switch (*pw++) {
	case '+': set = 1; break;
	case '-': set = 0; break;

#define MODE(VALUE) do {                                \
                if (set) {                              \
                    BITSET_SET(m_set, (VALUE));         \
                    BITSET_CLEAR(m_clr, (VALUE));       \
                } else {                                \
                    BITSET_CLEAR(m_set, (VALUE));       \
                    BITSET_SET(m_clr, (VALUE));         \
                }                                       \
	    } while(0)
	case 'x': MODE(IAUTH_XQUERY_HIDDEN_HOST); break;
	case '!': MODE(IAUTH_XQUERY_HIDDEN_ONLY); break;
#undef MODE
	}
    }

    /* Skip any spaces. */
    while (*pw == ' ') pw++;

    /* Check that there is a separation between <accountname> and
     * <password>.
     */
    if (!strchr(pw, ' '))
	return;

    /* Update the client's requested modes. */
    was_hidden_only = BITSET_GET(cli->modes, IAUTH_XQUERY_HIDDEN_ONLY);
    BITSET_ANDNOT(cli->modes, cli->modes, m_clr);
    BITSET_OR(cli->modes, cli->modes, m_set);
    is_hidden_only = BITSET_GET(cli->modes, IAUTH_XQUERY_HIDDEN_ONLY);
    no_account = req->account[0] == '\0';
    if (is_hidden_only && !was_hidden_only && no_account)
	req->holds++;
    else if (!is_hidden_only && was_hidden_only && no_account)
	req->holds--;

    /* Looks good, save and send the password. */
    strncpy(cli->password, pw, sizeof(cli->password));
    iauth_xquery_check(req, IAUTH_GOT_PASSWORD);
}

static void iauth_xquery_password(struct iauth_request *req,
				  const char password[])
{
    struct iauth_xquery_client *cli;
    void *ptr;
    unsigned int ii;

    /* Look up our state structure for the client. */
    ptr = &iauth_xquery;
    cli = set_find(&req->data, &ptr);
    if (!cli)
	return;

    if ((cli->more_mask == 0) || (cli->password[0] == '\0')) {
	iauth_xquery_check_password(req, cli, password);
    } else {
	struct iauth_xquery_service *srv;
	char routing[ROUTINGLEN];

	/* Presumably a response to a server's MORE challenge. */
	iauth_routing(req, routing, sizeof(routing));
	for (ii = 0; ii < iauth_xquery_services.used; ++ii) {
	    if (!(cli->more_mask & (1u << ii)))
		continue;

	    srv = iauth_xquery_services.vec[ii];
	    if (!srv || !srv->configured)
		continue;
	    iauth_x_query(srv->name, routing, "MORE %s", password);
	    cli->more_mask &= ~(1u << ii);
	}
    }
}

static void iauth_xquery_user_info(struct iauth_request *req)
{
    iauth_xquery_check(req, IAUTH_GOT_USER_INFO);
}

static struct iauth_module iauth_xquery = {
    .owner = "iauth_xquery",
    .field_change = iauth_xquery_check,
    .get_config = iauth_xquery_report_config,
    .get_stats = iauth_xquery_report_stats,
    .new_client = iauth_xquery_new_client,
    .password = iauth_xquery_password,
    .user_info = iauth_xquery_user_info,
    .x_reply = iauth_xquery_x_reply,
    .x_unlinked = iauth_xquery_x_unlinked,
};

static void iauth_xquery_config_service(const char *name, const char *type)
{
    struct iauth_xquery_service *srv = NULL;
    unsigned int ii;

    /* Do we already have an entry for this service? */
    for (ii = 0; ii < iauth_xquery_services.used; ++ii) {
	srv = iauth_xquery_services.vec[ii];
	if ((srv != NULL) && (0 == strcmp(srv->name, name)))
	    break;
    }

    /* If not, add it. */
    if (ii == iauth_xquery_services.used) {
	srv = xmalloc(sizeof(*srv) + strlen(name));
	strcpy(srv->name, name);

	/* Try to insert it in an empty slot. */
	for (ii = 0; ii < iauth_xquery_services.used; ++ii) {
	    if (!iauth_xquery_services.vec[ii]) {
		iauth_xquery_services.vec[ii] = srv;
		return;
	    }
	}

	/* If there are no empty slots, append it. */
	if (ii == iauth_xquery_services.used)
	    iauth_xquery_services_append(&iauth_xquery_services, srv);
    }

    /* Look up the type of the service. */
    for (ii = 0; ii < ARRAY_LENGTH(type_names); ++ii) {
	if (!strcasecmp(type, type_names[ii])) {
	    srv->type = (enum iauth_xquery_type)ii;
	    break;
	}
    }
    if (ii == ARRAY_LENGTH(type_names)) {
	srv->configured = 0;
	return;
    }

    /* Mark this service as configured. */
    srv->configured = 1;
}

static void iauth_xquery_services_changed(struct conf_node_base *node)
{
    struct iauth_xquery_service *srv;
    struct set_node *jj;
    unsigned int ii;

    if (node == &conf.root->base) {
	/* Mark all services as unconfigured. */
	for (ii = 0; ii < iauth_xquery_services.used; ++ii) {
	    srv = iauth_xquery_services.vec[ii];
	    if (srv != NULL)
		srv->configured = 0;
	}

	/* Mark each named service as configured. */
	for (jj = set_first(&conf.root->contents); jj != NULL; jj = set_next(jj)) {
	    struct conf_node_base *base = set_node_data(jj);

	    if (base->type == CONF_STRING) {
		struct conf_node_string *str = set_node_data(jj);
		iauth_xquery_config_service(str->base.name, str->value);
	    } /* else unknown type */
	}

	/* Check for unreferenced services. */
	for (ii = 0; ii < iauth_xquery_services.used; ++ii)
	    iauth_xquery_unref(ii);
    }
}

void module_constructor(UNUSED_ARG(const char name[]))
{
    iauth_xquery_log = log_type_register("iauth_xquery", NULL);
    module_depends("iauth", NULL);
    conf.root = conf_register_object(NULL, "iauth_xquery");
    conf.root->base.hook = iauth_xquery_services_changed;
    iauth_xquery_services_changed(&conf.root->base);
    BITSET_MULTI_SET(iauth_xquery.policies,
		     IAUTH_SEND_USER_AND_PASS,
		     IAUTH_PRIOR_APPROVAL,
		     IAUTH_SEND_NICKNAME_ETC,
		     IAUTH_EXTRA_TIME);
    BITSET_MULTI_SET(iauth_xquery_flags[LOGIN],
		     IAUTH_GOT_PASSWORD);
    BITSET_MULTI_SET(iauth_xquery_flags[LOGIN_IPR],
		     IAUTH_GOT_HOSTNAME,
		     IAUTH_GOT_IDENT,
		     IAUTH_GOT_PASSWORD);
    BITSET_MULTI_SET(iauth_xquery_flags[DRONECHECK],
		     IAUTH_GOT_HOSTNAME,
		     IAUTH_GOT_IDENT,
		     IAUTH_GOT_NICK,
		     IAUTH_GOT_USER_INFO);
    BITSET_OR(iauth_xquery_flags[COMBINED],
	      iauth_xquery_flags[LOGIN],
	      iauth_xquery_flags[DRONECHECK]);
    /* Clear the IAUTH_GOT_PASSWORD flag for a COMBINED service
     * because it should use a password when one is supplied, but send
     * a query even if no password was given.
     */
    BITSET_CLEAR(iauth_xquery_flags[COMBINED],
                 IAUTH_GOT_PASSWORD);
    iauth_register_module(&iauth_xquery);
}

void module_destructor(void)
{
    iauth_unregister_module(&iauth_xquery);
}
