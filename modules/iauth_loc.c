/* iauth_loc.c - IAuth login-on-connect (LoC) implementation
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

/* Functional specification:
 *
 * When a client sends "PASS :<account> <password>", this module sends
 * a request to its configured server and places a hold on the client.
 * When a final response comes back ("OK", "NO" or unlinked), it
 * releases the hold, and for "OK" responses sets the account stamp.
 * A non-final response ("MORE") passes its message to the client.
 *
 * If the "ipr" configuration value is set, this includes the client's
 * IP address and hostname in the login message it sends.
 */

#include "modules/iauth.h"

struct iauth_loc_password {
    /** Pointer to #iauth_loc. */
    void *key;
    /** Account name concatenated with password. */
    char password[1];
};

static struct {
    struct conf_node_object *root;
    struct conf_node_string *server;
    struct conf_node_string *ipr;
} conf;

static struct {
    unsigned int queries;
    unsigned int good;
    unsigned int bad;
    unsigned int unlinked;
} stats;

static struct iauth_module iauth_loc;
static struct log_type *iauth_loc_log;

static void iauth_loc_get_config(void)
{
    iauth_report_config(&iauth_loc, "%s", conf.server->value);
}

static void iauth_loc_get_stats(void)
{
    iauth_report_config(&iauth_loc, "%u %u %u %u", stats.queries, stats.good,
                        stats.bad, stats.unlinked);
}

static struct iauth_request *iauth_loc_request(const char routing[])
{
    irc_inaddr addr;
    struct iauth_request *req;
    char *sep;
    unsigned len;
    int id;
    unsigned short port;

    /* Parse the routing tag. */
    id = strtol(routing, &sep, 10);
    if (sep[0] != '/')
        return NULL;
    len = irc_pton(&addr, NULL, sep + 1, 1);
    if (sep[len+1] != '/')
        return NULL;
    port = strtol(sep+len+2, &sep, 10);
    if (sep[0] != '\0')
        return NULL;

    /* Look up the client and check that it is the correct one. */
    req = iauth_find_request(id);
    if (!req || port != req->remote_port
        || 0 != irc_inaddr_cmp(&addr, &req->remote_addr))
        return NULL;
    return req;
}

static void iauth_loc_x_reply(const char server[], const char routing[], const char reply[])
{
    struct iauth_request *req;

    req = iauth_loc_request(routing);
    if (!req)
        return;
    if (conf.server->value == NULL || 0 != strcmp(server, conf.server->value))
        return;

    if (0 == memcmp(reply, "OK ", 3)) {
        int ii;

        --req->soft_holds;
        for (ii = 3; (reply[ii] != ' ') && (reply[ii] != '\0') && ii < ACCOUNTLEN; ++ii)
            req->account[ii-3] = reply[ii];
        for (; ii < ACCOUNTLEN+3+1; ++ii)
            req->account[ii-3] = '\0';
        iauth_check_request(req);
    } else if (0 == memcmp(reply, "NO ", 3)) {
        --req->soft_holds;
        iauth_challenge(req, reply + 3);
        iauth_check_request(req);
    } else if (0 == memcmp(reply, "MORE ", 5)) {
        iauth_challenge(req, reply + 5);
        /* No need to check the request state right now. */
    } else {
        log_message(iauth_loc_log, LOG_WARNING, "Unexpected XR reply: %s", reply);
    }
}

static void iauth_loc_x_unlinked(const char server[], const char routing[],
                                 UNUSED_ARG(const char message[]))
{
    struct iauth_request *req;

    req = iauth_loc_request(routing);
    if (!req)
        return;
    if (conf.server->value == NULL || 0 != strcmp(server, conf.server->value))
        return;

    --req->soft_holds;
    iauth_challenge(req, "Login server unavailable");
    iauth_check_request(req);
}

static void iauth_loc_send_login(struct iauth_request *req, const char password[],
                                 struct iauth_loc_password *pw)
{
    /* Do we have all the information we need? */
    if (!conf.ipr->parsed.p_boolean
        || (BITSET_GET(req->flags, IAUTH_GOT_HOSTNAME)
            && BITSET_GET(req->flags, IAUTH_GOT_IDENT))) {
        char routing[IRC_NTOP_MAX + 20];
        char address[IRC_NTOP_MAX];

        irc_ntop(address, sizeof(address), &req->remote_addr);
        snprintf(routing, sizeof(routing), "%d/%s/%hu",
                 req->client, address, req->remote_port);

        if (!conf.ipr->parsed.p_boolean)
            iauth_x_query(conf.server->value, routing, "LOGIN %s", password);
        else if (req->hostname[0] != '\0')
            iauth_x_query(conf.server->value, routing, "LOGIN2 %s %s %s %s",
                          address, req->hostname, req->username, password);
        else
            iauth_x_query(conf.server->value, routing, "LOGIN2 %s . %s %s",
                          address, req->username, password);
    } else if (!pw) {
        /* Create a structure to record password data. */
        size_t pwlen = strlen(password);
        struct set_node *node = set_node_alloc(sizeof(*pw) + pwlen);
        pw = set_node_data(node);
        pw->key = &iauth_loc;
        strcpy(pw->password, password);
        set_insert(&req->data, node);
    }
}

static void iauth_loc_got_additional(struct iauth_request *req)
{
    void *ptr = &iauth_loc;
    struct iauth_loc_password *pw = set_find(&req->data, &ptr);
    if (pw) {
        iauth_loc_send_login(req, pw->password, pw);
        set_remove(&req->data, &ptr, 0);
    }
}

static void iauth_loc_password(struct iauth_request *req, const char password[])
{
    if (strchr(password, ' ') != NULL && conf.server->value != NULL) {
        void *ptr = &iauth_loc;
        struct iauth_loc_password *pw = set_find(&req->data, &ptr);
        iauth_loc_send_login(req, password, pw);
        ++req->soft_holds;
    }
}

static struct iauth_module iauth_loc = {
    .owner = "iauth_loc",
    .get_config = iauth_loc_get_config,
    .get_stats = iauth_loc_get_stats,
    .got_hostname = iauth_loc_got_additional,
    .got_ident = iauth_loc_got_additional,
    .got_x_reply = iauth_loc_x_reply,
    .got_x_unlinked = iauth_loc_x_unlinked,
    .no_hostname = iauth_loc_got_additional,
    .password = iauth_loc_password,
};

static void iauth_loc_ipr_changed(struct conf_node_base *node)
{
    if (node == &conf.ipr->base)
    {
        if (conf.ipr->parsed.p_boolean)
            BITSET_SET(iauth_loc.policies, IAUTH_SEND_NICKNAME_ETC);
        else
            BITSET_CLEAR(iauth_loc.policies, IAUTH_SEND_NICKNAME_ETC);
    }
}

void module_constructor(UNUSED_ARG(const char name[]))
{
    iauth_loc_log = log_type_register("iauth_loc", NULL);
    module_depends("iauth", NULL);
    conf.root = conf_register_object(NULL, "iauth_loc");
    conf.server = conf_register_string(conf.root, CONF_STRING_PLAIN, "server", NULL);
    conf.ipr = conf_register_string(conf.root, CONF_STRING_BOOLEAN, "ipr", "false");
    conf.ipr->base.hook = iauth_loc_ipr_changed;
    iauth_loc_ipr_changed(&conf.ipr->base);
    BITSET_SET(iauth_loc.policies, IAUTH_SEND_USER_AND_PASS);
    BITSET_SET(iauth_loc.policies, IAUTH_PRIOR_APPROVAL);
    iauth_register_module(&iauth_loc);
}

void module_destructor(void)
{
    iauth_unregister_module(&iauth_loc);
}
