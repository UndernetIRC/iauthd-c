/* iauth.c - IAuth interface implementation
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

#include "modules/iauth.h"

#include <unistd.h> /* STDIN_FILENO */

/** Set of all pending IAuth requests. */
static struct set *iauth_reqs;

/** Set of all registered IAuth modules. */
static struct set *iauth_modules;

/** Event descriptor for input data. */
static struct bufferevent *iauth_in;

/** Bitset containing all requested policies. */
static struct iauth_policyset iauth_policies;

/** Bitset containing all requested request state flags. */
static struct iauth_flagset iauth_flags;

/** Log for all iauth messages. */
static struct log_type *iauth_log;

/** Root of IAuth module configuation. */
static struct conf_node_object *iauth_conf;

/** Duration of the request timeout. */
static struct conf_node_string *iauth_conf_timeout;

/** Last assigned serial number. */
static unsigned int iauth_serial;

static void parse_registered(struct iauth_request *req, int from_ircd);

/** Sends a message to the IRCD related to \a req.
 *
 * This function ensures that the message is followed by a newline.
 *
 * \param[in] req IAuth request that describes the context.
 * \param[in] fmt printf()-style format string for the message.
 *  If \a req != NULL, at the first space (or at the end of the string
 *  if it does not contain spaces), IAuth will insert the <id>
 *  <remoteip> <reporteport> sequence that the IRCD expects.
 * \param[in] ... Parameters for the string printing.
 */
static void iauth_send(struct iauth_request *req, const char fmt[], ...)
{
    va_list args;
    size_t pos = 0;
    char msg[1024];

    va_start(args, fmt);
    if (req != NULL)
    {
        /* Copy the first word over. */
        for (; (*fmt != '\0') && !isspace(*fmt) && (pos < sizeof(msg) - 1); )
            msg[pos++] = *fmt++;

        /* Insert the request identifier. */
        if (pos < sizeof(msg))
            pos += snprintf(msg + pos, sizeof(msg) - pos, " %d %s %u",
                            req->client, req->text_addr, req->remote_port);
    }

    pos += vsnprintf(msg + pos, sizeof(msg) - pos, fmt, args);
    va_end(args);
    log_message(iauth_log, LOG_DEBUG, "< %s", msg);
    fputs(msg, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

/** Calculates ::iauth_policies and ::iauth_flags from the registered
 * IAuth modules.  This performs a bitwise or on all the requested
 * flags, but clears any nonsensical flags afterwards.
 */
static void calc_iauth_flags(void)
{
    struct iauth_module *plugin;
    struct set_node *node;

    /* Clear previous flags. */
    memset(&iauth_policies, 0, sizeof(iauth_policies));
    memset(&iauth_flags, 0, sizeof(iauth_flags));

    /* Accumulate from all the registered modules. */
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        BITSET_OR(iauth_policies, iauth_policies, plugin->policies);
        BITSET_OR(iauth_flags, iauth_flags, plugin->need_flags);
    }

    /* Require the full set of IAuth messages we ask for. */
    BITSET_SET(iauth_flags, IAUTH_GOT_HOSTNAME);
    if (BITSET_GET(iauth_policies, IAUTH_SEND_USER_AND_PASS))
        BITSET_SET(iauth_flags, IAUTH_GOT_USER_INFO);
    if (BITSET_GET(iauth_policies, IAUTH_SEND_NICKNAME_ETC)) {
        BITSET_SET(iauth_flags, IAUTH_GOT_NICK);
        BITSET_SET(iauth_flags, IAUTH_GOT_IDENT);
    }

    /* Clear flags that do not make sense. */
    BITSET_CLEAR(iauth_flags, IAUTH_RESPONDED);
}

/** Registers a decision module with the main IAuth module.
 *
 * \param[in] plugin Descriptor of the plugin to register.
 */
void iauth_register_module(struct iauth_module *module)
{
    set_insert(iauth_modules, &module->node);
    /* Flags will be calculated by iauth_startup(). */
}

/** Unregisters a decision module with the main IAuth module.
 *
 * \param[in] plugin Descriptor of the plugin to remove.
 */
void iauth_unregister_module(struct iauth_module *plugin)
{
    set_remove(iauth_modules, plugin, 1);
    calc_iauth_flags();
}

/** Looks up the request for \a client_id.
 *
 * \param[in] client_id ircd-assigned client identifier
 *   (iauth_request::id).
 * \return Pointer to the current request for that id, or NULL if none
 *   exists.
 */
struct iauth_request *iauth_find_request(int client_id)
{
    return set_find(iauth_reqs, &client_id);
}

/** Creates an iauthd-c standard routing string for a request.
 *
 * At the current time, the standard routing format contains the
 * ircd-assigned client identifier, a forward slash, the client's IP
 * address, a forward slash, and the client port number, in that
 * order.
 *
 * \todo Change the format to use a hash of the client info instead
 *
 * \param[in] req Client request to identify.
 * \param[out] routing Receives the routing string.
 * \param[in] routing_len Number of bytes writable to \a routing,
 *   including a NUL terminator.  This should be at least #ROUTINGLEN.
 * \return Zero on success, non-zero on failure.
 */
int iauth_routing(const struct iauth_request *req, char routing[], size_t routing_len)
{
    int needed;

    if (routing_len < 6)
	return 1;

    needed = snprintf(routing, routing_len, "%x_%x",
		      req->client, req->serial);
    if ((needed < 0) || ((size_t)needed >= routing_len)) {
	strcpy(routing, "???"); /* length was checked above */
	return 2;
    }

    return 0;
}

/** Looks up the request identified by \a routing, using the iauthd-c
 * standard routing format.
 *
 * See iauth_routing() for a description of the standard routing
 * string format.
 *
 * \param[in] routing iauthd-c standard routing string for a client.
 * \return Pointer to the current request for that client, or NULL if
 *   none exists.
 */
struct iauth_request *iauth_validate_request(const char routing[])
{
    struct iauth_request *req;
    char *sep;
    unsigned int serial;
    int id;

    /* Parse the routing tag. */
    id = strtol(routing, &sep, 16);
    if (sep[0] != '_')
        return NULL;
    serial = strtoul(sep + 1, &sep, 16);
    if (sep[0] != '\0')
        return NULL;

    /* Look up the client and check that it is the correct one. */
    req = set_find(iauth_reqs, &id);
    if (!req || serial != req->serial)
        return NULL;

    return req;
}

/** Checks the state of \a request, and accepts the client if we have
 * not yet responded for the client.
 *
 * A request must have all of the flags that are set in the
 * iauth_module.need_flags fields of registered modules, must not have
 * any holds, and must not have already gotten a decision.
 *
 * \param[in] request Valid IAuth request to check.
 */
void iauth_check_request(struct iauth_request *request)
{
    if (request->holds == 0
        && !BITSET_GET(request->flags, IAUTH_RESPONDED)
        && !BITSET_H_ANDNOT(iauth_flags, request->flags)) {
        if (request->soft_holds == 0)
            iauth_accept(request);
        else if (!BITSET_GET(request->flags, IAUTH_SOFT_DONE))
            iauth_soft_done(request);
	else
	    log_message(iauth_log, LOG_DEBUG, " -> client %d already had soft done", request->client);
    } else if (request->holds) {
	log_message(iauth_log, LOG_DEBUG, " -> client %d has %d holds",
		    request->client, request->holds);
    } else if (BITSET_GET(request->flags, IAUTH_RESPONDED)) {
	log_message(iauth_log, LOG_DEBUG, " -> already responded for client %d",
		    request->client);
    } else {
	log_message(iauth_log, LOG_DEBUG, " -> client %d still waiting: %#x & ~%#x (plus %d soft holds)",
		    request->client, iauth_flags.bits[0], request->flags.bits[0],
		    request->soft_holds);
    }
}

void iauth_send_opers(const char msg[])
{
    iauth_send(NULL, "> :%s", msg);
}

void iauth_set_debug_level(int level)
{
    iauth_send(NULL, "G %d", level);
}

void iauth_report_config(struct iauth_module *module, const char fmt[], ...)
{
    const size_t pfx_len = strlen("iauth_");
    const char *name = module->owner;
    va_list args;
    char config[1024];

    if (0 == memcmp(name, "iauth_", pfx_len))
        name += pfx_len;
    va_start(args, fmt);
    vsnprintf(config, sizeof(config), fmt, args);
    va_end(args);
    iauth_send(NULL, "A %s :%s", name, config);
}

void iauth_report_stats(struct iauth_module *module, const char fmt[], ...)
{
    const size_t pfx_len = strlen("iauth_");
    const char *name = module->owner;
    va_list args;
    char stats[1024];

    if (0 == memcmp(name, "iauth_", pfx_len))
        name += pfx_len;
    va_start(args, fmt);
    vsnprintf(stats, sizeof(stats), fmt, args);
    va_end(args);
    iauth_send(NULL, "S %s :%s", name, stats);
}

void iauth_x_query(const char server[], const char routing[], const char fmt[], ...)
{
    va_list args;
    char query[1024];

    va_start(args, fmt);
    vsnprintf(query, sizeof(query), fmt, args);
    va_end(args);
    iauth_send(NULL, "X %s %s :%s", server, routing, query);
}

void iauth_force_username(struct iauth_request *req, const char username[])
{
    iauth_send(req, "o %s", username);
    BITSET_SET(req->flags, IAUTH_GOT_IDENT);
    iauth_check_request(req);
}

void iauth_trust_username(struct iauth_request *req, const char username[])
{
    iauth_send(req, "U %s", username);
    BITSET_SET(req->flags, IAUTH_GOT_IDENT);
    iauth_check_request(req);
}

void iauth_weak_username(struct iauth_request *req, const char username[])
{
    iauth_send(req, "u %s", username);
    /* Does not "count" as a final username for state checking. */
}

void iauth_set_hostname(struct iauth_request *req, const char hostname[])
{
    iauth_send(req, "N %s", hostname);
    strncpy(req->hostname, hostname, HOSTLEN);
    BITSET_SET(req->flags, IAUTH_GOT_HOSTNAME);
    iauth_check_request(req);
}

void iauth_set_ip(struct iauth_request *req, const union irc_inaddr *addr)
{
    irc_ntop(req->text_addr, sizeof(req->text_addr), addr);
    iauth_send(req, "I %s", req->text_addr);
    memcpy(&req->remote_addr, addr, sizeof(req->remote_addr));
    /* Does not change anything that affects iauth_check_request(). */
}

void iauth_user_mode(struct iauth_request *req, const char modes[])
{
    assert(modes[0] == '+' || modes[0] == '-');
    iauth_send(req, "M :%s", modes);
    /* Does not change anything that affects iauth_check_request(). */
}

void iauth_challenge(struct iauth_request *req, const char text[])
{
    iauth_send(req, "C :%s", text);
    /* Does not change anything that affects iauth_check_request(). */
}

void iauth_quietly_kill(struct iauth_request *req, const char reason[])
{
    assert(!BITSET_GET(req->flags, IAUTH_RESPONDED));
    BITSET_SET(req->flags, IAUTH_RESPONDED);
    iauth_send(req, "k :%s", reason);
    /* Notify all the modules we are done with this client. */
    parse_registered(req, 0);
}

void iauth_kill(struct iauth_request *req, const char reason[])
{
    assert(!BITSET_GET(req->flags, IAUTH_RESPONDED));
    BITSET_SET(req->flags, IAUTH_RESPONDED);
    iauth_send(req, "k :%s", reason);
    /* Notify all the modules we are done with this client. */
    parse_registered(req, 0);
}

static void notify_pre_registered(struct iauth_request *req)
{
    struct iauth_module *plugin;
    struct set_node *node;

    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->pre_registered != NULL)
            plugin->pre_registered(req);
    }
}

void iauth_accept(struct iauth_request *req)
{
    assert(!BITSET_GET(req->flags, IAUTH_RESPONDED));
    notify_pre_registered(req);
    BITSET_SET(req->flags, IAUTH_RESPONDED);
    if (req->account[0] != '\0' && req->class[0] != '\0')
        iauth_send(req, "R %s %s", req->account, req->class);
    else if (req->account[0] != '\0')
        iauth_send(req, "R %s", req->account);
    else if (req->class[0] != '\0')
        iauth_send(req, "D %s", req->class);
    else
        iauth_send(req, "D");
    /* Notify all the modules we are done with this client. */
    parse_registered(req, 0);
}

void iauth_soft_done(struct iauth_request *req)
{
    BITSET_SET(req->flags, IAUTH_SOFT_DONE);
    iauth_send(req, "d");
}

static void iauth_req_cleanup(void *ptr)
{
    struct iauth_request *req = ptr;
    event_del(&req->timeout);
    set_clear(&req->data);
}

static void iauth_timeout(evutil_socket_t sock, short event, void *datum)
{
    struct iauth_request *req = datum;
    req->soft_holds = 0;
    iauth_check_request(req);
    (void)sock; (void)event;
}

static void parse_new_client(int id, int argc, char *argv[])
{
    struct iauth_module *plugin;
    struct iauth_request *req;
    struct set_node *node;
    struct timeval timeout;

    if (argc < 5)
        return;

    /* Allocate, populate and index the request descriptor. */
    node = set_node_alloc(sizeof(*req));
    req = set_node_data(node);
    req->client = id;
    req->serial = ++iauth_serial;
    req->state = IAUTH_REGISTER;
    irc_pton(&req->remote_addr, NULL, argv[1], 0);
    irc_ntop(req->text_addr, sizeof(req->text_addr), &req->remote_addr);
    req->remote_port = strtol(argv[2], NULL, 10);
    irc_pton(&req->local_addr, NULL, argv[3], 0);
    req->local_port = strtol(argv[4], NULL, 10);
    req->data.compare = set_compare_voidp;
    set_insert(iauth_reqs, node);

    /* Do we have a timeout? */
    timeout.tv_sec = iauth_conf_timeout->parsed.p_interval;
    timeout.tv_usec = 0;
    evtimer_set(&req->timeout, iauth_timeout, req);
    if (timeout.tv_sec > 0)
        evtimer_add(&req->timeout, &timeout);

    /* Broadcast the message. */
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->new_client != NULL)
            plugin->new_client(req);
    }
}

static void parse_disconnect(struct iauth_request *req)
{
    struct iauth_module *plugin;
    struct set_node *node;

    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->disconnect != NULL)
            plugin->disconnect(req);
    }
    set_remove(iauth_reqs, req, 0);
}

static void parse_hostname(struct iauth_request *req, char hostname[])
{
    struct iauth_module *plugin;
    struct set_node *node;

    if (req->hostname[0] != '\0')
        return;
    strncpy(req->hostname, hostname, HOSTLEN);
    BITSET_SET(req->flags, IAUTH_GOT_HOSTNAME);
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->field_change != NULL)
	    plugin->field_change(req, IAUTH_GOT_HOSTNAME);
    }
    iauth_check_request(req);
}

static void parse_no_hostname(struct iauth_request *req)
{
    struct iauth_module *plugin;
    struct set_node *node;

    BITSET_SET(req->flags, IAUTH_GOT_HOSTNAME);
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->field_change != NULL)
            plugin->field_change(req, IAUTH_GOT_HOSTNAME);
    }
    iauth_check_request(req);
}

static void parse_password(struct iauth_request *req, char password[])
{
    struct iauth_module *plugin;
    struct set_node *node;

    BITSET_SET(req->flags, IAUTH_GOT_PASSWORD);
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->password != NULL)
            plugin->password(req, password);
    }
}

static void parse_user_info(struct iauth_request *req, int argc, char *argv[])
{
    struct iauth_module *plugin;
    struct set_node *node;

    if (argc < 5)
        return;
    strncpy(req->cli_username, argv[1], USERLEN);
    strncpy(req->realname, argv[4], REALLEN);
    BITSET_SET(req->flags, IAUTH_GOT_USER_INFO);
    if (BITSET_GET(req->flags, IAUTH_EMPTY_IDENT))
	BITSET_SET(req->flags, IAUTH_GOT_IDENT);
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->user_info != NULL)
            plugin->user_info(req, argv[1], argv[2], argv[3]);
    }
    iauth_check_request(req);
}

static void parse_ident(struct iauth_request *req, char ident[])
{
    struct iauth_module *plugin;
    struct set_node *node;

    if (ident) {
	strncpy(req->auth_username, ident, USERLEN);
	BITSET_SET(req->flags, IAUTH_GOT_IDENT);
    } else if (req->cli_username[0] != '\0')
	BITSET_SET(req->flags, IAUTH_GOT_IDENT);
    else
	BITSET_SET(req->flags, IAUTH_EMPTY_IDENT);

    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->field_change != NULL)
            plugin->field_change(req, IAUTH_GOT_IDENT);
    }
    iauth_check_request(req);
}

static void parse_nick(struct iauth_request *req, char nick[])
{
    struct iauth_module *plugin;
    struct set_node *node;

    strncpy(req->nickname, nick, NICKLEN);
    BITSET_SET(req->flags, IAUTH_GOT_NICK);
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->field_change != NULL)
            plugin->field_change(req, IAUTH_GOT_NICK);
    }
    iauth_check_request(req);
}

static void parse_hurry_up(struct iauth_request *req, char class[])
{
    struct iauth_module *plugin;
    struct set_node *node;

    if (req->class == '\0')
        strncpy(req->class, class, CLASSLEN);
    BITSET_OR(req->flags, req->flags, iauth_flags);
    BITSET_SET(req->flags, IAUTH_GOT_HURRY_UP);
    req->state = IAUTH_HURRY;
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->field_change != NULL)
            plugin->field_change(req, IAUTH_GOT_HURRY_UP);
    }
    iauth_check_request(req);
}

static void parse_registered(struct iauth_request *req, int from_ircd)
{
    struct iauth_module *plugin;
    struct set_node *node;

    req->state = IAUTH_NORMAL;
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->registered != NULL)
            plugin->registered(req, from_ircd);
    }
    set_remove(iauth_reqs, req, 0);
}

static void parse_error(struct iauth_request *req, int argc, char *argv[])
{
    struct iauth_module *plugin;
    struct set_node *node;

    if (argc < 3)
        return;
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->error != NULL)
            plugin->error(req, argv[1], argv[2]);
    }
}

static void parse_server_info(int argc, char *argv[])
{
    struct iauth_module *plugin;
    struct set_node *node;
    int capacity;

    if (argc < 3)
        return;
    capacity = strtol(argv[2], NULL, 10);
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->server_info != NULL)
            plugin->server_info(argv[1], capacity);
    }
}

static void parse_x_reply(int argc, char *argv[])
{
    struct iauth_module *plugin;
    struct set_node *node;

    if (argc < 4)
        return;
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->x_reply != NULL)
            plugin->x_reply(argv[1], argv[2], argv[3]);
    }
}

static void parse_x_unlinked(int argc, char *argv[])
{
    struct iauth_module *plugin;
    struct set_node *node;

    if (argc < 4)
        return;
    for (node = set_first(iauth_modules); node; node = set_next(node)) {
        plugin = ENCLOSING_STRUCT(node, struct iauth_module, node);
        if (plugin->x_unlinked != NULL)
            plugin->x_unlinked(argv[1], argv[2], argv[3]);
    }
}

static void iauth_read(struct bufferevent *buf, UNUSED_ARG(void *arg))
{
    struct iauth_request *req;
    char *argv[16];
    char *line;
    char *sep;
    size_t argc;
    int id;

    /* Parse out the start of the line (simple, standard bits). */
    while ((line = evbuffer_readline(buf->input)) != NULL)
    {
        log_message(iauth_log, LOG_DEBUG, "> %s", line);
        id = strtol(line, &sep, 10);

        /* Parse the remaining arguments. */
        for (argc = 0; argc < ARRAY_LENGTH(argv); ) {
            for (; isspace(*sep); ++sep) {}
            if (*sep == '\0')
                break;
            if (*sep == ':') {
                argv[argc++] = sep + 1;
                break;
            }
            argv[argc++] = sep;
            for (; (*sep != '\0') && !isspace(*sep); ++sep) {}
	    if (*sep == '\0')
		break;
            *sep++ = '\0';
        }
        if (argc < ARRAY_LENGTH(argv))
            argv[argc] = NULL;

        /* If we should know the id, but don't, bail. */
        if (id == -1 || argv[0][0] == 'C')
            req = NULL;
        else if (!(req = set_find(iauth_reqs, &id))) {
            /* We don't log this because it happens during normal
             * client disconnects.
            log_message(iauth_log, LOG_DEBUG, " .. no client found for id %d", id);
            */
            return;
        }

        /* Dispatch based on the command. */
        switch (argv[0][0]) {
        case 'C':
            parse_new_client(id, argc, argv);
            break;
        case 'D':
            parse_disconnect(req);
            break;
        case 'N':
            parse_hostname(req, argv[1]);
            break;
        case 'd':
            parse_no_hostname(req);
            break;
        case 'P':
            parse_password(req, argv[1]);
            break;
        case 'U':
            parse_user_info(req, argc, argv);
            break;
        case 'u':
            parse_ident(req, argv[1]);
            break;
        case 'n':
            parse_nick(req, argv[1]);
            break;
        case 'H':
            parse_hurry_up(req, argv[1]);
            break;
        case 'T':
            parse_registered(req, 1);
            break;
        case 'E':
            parse_error(req, argc, argv);
            break;
        case 'M':
            parse_server_info(argc, argv);
            break;
        case 'X':
            /* id is always -1 with current ircu. */
            parse_x_reply(argc, argv);
            break;
        case 'x':
            /* id is always -1 with current ircu. */
            parse_x_unlinked(argc, argv);
            break;
        }
    }
}

static void iauth_io_error(UNUSED_ARG(struct bufferevent *buf), short events, UNUSED_ARG(void *arg))
{
    if (events & EVBUFFER_EOF) {
        log_message(log_core, LOG_INFO, "Terminating due to EOF on input");
        event_loopbreak();
    }
}

static void iauth_startup(UNUSED_ARG(int fd), UNUSED_ARG(short evt), UNUSED_ARG(void *arg))
{
    char policies[64] = "ARTUW";
    int pos;
    int ii;

    iauth_send(NULL, "V %s %s", PACKAGE_NAME, iauthd_version);

    calc_iauth_flags();

    for (ii = pos = 0; policies[ii] != '\0'; ++ii) {
        if (BITSET_GET(iauth_policies, ii))
            policies[pos++] = policies[ii];
    }

    if (pos > 0) {
        policies[pos] = '\0';
        iauth_send(NULL, "O %s", policies);
    }
}

void module_constructor(UNUSED_ARG(const char name[]))
{
    struct timeval tv_zero;

    tv_zero.tv_sec = 0;
    tv_zero.tv_usec = 0;
    iauth_log = log_type_register("iauth", NULL);
    iauth_reqs = set_alloc(set_compare_int, iauth_req_cleanup);
    iauth_modules = set_alloc(set_compare_charp, NULL);
    iauth_conf = conf_register_object(NULL, "iauth");
    iauth_conf_timeout = conf_register_string(iauth_conf, CONF_STRING_INTERVAL, "timeout", "0");
    event_once(-1, EV_TIMEOUT, iauth_startup, NULL, &tv_zero);
    iauth_in = bufferevent_new(STDIN_FILENO, iauth_read, NULL, iauth_io_error, NULL);
    bufferevent_enable(iauth_in, EV_READ);
}

void module_destructor(void)
{
    set_clear(iauth_reqs);
    free(iauth_reqs);
    set_clear(iauth_modules);
    free(iauth_modules);
}
