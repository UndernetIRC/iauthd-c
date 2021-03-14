/* iauth.c - IAuth miscellaneous support code
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

int irc_inaddr_cmp(const void *a_, const void *b_)
{
    const irc_inaddr *a = a_;
    const irc_inaddr *b = b_;
    return memcmp(a->in6, b->in6, sizeof(a->in6));
}

unsigned int irc_ntop(char *output, unsigned int out_size, const irc_inaddr *addr)
{
    static const char hexdigits[] = "0123456789abcdef";
    unsigned int pos;

    assert(output);
    assert(addr);

    if (irc_inaddr_is_ipv4(*addr)) {
        unsigned int ip4;

        ip4 = (ntohs(addr->in6[6]) << 16) | ntohs(addr->in6[7]);
        pos = snprintf(output, out_size, "%u.%u.%u.%u", (ip4 >> 24), (ip4 >> 16) & 255, (ip4 >> 8) & 255, ip4 & 255);
   } else {
        unsigned int part, max_start, max_zeros, curr_zeros, ii;

        /* Find longest run of zeros. */
        for (max_start = max_zeros = curr_zeros = ii = 0; ii < 8; ++ii) {
            if (!addr->in6[ii])
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

        /* Print out address. */
#define APPEND(CH) do { if (pos < out_size) output[pos] = (CH); pos++; } while (0)
        for (pos = 0, ii = 0; ii < 8; ++ii) {
            if ((max_zeros > 0) && (ii == max_start)) {
                if (ii == 0) {
                    APPEND('0');
                    APPEND(':');
                }
                APPEND(':');
                ii += max_zeros - 1;
                continue;
            }
            part = ntohs(addr->in6[ii]);
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
#undef APPEND
        output[pos < out_size ? pos : out_size - 1] = '\0';
    }

    return pos;
}

static unsigned int irc_pton_ip4(const char *input, unsigned int *pbits,
                                 uint32_t *output, int allow_trailing)
{
    unsigned int dots = 0;
    unsigned int pos = 0;
    unsigned int part = 0;
    unsigned int ip = 0;
    unsigned int bits = 32;

    /* Intentionally no support for bizarre IPv4 formats (plain
     * integers, octal or hex components) -- only vanilla dotted
     * decimal quads, optionally with trailing /nn.
     */
    if (input[0] == '.')
        return 0;
    while (1) switch (input[pos]) {
    default:
        if (dots < 3)
            return 0;
    out:
        ip |= part << (24 - 8 * dots++);
        *output = htonl(ip);
        if (pbits)
            *pbits = bits;
        return pos;
    case '.':
        if (input[++pos] == '.')
            return 0;
        ip |= part << (24 - 8 * dots++);
        part = 0;
        if (input[pos] == '*') {
            while (input[++pos] == '*') ;
            if (input[pos] != '\0')
                return 0;
            if (pbits)
                *pbits = dots * 8;
            *output = htonl(ip);
            return pos;
        }
        break;
    case '/':
        if (!pbits && allow_trailing)
            goto out;
        else if (!pbits || !isdigit(input[pos + 1]))
            return 0;
        for (bits = 0; isdigit(input[++pos]); )
            bits = bits * 10 + input[pos] - '0';
        if (bits > 32)
            return 0;
        goto out;
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        part = part * 10 + input[pos++] - '0';
        if (part > 255)
            return 0;
        break;
    }
}

unsigned int irc_pton(irc_inaddr *addr, unsigned int *bits, const char *input, int allow_trailing)
{
    const char *part_start = NULL;
    char *colon;
    char *dot;
    unsigned int part = 0;
    unsigned int pos = 0;
    unsigned int ii = 0;
    unsigned int cpos = 8;

    assert(input != NULL);
    memset(addr, 0, sizeof(*addr));
    for (; isspace(input[pos]); ++pos) {}
    colon = strchr(input, ':');
    dot = strchr(input, '.');

    if (colon && (!dot || (dot > colon))) {
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
        while (ii < 8) switch (input[pos]) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
            part = (part << 4) | ct_xdigit_val(input[pos++]);
            if (part > 0xffff)
                return 0;
            break;
        case ':':
            part_start = input + ++pos;
            if (input[pos] == '.')
                return 0;
            addr->in6[ii++] = htons(part);
            part = 0;
            if (input[pos] == ':') {
                if (cpos < 8)
                    return 0;
                cpos = ii;
            }
            break;
        case '.': {
            uint32_t ip4;
            unsigned int len;
            len = irc_pton_ip4(part_start, bits, &ip4, allow_trailing);
            if (!len || (ii > 6))
                return 0;
            memcpy(addr->in6 + ii, &ip4, sizeof(ip4));
            if (bits)
                *bits += 96;
            ii += 2;
            pos = part_start + len - input;
            goto finish;
        }
        case '/':
            addr->in6[ii++] = htons(part);
            if (!bits || !isdigit(input[pos + 1])) {
                if (allow_trailing)
                    goto finish;
                return 0;
            }
            for (part = 0; isdigit(input[++pos]); )
                part = part * 10 + input[pos] - '0';
            if (part > 128)
                return 0;
            *bits = part;
            goto finish;
        case '*':
            while (input[++pos] == '*') ;
            if (input[pos] != '\0' || cpos < 8)
                return 0;
            if (bits)
                *bits = ii * 16;
            return pos;
        default:
            addr->in6[ii++] = htons(part);
            if (cpos == 8 && ii < 8)
                return 0;
            if (bits)
                *bits = 128;
            goto finish;
        }
    finish:
        /* Shift stuff after "::" up and fill middle with zeros. */
        if (cpos < 8) {
            unsigned int jj;
            for (jj = 0; jj < ii - cpos; jj++)
                addr->in6[7 - jj] = addr->in6[ii - jj - 1];
            for (jj = 0; jj < 8 - ii; jj++)
                addr->in6[cpos + jj] = 0;
        }
    } else if (dot) {
        unsigned int ip4;
        pos += irc_pton_ip4(input + pos, bits, &ip4, allow_trailing);
        if (pos) {
            addr->in6[5] = htons(65535);
            addr->in6[6] = htons(ntohl(ip4) >> 16);
            addr->in6[7] = htons(ntohl(ip4) & 65535);
            if (bits)
                *bits += 96;
        }
    } else if (input[pos] == '*') {
        while (input[++pos] == '*') ;
        if (bits)
            *bits = 0;
    }
    if (input[pos] != '\0' && !allow_trailing)
        return 0;
    return pos;
}

unsigned int irc_check_mask(const irc_inaddr *check, const irc_inaddr *mask, unsigned int bits)
{
    unsigned int ii;

    for (ii = 0; (ii < 8) && (bits > 16); bits -= 16, ++ii)
        if (check->in6[ii] != mask->in6[ii])
            return 0;
    if (ii < 8 && bits > 0
        && (ntohs(check->in6[ii] ^ mask->in6[ii]) >> (16 - bits)))
        return 0;
    return 1;
}
