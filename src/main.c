/* main.c - Entry point for iauthd-c.
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

#include <evdns.h>
#include <event.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	/* Initialize libevent. */
	if (!event_init())
	{
		fprintf(stderr, "Unable to initialize event library.\n");
		return EXIT_FAILURE;
	}

	/* Capture libevent's error messages to our own log. */

	/* Initialize libevent's DNS module. */
	if (evdns_init())
	{
		fprintf(stderr, "Unable to initialize DNS library.\n");
		return EXIT_FAILURE;
	}
	evdns_search_clear();

	/* Run the event loop. */
	event_dispatch();
	return EXIT_FAILURE;
}
