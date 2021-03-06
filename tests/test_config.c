/* test_config.c - Test harness for configuration file code
 *
 * Copyright 2020 Michael Poole <mdpoole@troilus.org>
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

#include "tests/tests.h"

struct conf_node_object *conf_root;

static void test_config(void)
{
	struct conf_node_string *str_child;
	struct conf_node_string *null_child;
	struct conf_node_string *integer_child;
	struct conf_node_string *float_child;
	struct conf_node_string *interval_child;
	struct conf_node_string *volume_child;
	struct conf_node_string_list *list_child;
	struct conf_node_inaddr *inaddr_child;
	void *child;
	int res, valid;

	ok((conf_get_root() != NULL), "conf_get_root() != NULL");

	res = conf_parse_boolean("true", &valid);
	ok(res && valid, "conf_parse_boolean('true') -> true");

	res = conf_parse_boolean("false", &valid);
	ok(!res && valid, "conf_parse_boolean('false') -> false");

	res = conf_parse_boolean("pizza", &valid);
	ok(!valid, "conf_parse_boolean('pizza') fails");

	str_child = conf_register_string(conf_root, CONF_STRING_PLAIN, "plain", "");
	is(str_child->value, "jane", "plain config string is jane");

	null_child = conf_register_string(conf_root, CONF_STRING_PLAIN, "null", NULL);
	is(null_child->value, NULL, "null default string is carried through");

	integer_child = conf_register_string(conf_root, CONF_STRING_INTEGER, "integer", "0");
	cmp_ok(integer_child->parsed.p_integer, "==", 321, "integer config == 321");

	float_child = conf_register_string(conf_root, CONF_STRING_FLOAT, "float", "0");
	near(float_child->parsed.p_double, 8.0, "float config ~= 8");

	interval_child = conf_register_string(conf_root, CONF_STRING_INTERVAL, "interval", "0");
	cmp_ok(interval_child->parsed.p_interval, "==", 31719845, "interval config is long");

	volume_child = conf_register_string(conf_root, CONF_STRING_VOLUME, "volume", "0");
	cmp_ok(volume_child->parsed.p_volume, "==", (1 << 30) + (2 << 20) + (3 << 10) + 4, "volume config has parts");

	list_child = conf_register_string_list(conf_root, "list", NULL);
	cmp_ok(list_child->value.used, "==", 3, "string list has three items");
	skip(list_child->value.used != 3, 3, "skipping tests of list contents");
	is(list_child->value.vec[0], "this", "first string in list is 'this'");
	is(list_child->value.vec[1], "funky", "second string in list is 'funky'");
	is(list_child->value.vec[2], "people", "third string in list is 'people'");
	end_skip;

	inaddr_child = conf_register_inaddr(conf_root, "inaddr", "", "");
	is(inaddr_child->hostname, "::1", "inaddr hostname is ::1");
	is(inaddr_child->service, "8080", "inaddr service is 8080");

	child = conf_get_child(conf_root, "plain", CONF_STRING);
	ok((child == str_child), "can look up config string");
}

static void test_config_2(void)
{
	struct conf_node_string *str_child;
	unsigned int u_res;
	int valid;

	log_reopen();

	str_child = conf_register_string(conf_root, CONF_STRING_PLAIN, "plain", "");
	is(str_child->value, "jane", "plain config string is still jane");

	u_res = conf_parse_interval("2h3m4s", &valid);
	ok(valid && (u_res == (2*60+3)*60+4), "2h3m4s parses properly");

	u_res = conf_parse_interval("123z", &valid);
	ok(!valid, "123z is not a valid interval");

	u_res = conf_parse_interval("1:2:3:", &valid);
	ok(!valid, "1:2:3: is not a valid interval");

	u_res = conf_parse_volume("5B", &valid);
	ok(valid && (u_res == 5), "5B is a valid volume");
}

void module_constructor(const char name[])
{
	module_depends("tests", NULL);
	conf_root = conf_register_object(NULL, name);
	plan(test_config, 17);
	plan(test_config_2, 5);
}
