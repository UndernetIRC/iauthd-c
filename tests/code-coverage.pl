#! /usr/bin/env perl

use Expect;
use File::Basename qw(fileparse);
use File::Copy qw(copy);
use File::Temp qw(tempfile);
use strict;
use vars qw($TESTS_DIR $config_fh $config_name $exp);
use warnings;

# Copy initial config to a temporary file.
$TESTS_DIR = shift || (fileparse($0))[1];
die "Usage: $0 <TESTS_DIR>\n" unless -d $TESTS_DIR;
($config_fh, $config_name) = tempfile();
copy($TESTS_DIR . "/coverage-1.conf", $config_fh)
	or die "Unable to copy coverage-1.conf to $config_name: $!";

# Launch iauthd-c.
$exp = Expect->spawn(
#	'strace', '-f', '-o', 'iauthd-c.str',
#	'valgrind', '-v', '--vgdb=full', '--vgdb-error=1', '--log-file=valgrind.log',
	'./src/iauthd-c', '-n', '-A', '-f', $config_name)
	or die "Cannot spawn iauthd-c: $!\n";

# iauthd-c's banner should include version, and then options.
$exp->expect(1, '-re', '^V :iauthd-c v')
	or die "did not get iauthd-c version string\n";
$exp->expect(1, '-re', '^O [SARUW]{5}\r?$')
	or die "did not get expected IAuth options\n";

# Send our greeting and a bunch of garbage.
$exp->send(<<"HERE");
-1 M server.missing.maxclients
-1 M irc.example.org 1024
-1 D garbage command
-1 N more garbage
-1 d still garbage
-1 P password garbage
-1 U userinfo garbage
-1 u username garbage
-1 n nickname garbage
-1 H hurry-up garbage
-1 T registration complete garbage
-1 E missing-message
-1 E errtype :no, you are in error
19 C 0::1 40292 0::1
HERE

# Client 19 checks a lot of the normal path, including a challenge/response.
$exp->clear_accum();
$exp->send(<<"HERE");
19 C 0::1 40292 0::1 7701
19 N irc.example.org
19 P :+x! account password
19 U fakename :user info goes here
19 n Nickname
19 u username
-1 X euworld.example.org 13_1 OK
-1 X botcheck.example.org 13_1 OK
-1 X combined.example.org 13_1 OK
19 H
-1 X channels.example.org 13_1 :MORE Speak, friend, and enter
-1 X unlinked.without.routing
-1 X xreply.without.routing
HERE
$exp->expect(1, '-re', '^C 19 0::1 40292 :Speak, friend, and enter\r?$')
	or die "did not get IAuth challenge\n";
$exp->send("19 P :Mellon\n");
$exp->expect(1, '-re', '^X channels.example.org 13_1 :MORE Mellon\r?$');
$exp->send("-1 X channels.example.org 13_1 :OK friend:1\n");
$exp->expect(1, '-re', '^M 19 0::1 40292 :?\+x\r?$')
	or die "did not get mode +x for client 19\n";
$exp->expect(1, '-re', '^R 19 0::1 40292 friend:1 r400\r?$')
	or die "did not get register message for client 19\n";

# Client 20 checks NO handling and the content of U messages.
$exp->send(<<"HERE");
20 C 127.1.2.3 54321 127.0.0.1 7701
20 N trusted.example.org
20 P :traditional
20 U missing_user_info
20 U ~oident :Trusted
20 u username
20 n Nick
HERE
$exp->expect(1, '-re', '^X botcheck.example.org 14_2 :CHECK Nick username 127.1.2.3 trusted.example.org :Trusted\r?$')
	or die "did not get CHECK to botcheck.* for client 20\n";
$exp->expect(1, '-re', '^X combined.example.org 14_2 :CHECK Nick username 127.1.2.3 trusted.example.org :Trusted\r?$')
	or die "did not get CHECK to combined.* for client 20\n";
$exp->send("-1 X combined.example.org 14_2 OK\n");
$exp->send("-1 X botcheck.example.org 14_2 :NO you do not belong here\n");
$exp->expect(1, '-re', '^k 20 127.1.2.3 54321 :you do not belong here\r?$')
	or die "did not get kill message for client 20\n";

# Client 21 checks priority of r300 versus r400, and that bogus XREPLY
# messages are ignored.
$exp->send(<<"HERE");
21 C 127.2.3.4 65432 127.0.0.1 7701
21 N trusted.example.org
21 P :+ missing-passsword
21 U fakename :These are not the droids you are looking for
21 u ~fakename
21 n AAAAD
HERE
$exp->expect(1, '-re', '^X combined.example.org 15_3 :CHECK AAAAD ~fakename 127.2.3.4 trusted.example.org :These are not the droids you are looking for\r?$')
	or die "did not get CHECK to combined.* for client 21\n";
$exp->send(<<"HERE");
-1 X bogus.example.org 15_3 :OK who are you going to believe?
-1 X euworld.example.org 13+8 :NO why do you keep asking?
-1 X euworld.example.org 13_8_ :YES we have no bananas
HERE

# Rehash the config file and ask for stats (before all XQUERY servers
# have responded for client 21).
$config_fh->seek(0, 0);
copy($TESTS_DIR . "/coverage-2.conf", $config_fh)
	or die "Unable to copy coverage-2.conf to $config_name: $!";
sleep 0.05; # so that iauthd can process its inputs before we signal it
kill 'USR1', $exp->pid();
$exp->send(<<"HERE");
-1 ? config
-1 ? stats2
-1 ?
-1 ? bogus
HERE
$exp->expect(1, '-re', '^s\r?$');
$exp->send(<<"HERE");
-1 X botcheck.example.org 15_3 OK
-1 X combined.example.org 15_3 OK
HERE
$exp->expect(1, '-re', '^U 21.127.2.3.4 65432 fakename\r?$')
	or die "die not get username message for client 21\n";
$exp->expect(1, '-re', '^D 21 127.2.3.4 65432 trusted\r?$')
	or die "did not get done (trusted) message for client 21\n";

# Client 22 checks that we reject clients governed by the xreply_ok rule.
$exp->send(<<"HERE");
22 C 127.3.4.5 12345 127.0.0.1 7701
22 N untrusted.example.org
22 P :+x account password
22 U username :This part is my user info
22 u ~someone
22 n Nicky
HERE
$exp->expect(1, '-re', '^X botcheck.example.org 16_4 :CHECK ')
	or die "did not get CHECK to botcheck.* for client 22\n";
# the NO should be ignored because it has no explanation
$exp->send(<<"HERE");
-1 X botcheck.example.org 16_4 NO
-1 X botcheck.example.org 16_4 OK
-1 X channels.example.org 16_4 :AGAIN you smell funny
HERE
$exp->expect(1, '-re', '^C 22 127.3.4.5 12345 :you smell funny\r?$')
	or die "did not get challenge for client 22\n";
$exp->expect(1, '-re', '^D 22 127.3.4.5 12345 :?default_clients\r?$')
	or die "did not get done response for client 22\n";

# Client 23 checks username and address matching for iauth_class.
$exp->send(<<"HERE");
23 C 127.3.4.5 12345 127.0.0.1 7701
23 N untrusted.example.org
23 U someone :I hope to use rule r100
23 u joe-oper
23 n NickNolte
HERE
$exp->expect(1, '-re', '^X botcheck.example.org 17_5 :CHECK NickNolte .*\r?$')
	or die "did not get CHECK for client 23\n";
$exp->send(<<"HERE");
-1 X channels.example.org 17_5 OK
-1 X botcheck.example.org 17_5 OK
HERE
$exp->expect(1, '-re', '^D 23 127.3.4.5 12345 :?trusted\r?$')
	or die "did not get done response for client 23\n";

# Client 24 checks that trust_username works.
$exp->send(<<"HERE");
24 C 127.3.4.5 12345 127.0.0.1 7701
24 N trusted.example.org
24 U joe-oper :r300 should trust the client's asserted username
24 u ~username
24 n NickNolte
-1 X channels.example.org 18_6 OK
-1 X botcheck.example.org 18_6 OK
HERE
$exp->expect(1, '-re', '^U 24 127.3.4.5 12345 joe-oper\r?$')
	or die "expected r300 to trust client's username\n";
$exp->expect(1, '-re', '^D 24 127.3.4.5 12345 trusted\r?$')
	or die "did not get done response for client 24\n";

# Client 25 checks what happens with an unlinked XQUERY service.
$exp->send(<<"HERE");
25 C 127.3.4.5 12345 127.0.0.1 7701
25 N untrusted.example.org
25 U ~joe-oper :rustworthy, not trustworthy
25 u vonbraun
25 n Werner
25 P :+ account password
HERE
$exp->expect(1, '-re', '^X channels.example.org 19_7 :LOGIN2 127.3.4.5 untrusted.example.org vonbraun account password\r?$')
	or die "did not get LOGIN2 request for client 25\n";
$exp->send(<<"HERE");
-1 x channels.example.org 19_7 :Server not online
-1 X botcheck.example.org 19_7 OK
HERE
$exp->expect(1, '-re', '^U 25 127.3.4.5 12345 ',
	'-re', '^D 25 127.3.4.5 12345 :?default_clients\r?$') == 2
	or die "did not get (untrusted) done response for client 25";

# Client 26 checks handling of a disconnect in the middle of registration.
$exp->send(<<"HERE");
26 C 127.3.4.5 12345 127.0.0.1 7701
26 d
26 U joe-oper :r300 might fire, but iauth_xquery is still waiting.
26 u ~username
26 n NickNolte
26 D
HERE
$exp->expect(1, '-re', '^X botcheck.example.org 1a_8 :CHECK NickNolte ~username 127.3.4.5 127.3.4.5 :r300 might fire, but iauth_xquery is still waiting\r?$')
	or die "did not check CHECK request for client 26\n";

# Client 27 checks that clients get a "soft done" with no dronecheck.
$exp->send(<<"HERE");
27 C 127.4.5.6 23456 127.0.0.1 7701
27 N untrusted.example.org
27 U ~joe-user :I may be a drone
27 u mccarthy
27 n joe
HERE
$exp->expect(1, '-re', '^X botcheck.example.org 1b_9 :CHECK joe mccarthy 127.4.5.6 untrusted.example.org :I may be a drone\r?$')
	or die "did not get CHECK request for client 27\n";
$exp->send("-1 x botcheck.example.org 1b_9\n");
$exp->expect(1, '-re', '^d 27 127.4.5.6 23456')
	or die "did not get soft done for client 27\n";

# We should (a) handle lines with trailing whitespace and (b) ignore
# client numbers that do not have a current request pending.  We should
# also handle blank lines and the old ? stats.
$exp->send(<<"HERE");
18 D 

-1 ? stats
HERE

# Give iauthd-c a chance to finish, then stop it.
$exp->expect(1, 'The Magic Words are Squeamish Ossifrage');
$exp->hard_close();

# Delete our temporary config file.
unlink $config_name;
