#! /bin/sh -e

iauthd_input_1 () {
	# Unlink the FIFO we use for communications to iauthd-c.
	# (Our fd 3 should still point to it.)
	rm -f $FIFO_PATH
	ps fax | grep $IAUTHD_C_PID

	# Send our greeting and a bunch of garbage.
cat <<-HERE >&3
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
	-1 E :no, you are in error
	19 C 0::1 40292 0::1
HERE

	# Client 19 checks a lot of the normal path, plus a challenge/response.
cat <<-HERE >&3
	19 C 0::1 40292 0::1 7701
	19 N irc.example.org
	19 P :+x! account password
	19 U fakename :user info goes here
	19 n Nickname
	19 u username
	-1 X euworld.example.org 13_1 OK
	-1 X botcheck.example.org 13_1 OK
	-1 X combined.example.org 13_1 OK
	-1 X channels.example.org 13_1 :AGAIN Speak, friend, and enter
	19 P :Mellon
	-1 x unlinked.without.routing
	-1 X channels.example.org 13_1 :OK friend:1
HERE

	# Client 20 checks NO handling and U content checking.
cat <<-HERE >&3
	20 C 127.1.2.3 54321 127.0.0.1 7701
	20 N trusted.example.org
	20 P :traditional
	20 U ~oident :Trusted
	20 U missing_user_info
	20 u username
	20 n Nick
	-1 X botcheck.example.org 14_2 OK
	-1 X combined.example.org 14_2 OK
	-1 X channels.example.org 14_2 OK
	-1 X euworld.example.org 14_2 :NO you do not belong here
HERE

	# Client 21 checks priority of r300 versus r400, and some bogus
	# XREPLY messages (which should be ignored).
cat <<-HERE >&3
	21 C 127.2.3.4 65432 127.0.0.1 7701
	21 N untrusted.example.org
	21 P :+ missing-passsword
	21 U fakename :These are not the droids you are looking for
	21 u ~fakename
	21 n AAAAD
	-1 X euworld.example.org 13_8 :NO you don't have to be crazy to work here
	-1 X bogus.example.org 15_3 :OK who are you going to believe?
	-1 X euworld.example.org 13+8 :NO why do you keep asking?
	-1 X euworld.example.org 13_8_ :YES we have no bananas
HERE

	# Rehash config and ask for stats before all XQUERY servers have
	# responded.
	cp ${TESTS_DIR}/coverage-2.conf $CONFIG_FILE
	kill -USR1 $IAUTHD_C_PID
cat <<-HERE >&3
	-1 ? config
	-1 ? stats2
	-1 X euworld.example.org 15_3 OK
	-1 X botcheck.example.org 15_3 OK
	-1 X combined.example.org 15_3 OK
	-1 X channels.example.org 15_3 OK
HERE

	# Client 22 checks xreply_ok rejection.
cat <<-HERE >&3
	22 C 127.3.4.5 12345 127.0.0.1 7701
	22 N untrusted.example.org
	22 U username :This is my user info, not my user name
	22 u ~someone
	22 n Nicky
	-1 X channels.example.org 16_4 NO
	-1 X botcheck.example.org 16_4 OK
	-1 X channels.example.org 16_4 :NO you smell funny
HERE

	# Client 23 checks username and address matching for iauth_class.
cat <<-HERE >&3
	23 C 127.3.4.5 12345 127.0.0.1 7701
	23 N untrusted.example.org
	23 U joe-oper :I hope to use rule r100
	23 u ~someone
	23 n NickNolte
	-1 X channels.example.org 17_5 OK
	-1 X botcheck.example.org 17_5 OK
HERE

	# Client 24 checks trust_username handling.
cat <<-HERE >&3
	24 C 127.3.4.5 12345 127.0.0.1 7701
	24 N trusted.example.org
	24 U joe-oper :r300 should trust the client's asserted username
	24 u ~username
	24 n NickNolte
	-1 X channels.example.org 18_6 OK
	-1 X botcheck.example.org 18_6 OK
HERE

	# Client 25 checks what happens with an unlinked XQUERY service.
cat <<-HERE >&3
	25 C 127.3.4.5 12345 127.0.0.1 7701
	25 N untrusted.example.org
	25 U ~joe-oper :rustworthy, not trustworthy
	25 u vonbraun
	25 n Werner
	-1 x channels.example.org 19_7 :Server not online
	-1 X botcheck.example.org 19_7 OK
HERE

	# Client 26 checks what happens with a client who disconnects mid-registration.
cat <<-HERE >&3
	24 C 127.3.4.5 12345 127.0.0.1 7701
	24 d
	24 U joe-oper :r300 might fire, but iauth_xquery is still waiting.
	24 u ~username
	24 n NickNolte
	24 D
HERE

	# Check an error message from the ircd.
	echo "-1 E :IAuthd has been smoking the funny leaf"

	# Check the special commands.
cat <<-HERE >&3
	-1 ?
	-1 ? bogus
	-1 ? config
	-1 ? stats
	-1 ? stats2
HERE

	# Terminate it with SIGHUP.
	ps fax | grep $IAUTHD_C_PID
	rm -f ${CONFIG_FILE}
	kill -HUP $IAUTHD_C_PID
	wait
}

# Remove any existing profiling output.
rm -f coverage.info */*.gcda */*.gcno -r lcov

# Run "make check" with profiling enabled.
SANITIZE="-fsanitize=address,undefined"
make -j ${NCPUS-6} clean check \
	CFLAGS="-g --coverage ${SANITIZE} -fstack-protector-strong" \
	LDFLAGS="-g --coverage ${SANITIZE}"

# Test some trivial behaviors.
TESTS_DIR=`dirname $0`
./src/iauthd-c --help > /dev/null
./src/iauthd-c -v > /dev/null
./src/iauthd-c -dkn --config ${TESTS_DIR}/coverage-1.conf > /dev/null

# Normal iauthd-c generates non-TAP output, so we run it outside of
# "make check".  And we want to signal it, so we use mkfifo to pipe
# data from it.  (POSIX shell only provides | to create anonymous pipes,
# but that does not let us capture the PID.)
CONFIG_FILE=iauthd-$$.conf
FIFO_PATH=iauthd-$$.fifo
mkfifo -m0700 ${FIFO_PATH}
cp ${TESTS_DIR}/coverage-1.conf ${CONFIG_FILE}
# strace -f -o iauthd-c.str \
# valgrind -v --vgdb=full --vgdb-error=1 --log-file=valgrind.log \
./src/iauthd-c -n -A -f `pwd`/${CONFIG_FILE} > /dev/null < ${FIFO_PATH} &
IAUTHD_C_PID=$!
iauthd_input_1 3<>${FIFO_PATH}

# Generate our coverage reports.
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory lcov
sensible-browser lcov/index.html
