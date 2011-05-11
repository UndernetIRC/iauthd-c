#! /bin/sh

set -e
cd tests
rm -f *.log
export CONFIG=../${srcdir}/tests/iauthd-c.conf
../src/iauthd-c -n -d -f ${CONFIG}
