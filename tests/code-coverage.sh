#! /bin/sh -e

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
./src/iauthd-c -dkn --config ./this/file/must/never/exist > /dev/null || :
./src/iauthd-c -dkn --config ${TESTS_DIR}/coverage-1.conf > /dev/null
echo "" | ./src/iauthd-c -n --config ${TESTS_DIR}/coverage-1.conf > /dev/null

# POSIX shell doesn't give us functionality like Expect, so use Perl.
perl ${TESTS_DIR}/code-coverage.pl ${TESTS_DIR}

# Generate our coverage reports.
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory lcov
sensible-browser lcov/index.html
