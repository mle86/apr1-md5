#!/bin/sh

if [ "$TRAVIS_PHP_VERSION" = "hhvm" ]; then
	# HHVM requires an earlier PHPUnit version.
	# see https://docs.travis-ci.com/user/languages/php/#hhvm-versions
	curl -sSfL -o ~/.phpenv/versions/hhvm/bin/phpunit https://phar.phpunit.de/phpunit-5.7.phar
fi

true
