#!/bin/sh

openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 9999 -subj /CN=e2e-test-server
