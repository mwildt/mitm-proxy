#!/bin/bash

#curl \
#  --proxy http://localhost:8888/ \
#  --cacert ./certs/mitm_root_ca.crt \
#   https://registry-1.docker.io/v2/

# curl -i \
#   --proxy http://localhost:8888/ \
#   --cacert ./certs/mitm_root_ca.crt \
#    https://demo.local.host/test/

HTTPS_PROXY=http://localhost:8888/ podman pull docker.io/library/tomcat:latest

lit