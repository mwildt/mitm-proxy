#!/bin/bash

#curl -L -i --proxy http://localhost:8888/ --cacert ./certs/mitm_root_ca.crt https://registry-1.docker.io/v2/
#curl -L --proxy http://localhost:8888/ --cacert ./certs/mitm_root_ca.crt https://wolke.ohrenpirat.de
#curl -L -i --proxy http://localhost:8888/ --cacert ./certs/mitm_root_ca.crt https://demo.local.host/test/

curl -L -i --proxy http://localhost:8888/ --cacert ./certs/mitm_root_ca.crt https://www.google.com

# curl -i \
#   --proxy http://localhost:8888/ \
#   --cacert ./certs/mitm_root_ca.crt \
#

#HTTP_PROXY=https://localhost:8888/ podman pull docker.io/library/tomcat:latest
