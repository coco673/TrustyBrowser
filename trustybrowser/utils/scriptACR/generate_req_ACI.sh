#!/bin/bash

key=$1".key"
csr=$1".csr"

usage(){
	echo "Usage : $0 name-req"
	exit 0
}
[[$# -le 0]] && usage

#Verification des droits root
if [[ $EUID -ne 0 ]]; then
    echo "Le script necessite les droits d administration." 1>&2
    exit 0
fi
openssl req -newkey rsa:2048 -keyout private/${key} \
	-out request/${csr} -config openssl.cnf 
