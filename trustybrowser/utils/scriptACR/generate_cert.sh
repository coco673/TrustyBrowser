#!/bin/bash
# x x EXT nom_de_certificat ou x x correspondent à l id des clefs du certificat

private="cle-RSA-"$1".key";
csr=$1".csr";
ext=$2;
cert=$1".crt";
CA=$3
CAKey=$4

usage(){
        echo "Usage: $0 [name-cert] [extension-Openssl] [CA][CA-Key]"
            exit 0
        }

[[ $# -le 3 ]]&&usage

while [[ $? -ne 0 ]] ; do
    read -p "\nVoulez vous chiffrer la clef? [y/n]: " chiffre
echo $chiffre
case $chiffre in
    [Yy]* )
        openssl req -newkey rsa:1024 -keyout private/${private} \
        	-out request/${csr} -config openssl.cnf
        ;;
    [Nn]* )
	echo"tt"
#Generation de la demande de signature de certificat	
        openssl req -nodes -newkey rsa:1024 -keyout private/${private} \
        	-out request/${csr} -config openssl.cnf
        ;;
    *)
        echo "Merci de répondre y or n."
                    ;;
    esac
done
##Generation de la demande de signature DSA 
#sudo openssl req -newkey dsa:dsaparam.pem -keyout ${private} \
	#-out ${csr} -config openssl.cnf;

#Generation du certificat signé x509
openssl x509 -req -extensions ${ext} -CAserial serial -in request/${csr} \
	-out ${cert} -CA ${CA} -CAkey ${CAKey} -extfile openssl.cnf;

mv ${cert} certs/${cert}
mv ${csr} certs/${csr};
mv ${private} private/${private}
