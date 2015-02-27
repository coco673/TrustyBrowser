#!/bin/bash


#================= Fonction Auxiiliaire ========================
#Permet d afficher la syntaxe pour l utilisation du script

usage(){
    echo "Usage: $0 [Install_Path]"
    exit 0
}

#Verifie si le fichier existe
is_file_exists(){
    [[ -f "$1" ]] && return 0 || return 1
}

#verifie si le dossier existe
is_dir_exists(){
    [[ -d "$1" ]] && return 0 || return 1
}

[[ $# -ne 1 ]] && usage

#================= Tests preconditions ========================
#Verification des droits root
if [[ $EUID -ne 0 ]]; then
    echo "Le script necessite les droits d'administration." 1>&2
    exit 0
fi

#Verification installation OpenSSL
openssl test 2>/dev/null
if [[ $? -ne 0 ]]; then
    echo "Verifier votre installation d'OpenSSL."
    exit 0
fi

#Verification Chemin d installation
if ( ! is_dir_exists $1 )
then
    echo "Veuillez founir un chemin d'installation valide."
    exit 0
fi

pathInstall=$1"/"

#Verification presence des fichiers et dossiers
if ( is_dir_exists $pathInstall"private" )
then
    echo "le repertoire 'private' existe déjà."
    exit 0
fi

if ( is_dir_exists $pathInstall"certs" )
then
    echo "le repertoire 'certs' existe déjà."
    exit 0
fi

if ( is_dir_exists $pathInstall"crl" )
then
    echo "le repertoire 'crl' existe déjà."
    exit 0
fi

if ( is_dir_exists $pathInstall"newcerts" )
then
    echo "le repertoire 'newcerts' existe déjà."
    exit 0
fi

if ( is_file_exists $pathInstall"index.txt" )
then
    echo "le fichier 'index.txt' existe déjà."
    exit 0
fi

if ( is_file_exists $pathInstall"serial" )
then
    echo "le fichier 'serial' existe déjà."
    exit 0
fi

if ( is_file_exists $pathInstall"crlnumber" )
then
    echo "le fichier 'crlnumber' existe déjà."
    exit 0
fi


#================= Creation des ressources ==================
#Creation des fichiers et repertoires necessaires
#on sauvegarde le repertoire local lors de l'appel au script
oldPath=$pwd

cd $pathInstall
mkdir {private,certs,crl,newcerts,request}

#Définition de droits particuliers sur les repertoires
chmod -R 750 private
chmod -R 655 certs
chmod -R 655 crl
chmod -R 655 newcerts
chmod -R 655 request

touch {index.txt,serial,crlnumber}
echo "01" > serial
echo "01" > crlnumber

chmod 644 index.txt
chmod 644 serial
chmod 644 crlnumber

groupadd pki
uid=`id -u`
usermod -a -G pki `who am i | cut -d " " -f1`

chown -R root:pki ./*

#================= Création Autorite Racine (ACR) =============
#Creation point de montage RAM
mkdir -p /mnt/secure
chmod 600 /mnt/secure
mount -t tmpfs -o size=5m tmpfs /mnt/secure
#creation de la bi-clef RSA 4096 bits
openssl genpkey -algorithm RSA -outform PEM -pkeyopt rsa_keygen_bits:4096 \
        -out /mnt/secure/ACR.tmp.pem
#Chiffrement de la bi-clef
touch /mnt/secure/KeyAes.key
head -c 8 /dev/urandom | hexdump -v -e '/1 "%02x"' > /mnt/secure/KeyAes.key
echo -n '$' >> /mnt/secure/KeyAes.key
head -c 32 /dev/urandom | hexdump -v -e '/1 "%02x"' >> /mnt/secure/KeyAes.key

IV=`cat /mnt/secure/KeyAes.key | cut -d '$' -f1`
Key=`cat /mnt/secure/KeyAes.key | cut -d '$' -f2`

openssl enc -iv $IV -K $Key -aes-256-cbc -in /mnt/secure/ACR.tmp.pem \
        -out private/ACR.pem
if [[ $? -ne 0 ]] ;
then
    #Effacement des données
    shred /mnt/secure/KeyAes.key
    shred /mnt/secure/ACR.tmp.pem
    if ( is_file_exists "private/ACR.pem" )
    then
        rm private/ACR.pem
    fi

    umount -f /mnt/secure/
    rm -R /mnt/secure

    cd $oldPath
    echo "Erreur lors du chiffrement de la clef secrete"
    exit 1
fi
#Genération du certificat
openssl req -sha256 -config openssl.cnf -new -key /mnt/secure/ACR.tmp.pem \
        -out request/ACR.req
if [[ $? -ne 0 ]] ;
then
    #Effacement des données
    shred /mnt/secure/KeyAes.key
    shred /mnt/secure/ACR.tmp.pem
    if ( is_file_exists "private/ACR.pem" )
    then
        rm private/ACR.pem
    fi
    if ( is_file_exists "request/ACR.req" )
    then
        rm request/ACR.req
    fi

    umount -f /mnt/secure/
    rm -R /mnt/secure
    cd $oldPath
    echo "Erreur lors de la génération du certificat"
    exit 1
fi
#Auto-signature du certificat
openssl x509 -req -sha256 -days 7300 -in request/ACR.req \
        -signkey /mnt/secure/ACR.tmp.pem -out certs/ACR_crt.pem
if [[ $? -ne 0 ]] ;
then
    #Effacement des données
    shred /mnt/secure/KeyAes.key
    shred /mnt/secure/ACR.tmp.pem
    if ( is_file_exists "private/ACR.pem" )
    then
        rm private/ACR.pem
    fi
    if ( is_file_exists "request/ACR.req" )
    then
        rm request/ACR.req
    fi
    if ( is_file_exists "certs/ACR_crt.pem" )
    then
        rm certs/ACR_crt.pem
    fi

    umount -f /mnt/secure/
    while [[ $? -ne 0 ]] ; do
        read -p "Echec du démontage du tmpfs, voulez-vous reessayer? [y/n]: " yn
        case $yn in
            [Yy]* )
                echo ""
                umount -f /mnt/secure/
                ;;
            [Nn]* )
                break
                ;;
            * )
                echo "Merci de répondre y or n."
                ;;
        esac
    done

    rm -R /mnt/secure
    while [[ $? -ne 0 ]] ; do
        read -p "Echec de suppression du point de montage"\
             " voulez-vous reessayer? [y/n]: " yn
        case $yn in
            [Yy]* )
                echo ""
                rm -R /mnt/secure
                ;;
            [Nn]* )
                break
                ;;
            * )
                echo "Merci de répondre y or n."
                ;;
        esac
    done

    cd $oldPath
    echo "Erreur lors de l'auto-signature"
    exit 1
fi
#Partage de la clef de chiffrement
share=`cat /mnt/secure/KeyAes.key`


echo -e "\nChiffrement de la clef"
openssl enc -aes-256-cbc -in /mnt/secure/KeyAes.key -out private/cipherKeyAes.key
while [[ $? -ne 0 ]] ;
do
    openssl enc -aes-256-cbc -in /mnt/secure/KeyAes.key -out private/cipherKeyAes.key
done


#Effacement des données
shred /mnt/secure/KeyAes.key
shred /mnt/secure/ACR.tmp.pem


echo "Operations en cours, veuillez patienter ..."
umount -f /mnt/secure/
while [[ $? -ne 0 ]] ; do
    read -p "Echec du démontage du tmpfs, voulez-vous reessayer? [y/n]: " yn
    case $yn in
        [Yy]* )
            echo ""
            umount -f /mnt/secure/
            ;;
        [Nn]* )
            break
            ;;
        * )
            echo "Merci de répondre y or n."
            ;;
    esac
done

rm -R /mnt/secure
while [[ $? -ne 0 ]] ; do
    read -p "Echec de suppression du point de montage,"\
         " voulez-vous reessayer? [y/n]: " yn
    case $yn in
        [Yy]* )
            echo ""
            rm -R /mnt/secure
            ;;
        [Nn]* )
            break
            ;;
        * )
            echo "Merci de répondre y or n."
            ;;
    esac
done

cd $oldPath

echo "Création ACR réussie."
exit 0
