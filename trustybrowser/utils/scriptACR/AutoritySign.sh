#!/bin/bash


#================= Fonction Auxiliaire ========================
#Permet d afficher la syntaxe pour l utilisation du script

usage(){
    echo "Usage: $0 -c [Path-to-certificat] [key]"
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

[[ $# -le 2 ]] && usage

#================= Tests preconditions ========================
#Verification des droits root
if [[ $EUID -ne 0 ]]; then
    echo "Le script necessite les droits d administration." 1>&2
    exit 0
fi

#Verification installation OpenSSL
openssl test 2>/dev/null
if [[ $? -ne 0 ]]; then
    echo "Verifiez votre installation d'OpenSSL."
    exit 0
fi

#================= Récupération des arguments =================
while getopts ":c:t:" option
do
    case $option in
        c)
            #On verifie que le certificat existe bien
            if ( ! is_file_exists $OPTARG )
            then
                echo "le fichier $OPTARG n'existe pas."
                exit 0
            fi
            pathcertif=$OPTARG
            ;;
        *)
            usage
            ;;
    esac
done


    if ( ! is_file_exists ${2} )
    then
        echo "le fichier '${2}' n'existe pas."
        exit 1
    fi


#================= Signature (ACI) =============
#Creation point de montage RAM
mkdir -p /mnt/security
chmod 600 /mnt/security

mount -t tmpfs -o size=5m tmpfs /mnt/security
touch /mnt/security/KeyAes.key
chmod 600 /mnt/security/KeyAes.key
#Récupération de la clef de chiffrement
cmd=""
    echo -e "\nVeuillez Saisir le mot de passe pour dechiffrer"\
         " la clef suivante:"
    echo ">>>>>>>>"${3}
    openssl enc -d -aes-256-cbc -in ${3} -out /mnt/security/KeyAes.key
    while [[ $? -ne 0 ]]; do
        echo "Mot de passe éronné, réassayez.\n"
        openssl enc -d -aes-256-cbc -in ${3} -out /mnt/security/KeyAes.key
    done
    cmd=$cmd`cat /mnt/security/KeyAes.key`"\n"


#Séparation de l'IV et de la clef
IV=`cat /mnt/security/KeyAes.key | cut -d"$" -f1`
Key=`cat /mnt/security/KeyAes.key | cut -d"$" -f2`
#Déchiffrement de la clef de privée
touch /mnt/security/ACRplain.pem
chmod 600 /mnt/security/ACRplain.pem
err=0
openssl enc -d -iv $IV -K $Key -aes-256-cbc -in private/ACR.pem \
        -out /mnt/security/ACRplain.pem
if [[ $? -ne 0 ]] ;
then
    #Effacement des données
    shred /mnt/security/KeyAes.key
    sync
    if ( is_file_exists "/mnt/security/ACRplain.pem" )
    then
        shred /mnt/security/ACRplain.pem
        sync
    fi
    umount -f /mnt/security/
    rm -R /mnt/security
    echo "Erreur lors du dechiffrement de la clef secrete"
    exit 1
fi

#Signature du certificat d'ACI
#récuperation du nom du fichier
fullfilename=$(basename $pathcertif)
filename=${fullfilename%.*}
alea=`head -c 4 /dev/urandom | hexdump -v -e '/1 "%02x"'`
certfilename=$filename$alea".pem"
openssl ca -config openssl.cnf -keyfile /mnt/security/ACRplain.pem\
        -extensions EXT_ACI -in $pathcertif -out certs/$certfilename
if [[ $? -ne 0 ]] ;
then
    err=1
fi

#Vérification du certificat créé
if [[ $err -eq 0 ]] ; then
    openssl verify -verbose -CAfile certs/ACR_crt.pem  certs/$certfilename
    if [[ $? -ne 0 ]] ;
    then
        err=1
    fi
fi

#Effacement des données
shred /mnt/security/KeyAes.key
shred /mnt/security/ACRplain.pem
sync
umount -f /mnt/security/
while [[ $? -ne 0 ]] ; do
    read -p "Echec du demontage du tmpfs, voulez-vous reessayer? [y/n]: " yn
    case $yn in
        [Yy]* )
            echo ""
            umount -f /mnt/security/
            ;;
        [Nn]* )
            break
            ;;
        * )
            echo "Merci de répondre y or n."
            ;;
    esac
done
rm -Rf /mnt/security
while [[ $? -ne 0 ]] ; do
    read -p "Echec de suppression du point de montage, voulez-vous"\
         " reessayer? [y/n]: " yn
    case $yn in
        [Yy]* )
            echo ""
            umount -f /mnt/security/
            ;;
        [Nn]* )
            break
            ;;
        * )
            echo "Merci de répondre y or n."
            ;;
    esac
done

if [[ $err -ne 0 ]] ;
then
    echo "Echec de la signature du certificat"
    if ( is_file_exists certs/$certfilename )
    then
        rm certs/$certfilename
    fi
    exit 1
fi
c_rehash certs/
echo "Signature du certificat reussie."
exit 1
