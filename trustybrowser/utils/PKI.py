#!/usr/bin/env python3
# encoding: utf-8

import OpenSSL
import sys
import os
import time
from random import random

def genCerts(CACert, CAKey, CN, version=3, C="FR", ST="Normandie",
             OU="M2SSI 2014-2015", O="Université de Rouen",
             L="Saint Étienne du Rouvray", hashAlgorithm="sha256",
             signingAlgortihm=OpenSSL.crypto.TYPE_RSA, generatedKeySize=2048,
             dateBefore=0, dateAfter=0, extensions={}):
    """ Génère une paire (clef, certificat) signés par la CA passée
    en paramètre

    @param CACert: Le path vers le certificat authorité.
    @type CACert: str
    @param CAKey: Le path vers la la clef pour signer avec le certificat
                  authorité.
    @type CAKey: str

    @param version: La version désirée pour le certificat en sortie.
    @param C: L'attribut Country du certificat à générer
    @type C: str
    @param ST: L'attribut State du certificat à générer
    @type ST: str
    @param CN: L'attribut Common Name du certificat à générer
    @type CN: str
    @param OU: L'attribut Organisational Unit du certificat à générer
    @type OU: str
    @param O: L'attribut Organisation du certificat à générer

    @type O: str
    @param L: L'attribut Location du certificat à générer
    @type L: str

    @param hashAlgorithm: L'algo utilisé par le certificat à générer.
    @type hashAlgorithm: str

    @param signingAlgorithm: L'algorithme asymétrique de signature utilisé
                             par le certificat à générer.
    @type signingAlgorithm: int
    
    @param generatedKeySize: taille de la clée à générée
    @type generatedKeySize: int

    @param dateBefore: La date à partir de la quelle le certificat à
                       générer sera valide
    @type dateBefore: int
    @param dateAfter: La date au delà de la quelle le certificat à
                      générer ne sera plus valide
    @type dateAfter: int

    @param extensions: liste d'extensions à utiliser pour x509v3
    @type extensions: dict

    @return (key, cert): Une clef et un certificat x509 signés par la CA.
    @rtype str, str
    """

    with open(CACert, "r") as f:
        ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                  f.read())
    with open(CAKey, "r") as f:
        ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                  f.read())

    key = OpenSSL.crypto.PKey()
    key.generate_key(signingAlgortihm, generatedKeySize)

    req = OpenSSL.crypto.X509Req()
    req.get_subject().C = C
    req.get_subject().ST = ST
    req.get_subject().L = L
    req.get_subject().O = O
    req.get_subject().OU = OU
    req.get_subject().CN = CN

    req.set_pubkey(key)
    req.sign(key, hashAlgorithm)
    
    cert = OpenSSL.crypto.X509()
    cert.set_subject(req.get_subject())
    cert.set_version(version - 1)
    cert.set_serial_number(int.from_bytes(os.urandom(8), "big"))
    cert.gmtime_adj_notBefore(dateBefore)
    cert.gmtime_adj_notAfter((1 + dateAfter)*365*24*60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(req.get_pubkey())
    
    if(version == 3):
        x509Extensions = []
        for dict_key in extensions:
            dict_value = extensions[dict_key]
            x509Extensions.append(OpenSSL.crypto.X509Extension(dict_key.encode(), False, dict_value.encode()))
        cert.add_extensions(x509Extensions)

    cert.sign(ca_key, hashAlgorithm)

    PEMKey = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    PEMCert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    return PEMKey.decode(),PEMCert.decode()
