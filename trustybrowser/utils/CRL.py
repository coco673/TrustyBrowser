#!/usr/bin/env python3
# encoding: utf-8

import OpenSSL
import sys
import os
import time
from random import random
import binascii


def revokeCerts(CACert, CAKey, Certs):
    """ Revoke la liste des certificats signés par la CA passée
    en paramètre et l'enregistre dans le fichier liste des CRL passés en
                 paramètre

    @param CACert: Le path vers le certificat authorité.
    @type CACert: str

    @param CAKey: Le path vers la la clef pour signer avec le certificat
                  authorité.
    @type CAKey: str

    @param Certs: liste des certificats à revoker
    @type Certs: liste

    @param CERT_REVOKE_FILE: liste des certificats revokés
    @type CERT_REVOKE_FILE: str

    """
    try:
        with open(CACert, "r") as f:
            ca_cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, f.read())
        with open(CAKey, "r") as f:
            ca_key = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, f.read())
    except IOError as e:
        log.error(e)
        raise
    crl = OpenSSL.crypto.CRL()
    for cert in Certs:
        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert)
        revoked = OpenSSL.crypto.Revoked()
        revoked.set_serial(hex(x509.get_serial_number()).encode("utf8"))
        crl.add_revoked(revoked)
        crl.export(ca_cert, ca_key)
    return crl
