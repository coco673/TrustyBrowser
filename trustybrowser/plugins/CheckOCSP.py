#!/usr/bin/env python
# encoding: utf-8

from .Test import Test
import logging
import socket
from trustybrowser import tlslite
from trustybrowser.utils import PKI, CRL
from trustybrowser.tlslite.api import X509CertChain, X509
from trustybrowser.tlslite.api import parsePEMKey


class CheckOCSP(Test):

    """ module permettant de tester la verification des certificats via OCSP.
        Si le client accepte une connexion sans recevoir de reponse d'un
        responder OCSP alors le test est un échec, sinon le test est réussi.
    """

    def __init__(self, options, vulnDetector):
        Test.__init__(self, options, 10561, vulnDetector)
        self.__tag = "Tests sur le protocole OCSP"
        self.__name = "Analyse des requêtes OCSP provenant du client"
        self.__description = "Vérification de la reponse d'un responder OCSP"
        self.__criticity = Test.MAXIMAL
        self.__result = 0
        self.__extensions = {"nsComment": "ssi-ssl Server certificate",
                             "basicConstraints": "critical,CA:FALSE",
                             "keyUsage": "digitalSignature, nonRepudiation" +
                             ", keyEncipherment",
                             "nsCertType": "server",
                             "extendedKeyUsage": "serverAuth",
                             "authorityInfoAccess": "OCSP;URI:http://" +
                             socket.gethostbyaddr(
                                 socket.gethostbyname(socket.getfqdn()))[0]}

        with open(self.options["cert_ca"]) as f0:
            self.CA = X509().parse(f0.read())
        # Génération de certificats invalides
        key, cert = PKI.genCerts(self.options["cert_ca"],
                                 self.options["key_ca"], socket.gethostbyaddr(
                                     socket.gethostbyname(
                                         socket.getfqdn()))[0],
                                 extensions=self.__extensions)
        CRL.revokeCerts(self.options["cert_ca"],
                        self.options["key_ca"], [cert])
        self.key = parsePEMKey(key, private=True)
        self.cert = X509().parse(cert)

    def execute(self, socket):

        self.__result = 0
        # Création de la connexion TLS
        conn = tlslite.TLSConnection(socket)
        addr = conn.getpeername()[0]
        # FIXME : verification de la présence du rapport dans l'objet.
        # if self.reports.get(addr, self.__name) == []:
        xCertChain = X509CertChain([self.cert, self.CA])
        comment = ""
        try:
            conn.handshakeServer(certChain=xCertChain, privateKey=self.key)
            # Handshake complet - Echec du test
            comment = "Attention ! Votre navigateur est peu fiable car\
               il ne verifie pas la conformité du certificat du serveur\
               avec un responder OCSP"
        except Exception as e:
            # Handshake incomplet à cause de la verification -
            if "bad_certificate" in format(e):
                # Succès du Test
                self.__result = 1,
                comment = "Félicitation ! Votre navigateur attend une \
                   reponse sur la validité du certificat serveur utilisé\
                    avant de continuer la poignée de main"
                logging.info("CheckOCSP : {0}".format(e))
            else:
                logging.info("CheckOCSP : {0}".format(e))
        finally:
            try:
                self.reports.append(addr, {
                    "tag": self.__tag,
                    "name": self.__name,
                    "description":  self.__description,
                    "criticity": self.__criticity,
                    "result": self.__result,
                    "comment": comment
                }
                )
            except Error as er:
                logging.error("Exception reçue par CheckOCSP : {0}"
                              .format(er))
            except Exception as er:
                logging.error("Exception reçue par CheckOCSP : {0}"
                              .format(er))
