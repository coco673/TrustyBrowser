import logging
from .Test import Test
import socket
from trustybrowser import tlslite
from trustybrowser.tlslite.api import X509CertChain, X509
from trustybrowser.tlslite.api import parsePEMKey
from trustybrowser.utils import PKI


class CheckX509TimeValidity(Test):

    """ Vérifie si le client accepte des certificats X509 dont la date de
    validité est dépassée puis retourne un rapport """

    def __init__(self, options, vulnDetector):
        Test.__init__(self, options, 10557, vulnDetector)

        self.__tag = "Tests sur les certificats X509"
        self.__name = "Analyse de la validité temporelle des certificats"
        self.__description = "Vérifie si le client accepte les certifcats X509\
        dont la date de validité est dépassée."
        self.__criticity = Test.LIMITED
        self.__result = 0
        self.__comment = ""

        # Génération de certificats invalides
        key, cert = PKI.genCerts(self.options["cert_ca"],
                                 self.options["key_ca"],
                                 socket.gethostbyaddr(socket.gethostbyname(
                                                      socket.getfqdn()))[0],
                                 dateAfter=-2,
                                 extensions={
                                    'basicConstraints': 'CA:false',
                                    'keyUsage': 'digitalSignature, \
                                                keyEncipherment',
                                    'extendedKeyUsage': 'serverAuth',
                                    'nsCertType': 'server'})

        self.key = parsePEMKey(key, private=True)
        self.cert = X509().parse(cert)
        with open(self.options["cert_ca"]) as f0:
            self.CA = X509().parse(f0.read())

    def execute(self, socket):
        """ Exécute le test sur la connexion socket en utilisant un
        certificat dont la date a expiré. """

        self.__result = 0
        tls = tlslite.TLSConnection(socket)
        addr = tls.getpeername()[0]

        xCertChain = X509CertChain([self.cert, self.CA])

        settings = tlslite.HandshakeSettings()
        settings = settings._filter()

        # Handshake
        try:
            tls.handshakeServer(certChain=xCertChain, privateKey=self.key)

            self.__result = 0
            self.__comment = "Attention ! Votre navigateur accepte des \
            certificats qui ne sont plus valide du fait d'un dépassement de \
            période de validité."
        except Exception as err:
            self.__result = 1,
            self.__comment = "Félicitation ! Votre navigateur refuse les \
            connexions dont le certificats est dépassé par le temps."
            logging.info("CheckX509TimeValidity : {0}".format(err))
        finally:
            self.reports.append(addr, {
                "tag": self.__tag,
                "name": self.__name,
                "description": self.__description,
                "criticity": self.__criticity,
                "result": self.__result,
                "comment": self.__comment
            })
