from .Test import Test
from trustybrowser import tlslite
import logging
import socket
from trustybrowser.tlslite.api import X509CertChain, X509
from trustybrowser.tlslite.api import parsePEMKey
from trustybrowser.utils import PKI


class CheckX509V2(Test):

    """ Vérifie si le client accepte des certificats X509 de Versions V1 puis
    retourne un rapport.
    """

    def __init__(self, options, vulnDetector):
        Test.__init__(self, options, 10560, vulnDetector)

        self.__tag = "Tests sur les certificats X509"
        self.__name = "Analyse de l'utilisation de certificats depréciés \
        (x509 version 2)"
        self.__criticity = Test.MAXIMAL
        self.__description = "Vérifie si le client accepte des certifcats X509\
        de version V2."
        self.__result = 0
        self.__comment = ""

        # Génération de certificats invalides
        key, cert = PKI.genCerts(self.options["cert_ca"],
                                 self.options["key_ca"],
                                 socket.gethostbyaddr(socket.gethostbyname(
                                                      socket.getfqdn()))[0],
                                 version=2)
        self.key = parsePEMKey(key, private=True)
        self.cert = X509().parse(cert)
        with open(self.options["cert_ca"]) as f0:
            self.CA = X509().parse(f0.read())

    def execute(self, socket):

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
            self.__comment = "Attention ! Votre navigateur accepte de se \
            connecter sur des serveurs disposant de certificats x509 en \
            version 2 qui sont actuellement obsolètes."
        except Exception as err:
            if format(err) == "bad_certificate":
                self.__result = 1
                self.__comment = "Félicitation ! Votre navigateur refuse de se\
                connecter sur des serveurs disposant de certificats x509 en \
                version 2 qui sont actuellement obsolètes."
            logging.info("CheckX509Versions : {0}".format(err))
        finally:
            self.reports.append(addr, {
                "tag": self.__tag,
                "name": self.__name,
                "description": self.__description,
                "criticity": self.__criticity,
                "result": self.__result,
                "comment": self.__comment
            })
