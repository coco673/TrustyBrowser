from .Test import Test
import logging
from trustybrowser import tlslite
import socket
from trustybrowser.tlslite.api import X509CertChain, X509
from trustybrowser.tlslite.api import parsePEMKey
from trustybrowser.utils import PKI


class CheckX509V3Extensions(Test):

    """ Vérifie si le client vérifie les extensions obligatoires
        dans les certificats X509 Version 3 puis retourne un rapport """

    def __init__(self, options, vulnDetector):
        Test.__init__(self, options, 10559, vulnDetector)

        self.__tag = "Tests sur les certificats X509"
        self.__name = "Analyse des extensions des certificats v3"
        self.__description = "Vérifie si le client accepte les certificats \
        x509 v3 ne disposant pas des extensions nécessaires."
        self.__criticity = Test.IMPORTANT
        self.__result = 0
        self.__comment = ""

        # Génération de certificats invalides x509v3 sans extensions
        key, cert = PKI.genCerts(self.options["cert_ca"],
                                 self.options["key_ca"],
                                 socket.gethostbyaddr(socket.gethostbyname(
                                                      socket.getfqdn()))[0])

        self.key = parsePEMKey(key, private=True)
        self.cert = X509().parse(cert)
        with open(self.options["cert_ca"]) as f0:
            self.CA = X509().parse(f0.read())

    def execute(self, socket):
        """ Exécute le test sur la connexion socket en utilisant un
        certificat X509 V3 sans extensions. """

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
            self.__comment = "Attention ! Votre navigateur ne vérifie pas les \
            extensions minimales des certificats X509 Version 3. Les \
            extensions minimales requises sont: (voir RFC 5280) <ul><li> \
            keyUsage,</li><li>certificatePolicies,</li><li> \
            subjectAlternativeName,</li><li>basicConstraints,</li><li> \
            nameConstraints,</li><li>policyConstraints,</li><li> \
            extendedKeyUsage,</li><li>inhibitAnyPolicy.</li></ul>"
        except Exception as err:
            self.__result = 1
            self.__comment = "Félicitation ! Votre client vérifie les \
            extensions minimales des certificats X509 Version 3."
            logging.info("CheckX509V3Extensions : {0}".format(err))
        finally:
            self.reports.append(addr, {
                "tag": self.__tag,
                "name": self.__name,
                "description": self.__description,
                "criticity": self.__criticity,
                "result": self.__result,
                "comment": self.__comment
            })
