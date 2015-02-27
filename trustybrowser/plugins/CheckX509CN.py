import logging
from .Test import Test
from trustybrowser import tlslite
from trustybrowser.tlslite.api import X509CertChain, X509
from trustybrowser.tlslite.api import parsePEMKey
from trustybrowser.utils import PKI


class CheckX509CN(Test):

    """ Vérifie si le client accepte des certificats X509 obsolètes de CN
    invalide """

    def __init__(self, options, vulnDetector):
        Test.__init__(self, options, 10558, vulnDetector)

        self.__tag = "Tests sur les certificats X509"
        self.__name = "Analyse de la concordance du common name du \
        certificat et le nom de serveur"
        self.__description = "Vérifie si le client accepte des certifcats \
        dont le Common Name est invalide."
        self.__criticity = Test.MAXIMAL
        self.__result = 0
        self.__comment = ""

        key, cert = PKI.genCerts(self.options["cert_ca"],
                                 self.options["key_ca"],
                                 "*",
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
        """ Exécute le test sur la connexion socket en utilisant un certificat
        dont le nom ne correspond pas au service pour établir la session TLS.

        @param socket: La connexion sur la quelle le test sera effectué.
        @type socket: L{socket.socket}
        """

        self.__result = 0
        tls = tlslite.TLSConnection(socket)
        addr = tls.getpeername()[0]
        xCertChain = X509CertChain([self.cert, self.CA])

        settings = tlslite.HandshakeSettings()
        settings = settings._filter()

        # Handshake
        try:
            tls.handshakeServer(certChain=xCertChain, privateKey=self.key)

            # Si le handshake réussi, le certificat à été accepté:
            self.__result = 0
            self.__comment = "Attention ! Votre navigateur accepte de se \
            connecter sur des serveurs qui ne dispose pas du bon nom de \
            connexion."
        except Exception as err:
            if format(err) == "bad_certificate":
                # Si le test échoue car le certificat à été rejeté:
                self.__result = 1
                self.__comment = "Félicitation ! Votre navigateur n'accepte \
                pas les connexions avec des serveurs ayant un certificat qui \
                ne correspond pas à leur adresse sur laquelle vous vous \
                connecté."
            logging.info("CheckX509CommonName : {0}".format(err))
        finally:
            self.reports.append(addr, {
                "tag": self.__tag,
                "name": self.__name,
                "description": self.__description,
                "criticity": self.__criticity,
                "result": self.__result,
                "comment": self.__comment
            })
