from .Test import Test
from trustybrowser import tlslite
from trustybrowser.tlslite.constants import ContentType
from trustybrowser.tlslite.constants import HandshakeType


class CheckSSLVersion(Test):

    def __init__(self, options, vulnDetector):
        Test.__init__(self, options, 10562, vulnDetector)
        # Les informations sur chaque version du protocole
        self.__versions = [
            {
                "result": 0,
                "name": "SSL 3",
                "description": "Vérifie le support de SSL 3",
                "comment": "Cette version n'est pas sûre et ne devrait plus \
                être utilisée"
            },
            {
                "result": 0,
                "name": "TLS 1.0",
                "description": "Vérifie le support de TLS 1.0",
                "comment": "Cette version est sujette à des attaques et ne \
                supporte pas les dernières suites cryptographiques"
            },
            {
                "result": 1,
                "name": "TLS 1.1",
                "description": "Vérifie le support de TLS 1.1",
                "comment": "Cette version est sûre"
            },
            {
                "result": 1,
                "name": "TLS 1.2",
                "description": "Vérifie le support de TLS 1.2",
                "comment": "Cette version est la plus sûre à ce jour"
            },
            {
                "result": 0,
                "name": "Version inconnue",
                "description": "Vérifie le support de versions inconnues",
                "comment": "La sécurité de cette version ne peut être évaluée"
            }
        ]

    def execute(self, socket):
        """ Exécute le test de récupération des version SSL/TLS.

        @param socket: la connexion dont on veut récupérer les paramètres.
        @type socket: socket.socket
        """
        # Récupération de l'ip
        ip = socket.getpeername()[0]

        # Encapsulation dans TLS
        tls = tlslite.TLSConnection(socket)

        # Récupération de la version
        # TODO: trouver un moyen plus propre
        for result in tls._getMsg(ContentType.handshake,
                                  HandshakeType.client_hello):
            if result not in (0, 1):
                break

        # Récupération des infos sur la version
        index = None
        try:
            index = result.client_version[1]
            version = self.__versions[index]
        except:
            index = 4
            version = self.__versions[index]

        # Mise à jour de la classe VulnerabilitiesDetector
        if (index == 0):
            self.vulnDetector.setVuln(tls.getpeername()[0], "SSL3", True)
        elif (index == 1):
            self.vulnDetector.setVuln(tls.getpeername()[0], "TLS1", True)
        elif (index == 2):
            self.vulnDetector.setVuln(tls.getpeername()[0], "TLS1.1", True)
        elif (index == 3):
            self.vulnDetector.setVuln(tls.getpeername()[0], "TLS1.2", True)
        report = {
            "tag":  "Tests sur les versions SSL/TLS supportées",
            "criticity": Test.MAXIMAL,
            "name": version["name"],
            "description":  version["description"],
            "comment": version["comment"],
            "result": version["result"]
        }
        # Envoie du rapport
        self.reports.append(ip, report)
