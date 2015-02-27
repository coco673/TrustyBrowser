#!/usr/bin/env python
# encoding: utf-8

import os
import os.path
import logging
import inspect
import socket
import binascii
import re
import sys
import threading
import json
import trustybrowser.plugins
from trustybrowser.plugins import Test
from multiprocessing.pool import ThreadPool
from .tlslite import errors
from .tlslite.api import TLSConnection
from .tlslite.api import X509CertChain, X509
from .tlslite.api import parsePEMKey
from .Reports import Reports
from .Statistics import Statistics
from .VulnerabilitiesDetector import VulnerabilitiesDetector

NB_LISTEN = 10


class SSLTester(object):

    """ Classe principale gérant l'ensemble des connexions, le chargement des
    modules de test et le maintien de la liste de rapports. """

    def __init__(self, options):
        self.__options = options
        # Chargement du certificat pour le SSLTester:
        try:
            with open(self.__options["cert_ca"], "r") as caCert:
                xCertCa = X509().parse(caCert.read())

            with open(self.__options["cert_file"], "r") as certfile:
                xCert = X509().parse(certfile.read())
            # Chargement de la clef privée
            with open(self.__options["key_file"]) as keyfile:
                self.__certkey = parsePEMKey(keyfile.read(), private=True)
        except FileNotFoundError:
            logging.critical("Certificat introuvable")
            sys.exit(1)
        except errors.TLSAlert:
            logging.critical("Certificat mal formé")
            sys.exit(1)
        else:
            # La socket qui recevra les connexions.
            self.serverSocket = None
            # La liste des rapports
            self.reports = Reports()
            # L'objet qui détectera les attaques possibles pendant l'exécution
            # des plugins
            self.vulnDetector = VulnerabilitiesDetector()
            # Le générateur de statistiques
            self.__statistics = Statistics("statistics.json", 60)
            # L'ensemble des modules de test à charger.
            self.__testPool = []
            # Les nonces sauvegardés
            self.__nonces = {}
            # Table des correspondances ip => token
            # self.ip_mapping = {}
            # Chargement des modules
            self.__loadModule()
            self.__certificateChain = X509CertChain([xCert, xCertCa])

    def __loadModule(self):
        """ Charge les modules dans le pool de tests à exécuter. """
        self.__testPool = [c[1](self.__options, self.vulnDetector)
                           for c in inspect.getmembers(trustybrowser.plugins,
                                                       inspect.isclass)
                           if (c[0] != 'Test') and issubclass(c[1], Test)]
        for loadedPlugin in self.__testPool:
            loadedPlugin.hostname = self.__options['hostname']
            loadedPlugin.reports = self.reports

    def run(self):
        """ Lance l'exécution du serveur pour accepter des connexion sur la
        socket serveur."""

        self.serverSocket = socket.socket()
        try:
            self.serverSocket.bind((self.__options["hostname"],
                                    self.__options["port"]))
        except socket.error as msg:
            logging.error("SSLTester.run() : Le bind a échoué : {0}".
                          format(msg))
            sys.exit(0)
        self.serverSocket.listen(NB_LISTEN)
        threport = threading.Thread(target=self.reporter)
        threport.isDaemon = True
        threport.start()

        # substitution de l'utilisateur pour ne pas s'exécuter en root
        uid = self.__options["substitute"]
        if uid:
            os.setuid(uid)

        # lancement des serveurs de tests
        for test in self.__testPool:
            test.start()

        with ThreadPool(processes=self.__options['pool_size']) as pool:
            try:
                while 1:
                    nsock, add = self.serverSocket.accept()
                    pool.apply_async(self.worker, [[nsock, add]])
            except KeyboardInterrupt:
                logging.error("SSLTester.run() : Signal d'interruption reçu")
                pool.terminate()
                for test in self.__testPool:
                    test.stop()
                exit(0)

    def reporter(self):
        """ Méthode chargé d'envoyer le rapport à un client se connectant.

            Doit être exécutée dans un thread à part.
        """
        try:
            sock = socket.socket()
            sock.bind((self.__options['hostname'],
                       self.__options['report_port']))
        except socket.error as e:
            logging.error("Erreur sur la socket : {0}".format(e))
        sock.listen(NB_LISTEN)
        while 1:
            cli, addr = sock.accept()
            tls = TLSConnection(cli)
            try:
                ipAddr = tls.getpeername()[0]
                tls.handshakeServer(certChain=self.__certificateChain,
                                    privateKey=self.__certkey)
                # Récupération du token depuis la réponse HTTP
                httpRequest = tls.recv(1024)
                token = re.search("token=(.+?)'", str(httpRequest)).group(1)

                # Exécution du test sur les nonces
                test = {
                    "tag": "Contrôle sur l'utilisation des clefs",
                    "name": "Réutilisation des nonces",
                    "description": "Ce test vérifie que l'aléa utilisé dans le\
                    clientHello est différent entre chaque connexion",
                    "criticity": 5
                }
                if tls.clientHello.random != self.__nonces[token]:
                    test["result"] = 1
                    test["comment"] = "Votre navigateur envoie bien un aléa \
                    différent pour chaque tentative"
                else:
                    test["result"] = 0
                    test["comment"] = "Votre navigateur utilise le même aléa \
                    pour plusieurs connexions"
                self.reports.append(ipAddr, test, token)
                del self.__nonces[token]

                # Exécution du test sur la méthode de compression : si cette
                # options est autorisée, des attaques sont possibles
                if (len(self.__cpr) == 1):
                    if (self.__cpr[0] == 0):
                        self.vulnDetector.setVuln(ipAddr,
                                                  "TLScompression",
                                                  True)

                # Recherche de vulnérabilités
                self.vulnDetector.checkVuln(self.reports, ipAddr)

                # Envoi du rapport
                json_report = json.dumps(
                    self.reports.get(ipAddr))
                self.__sendHTTP(tls, json_report, "text/json", True)

                # Suppression de l'entrée dans la liste des rapports
                self.reports.delete(ipAddr)
                self.vulnDetector.delete(ipAddr)

            except errors.TLSAlert:
                pass
            except AttributeError:
                pass
            except Exception as e:
                logging.error("Exception reçue par le reporter: {0}".format(e))
            finally:
                tls.close()

    def worker(self, *args):
        """ Méthode chargée de gérer une connexion d'un client sur le service
        principal. Celle ci est exécutée par un pool de threads.
        """
        tls = TLSConnection(args[0][0])
        try:
            tls.handshakeServer(certChain=self.__certificateChain,
                                privateKey=self.__certkey)
            httpRequest = tls.recv(1024)
            try:
                # La page principale a-t-elle déja été chargée ?
                token = re.search("token=(.+?)'", str(httpRequest)).group(1)
            except:
                # Création du token si chargement de la page principale
                token = "".join("%02x" % b for b in os.urandom(8))
                # Envoi de la page principale
                self.__sendMainPage(tls, token)
            else:
                try:
                    # Création d'une entrée dans la liste des rapports
                    self.reports.add(args[0][1][0], token)
                    self.vulnDetector.add(args[0][1][0])
                except Exception as e:
                    # Si déja occupé, on laisse la connexion se fermer
                    pass
                else:
                    # Si libre, on indique au client que le serveur est prêt
                    # à recevoir les connexions de test
                    self.__sendHTTP(tls, "{}", "text/json", True)
                    # Récupération du nonce pour test utltérieur
                    self.__cpr = tls.clientHello.compression_methods
                    self.__nonces[token] = tls.clientHello.random
        except Exception as e:
            logging.error("Exception reçue par un worker: {0}".format(e))
        finally:
            tls.close()

    def __sendMainPage(self, client, token):
        """ Sert la page principale de l'application

        @param client: Socket cliente.
        @param token: Identifiant du client servant à récupérer le rapport
                         ultérieurement
        """
        tests = []
        for test in self.__testPool:
            tests.append(test.port)
        try:
            response = ""
            with open(self.__options["html_dir"] + "/index.html", "r") as f:
                for line in f:
                    response += line
            self.__sendHTTP(client, response, cookie={
                "token": token,
                "report": self.__options["report_port"],
                "tests": tests,
                "stats": self.__statistics.read(),
                "ip": client.getpeername()[0]
            })
        except FileNotFoundError:
            logging.error("Impossible de charger le fichier index.html")
        except Exception as e:
            logging.error("Erreur inattendue {0}.".format(e))

    def __sendHTTP(self, client, content, contentType="text/html",
                   allowOrigin=False, cookie=None, status="200 OK"):
        """ Envoie une réponse HTTP à un client.

        @param client: La socket cliente
        @param content: Le contenu de la réponse
        @param contentType: Le type de contenu (text/html, text/json, ...)
        @param allowOrigin: Utiliser ou non CORS
        @param cookie: Un dictionnaire
        @param status: Le code de retour de la réponse HTTP
        """
        message = (
            ("HTTP/1.1 {0}\r\n") +
            ("Content-Type:{3};charset=utf-8\r\n") +
            ("Access-Control-Allow-Origin:*\r\n" if allowOrigin else "") +
            ("Set-Cookie:cookie={2}\r\n" if cookie else "") +
            ("Content-Length:{1}\r\n\r\n") +
            ("{4}")) \
            .format(status, len(content.encode("utf8")), binascii.hexlify(
                json.dumps(cookie).encode()).decode("utf8"),
            contentType, content).encode("utf8")
        client.send(message)
