#!/usr/bin/env python
# encoding: utf-8

import socket
import threading
import logging
import re


class Test(threading.Thread):

    NEGLIGIBLE = 2
    LIMITED = 3
    IMPORTANT = 5
    MAXIMAL = 8

    def __init__(self, options, port, vulnDetector):
        threading.Thread.__init__(self)
        self.reports = None
        self.__hostname = None
        self.__stop = threading.Event()
        self.__port = port
        self.options = options
        self.__statistics = None
        self.vulnDetector = vulnDetector

    def stop(self):
        """ Stope proprement le test """
        self.__stop.set()
        with socket.socket() as conn:
            try:
                conn.connect((self.__hostname, self.__port))
            except:
                pass
        self.join()
        logging.info("Arrêt de {0}".format(self.__class__.__name__))

    def run(self):
        """ Lance un serveur en écoute en vue d'exécuter le test sur toutes les
        connexions entrantes. Stocke le résultat du test dans la liste des
        rapports.

        """
        with socket.socket() as server:
            try:
                server.bind((self.__hostname, self.__port))
                server.listen(10)
            except socket.error:
                logging.error("Impossible de charger {0} en écoute sur le \
                            le port {1} : port occupé".
                              format(self.__class__.__name__,
                                     str(self.__port)))
            else:
                logging.info("Démarrage de {0}".
                             format(self.__class__.__name__))
                while self.__stop.isSet() is False:
                    try:
                        client, addr = server.accept()
                        self.execute(client)
                    except:
                        logging.error("Une erreur est survenue dans ". \
                            format(self.__class__.__name__))
                    finally:
                        client.close()

    def execute(self, socket):
        """ Méthode à surcharger pour l'exécution du test.

        @param socket: La connexion sur laquelle le test sera exécuté.
        @type socket: L{socket.socket}

        @return name: Le nom du test
                description: Une description générale de ce que fait le test
                criticity: L'importance du test du point de vue de la sécurité
                result: Succès (1) ou échec (0) du test
                comment: Les raisons pour lesquelles le test a échoué, des
                conseils pour améliorer la sécurité, ...
        """
        pass

    def getToken(self, socket):
        """ Récupère le token à partir d'une requête HTTP via une expression
        régulière.

        @param socket: La connexion sur laquelle on va récupérer le token.
        @type socket: L{socket.socket}

        @return token: le token associé au client.
        """

        buf = socket.read(1024).decode()
        pattern = re.compile('token=([a-fA-F0-9]+)')
        match = re.search(pattern, buf)
        if match:
            return match.group(1)
        raise ValueError("Token introuvable")

    @property
    def port(self):
        return self.__port

    @property
    def hostname(self):
        return self.__hostname


    # @property
    # def statistics(self):
    #     return self.__statistics

    @port.setter
    def port(self, value):
        if isinstance(self, Test):
            self.__port = value
        else:
            raise AttributeError

    @hostname.setter
    def hostname(self, value):
        if isinstance(self, Test):
            self.__hostname = value
        else:
            raise AttributeError

    # @statistics.setter
    # def statistics(self, value):
    #     if isinstance(self, Test):
    #         self.__statistics = value
    #     else:
    #         raise AttributeError
