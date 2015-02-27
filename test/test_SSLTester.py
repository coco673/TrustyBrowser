#!/usr/bin/env python3
# encoding: utf-8

import os
import sys
import unittest
import threading
from trustybrowser import SSLTester
from trustybrowser.tlslite.api import *
from trustybrowser.tlslite.api import TLSConnection
from trustybrowser.tlslite.api import X509CertChain, X509
from trustybrowser.tlslite.api import parsePEMKey
from time import sleep
import socket


class ServerThread(threading.Thread):
    def __init__(self, sslTester):
        threading.Thread.__init__(self)
        self.sslTester = sslTester

    def run(self):
        self.sslTester.run()
        sys.exit()


class TestSSLTester(unittest.TestCase):

    """ Case utilisé pour tester les fonctions de la classes 'SSLTester' """

    def setUp(self):
        # Création d'une instance du testeur avec les optiosn par défauts
        self.params = {
            "config": "./config.ini",
            "port": 443,
            "report_port": 8001,
            "hostname": "127.0.0.1",
            "html_dir": "./html",
            "plugin_dir": "./plugins",
            "cert_ca": "./PKI/Coriolle_inter_ca2.crt",
            "cert_file": "./PKI/server.crt",
            "key_file": "./PKI/server.key",
            "pool_size": 4}
        self.sslTester = SSLTester(self.params)
        self.nameObj = ["toto.py", "tata.py"]

    def test_run(self):
        """ Teste si une connexion au serveur se déroule bien """

        # Démarrage d'un thread de serveur
        print("TestSSLTester.test_run() : démarrage du serveur")
        servTh = ServerThread(self.sslTester)
        servTh.start()

        # Création de la socket cliente
        print("TestSSLTester.test_run() : création de la socket")
        cSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Laisser le temps au serveur de se mettre en écoute
        sleep(1)

        # Connexion au serveur si celui ci est toujours actif
        if servTh.is_alive():
            try:
                print("TestSSLTester.test_run() : connexion au serveur")
                cSock.connect((self.params['hostname'], self.params['port']))
            except:
                cSock.close()
                exit(0)

            # SSLification
            print("TestSSLTester.test_run() : connexion SSL")
            conn = TLSConnection(cSock)
            print("TestSSLTester.test_run() : handshake")
            conn.handshakeClientCert()

            # Selon la RFC de HTTP, le serveur attend des données avant de
            # pouvoir en diffuser, on envoie donc des données même si elles ne
            # sont pas taitées.
            conn.send("Gros naze!".encode())

            # Réception et affichage de la page principale
            print("TestSSLTester.test_run() : En attente de données")
            mp = conn.recv(1024)
            print(str(mp))
        else:
            print("TestSSLTester.test_run() : Le serveur n'a pas démarré "
                  + "correctement")

        # Fermeture de la socket
        cSock.close()

    def test_stress_run(self):
        """ Test de connexions multiples """
        pass

    def server(self, event):
        """ Initialisation du serveur """
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock.bind(("192.168.34.39", 443))
        ssock.listen(2)
        event.set()
        while True:
            csock, address = ssock.accept()
            print(address)
            self.sslTester.worker(csock, address)
            event.clear()

    def test_worker(self):
        event = threading.Event()
        thread = threading.Thread(target=self.server, args=(event,))
        thread.start()

        event.wait()
        """ Initialisation du client """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("192.168.34.39", 443))
        connection = TLSConnection(sock)
        f1 = open("PKI/client_02.crt")
        xCert = X509().parse(f1.read())
        xCertChain = X509CertChain([xCert])
        f2 = open("PKI/cle-RSA-client_02.key")
        s = f2.read()
        x509key = parsePEMKey(s, private=True)
        connection.handshakeClientCert(certChain=xCertChain,
                                       privateKey=x509key)
        message = ("HTTP/1.0 {0} OK\r\n" +
                   "Content-Length: {1}\r\n" +
                   "Content-Type: {2}; charset=utf-8\r\n\r\n" +
                   "{3}")\
            .format(200, len("toto"), "text/html", "toto").encode("utf-8")

        connection.send(message)
        response = connection.recv(1024)

        print("début des données recues")
        print(response)
        f1.close()
        f2.close()

    def test_loadModule_true(self):
        """Test qui charge un module créé à la volé et ne doit pas
         lever d'exception. Attention il faut rendre visible la
         méthode loadModule
          """
        with open("plugins/"+self.nameObj[0], "w+") as f:
            f.write("#!/usr/bin/env python\n# encoding: utf-8\n"
                    "import Test\nclass Bidon(Test.Test):\n\tdef __init__(self):"
                    "\n\t\tself.i=0\n\tdef plus(self):\n\t\tself.i=self.i+2\n"
                    "def load():\n\treturn Bidon()")
        self.sslTester.loadModule()

    def test_loadModule_false(self):
        """Test qui charge un module créé à la volé et doit
        lever une exception. Attention il faut rendre visible la
        méthode loadModule
        """
        with open("plugins/"+self.nameObj[1], "w+") as f:
            f.write("#!/usr/bin/env python\n# encoding: utf-8\n"
                    "import Test\nclass Bidon(object):\n\tdef __init__(self):"
                    "\n\t\tself.i=0\n\tdef plus(self):\n\t\tself.i=self.i+2\n"
                    "def load():\n\treturn Bidon()")
        self.sslTester.loadModule()

if __name__ == "__main__":
    unittest.main()
    # On supprime les fichiers créés.
    for name in self.nameObj:
            if os.path.isfile("plugins/"+name):
                os.remove("plugins/"+name)
