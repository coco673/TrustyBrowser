#!/usr/bin/env python
# encoding: utf-8

import logging
import re
from .Test import Test
from trustybrowser import tlslite
from trustybrowser.utils.CipherSuitesCriticity import CipherSuiteCriticity


class CheckLowLevelCiphers(Test):

    def __init__(self, options, vulnDetector):
        Test.__init__(self, options, 10556, vulnDetector)

        # Éléments du rapport
        self.__tag = "Tests sur les suites cryptographiques"
        self.__name = ""
        self.__description = ""
        self.__criticity = self.IMPORTANT
        self.__result = 0
        self.__comment = ""

        # Dictionnaire sur les suites chiffrantes
        self.__cscDict = CipherSuiteCriticity()

    def execute(self, socket):
        """ Surchage de la fonction héritée de Test. Établit une nouvelle
        session TLS avec le client, récupère la liste des suites chiffrantes
        proposée dans le ClientHello et analyse la criticité des algorithmes
        avant de renvoyer le rapport. """

        self.__result = 0

        # Structure répertoriant, selon leur types, les algorithmes utilisés
        # dans les suites chiffrantes présentes dans le ClientHello et leur
        # niveau de sécurité respective.
        # Chaque élément de la liste est un couple (string, dict) : la chaîne
        # de caractères servira pour la description du rapport; le
        # dictionnaire reprend les données du tableau properties de __cscDict
        # avec uniquement les algorithmes présents dans le ClientHello
        clientHelloAlgo = [
            ("algorithmes d'échanges de clefs", {}),
            ("algorithmes d'authentification", {}),
            ("algorithmes de chiffrement", {}),
            ("codes MAC", {})
        ]

        # SSLification de la connexion
        tls = tlslite.TLSConnection(socket)

        with open(self.options["cert_ca"], "r") as caCert:
            xCertCa = tlslite.X509().parse(caCert.read())
        with open(self.options["cert_file"], "r") as certfile:
            xCert = tlslite.X509().parse(certfile.read())
        with open(self.options["key_file"]) as keyfile:
            certkey = tlslite.parsePEMKey(keyfile.read(), private=True)
        certChain = tlslite.X509CertChain([xCert, xCertCa])

        # Handshake
        try:
            tls.handshakeServer(certChain=certChain, privateKey=certkey)
        except Exception as err:
            logging.error("CheckLowLevelCiphers : {0}".format(err))
            tls.close()
            raise err

        # Suite chiffrante du ClientHello
        chCS = tls.clientHello.cipher_suites

        # Collecte des niveaux de sécurité des algorithmes du ClientHello. Ce
        # dernier contient uniquement des codes standard au format hexadécimal
        # des suites reconnues par SSL/TLS. À partir de ces codes, nous allons
        # remplir la structure clientHelloAlgo.
        # Pour chacun de ces codes :
        for csCode in chCS:
            # On récupère la liste des algorithmes de la suite (si elle existe)
            try:
                algoList = self.__cscDict.cipherSuitesAlgos[csCode]

                # Pour chaque algorithme de la liste:
                for i in range(4):
                    # On renseigne son niveau de sécurité dans le dictionnaire
                    # correspondant de clientHelloAlgo
                    algoLbl = algoList[i]
                    algoDict = clientHelloAlgo[i][1]
                    propDict = self.__cscDict.properties[i]

                    if algoLbl in propDict:
                        algoDict[algoLbl] = propDict[algoLbl]
                    else:
                        logging.error("CheckLowLevelCiphers: Aucune entrée \
                                      correspondant à {0} dans le dictionnaire\
                                      des nivaux de sécurité des algorithmes.\
                                      ".format(algoLbl))
            except Exception as err:
                logging.error("CheckLowLevelCiphers: {0}".format(err))

        # Si des algorithmes de chiffrement utilisant CBC sont utilisés alors
        # on le signale au détecteur de vulnérabilités
        regexp = re.compile(".*_CBC.*")
        for algoLbl in list(clientHelloAlgo[2][1].keys()):
            if regexp.match(algoLbl):
                self.vulnDetector.setVuln(tls.getpeername()[0], "CBC", True)

        # Établissement du diagnostic : nous allons déterminer les paramètres
        # du rapport au cas par cas (échange de clefs, authentification, ...)
        # Pour chaque type d'algorithme (kExch, Auth, Enc, Mac)
        for i in range(4):
            chAlgoDict = clientHelloAlgo[i]

            # On donne un nom et une description du test
            self.__name = "Analyse des {0}".format(chAlgoDict[0])
            self.__description = "Examine le niveau de sécurité des {0} \
            utilisés dans les suites chiffrantes.\
            ".format(chAlgoDict[0])

            # On recherche du niveau le plus critique parmi ceux retenus
            # précédemment
            # lvl = max(clientHelloAlgo[i][1].values()[0])
            lvl = max([p[0] for p in clientHelloAlgo[i][1].values()])

            # On en déduit si le test est un échec ou une réussite
            if lvl > 0:
                self.__result = 0
            else:
                self.__result = 1

            # Enfin, on fournit des commentaires sur le résultat du test :
            # libellés des algorithmes, des suites chiffrantes contenant ces
            # algorithmes, la cause de la criticité et éventuellement, les
            # attaques possibles dessus.
            if self.__result == 1:
                self.__comment = "Félicitation! Aucun algorithme faible n'a \
                été trouvé dans votre configuration. Vous utilisez les \
                algorithmes suivants (qui sont sûrs à ce jour) :<ul><li>"
            else:
                self.__comment = "Les algorithmes suivants ont été jugés \
                faibles :<ul><li>"

            self.__comment += ", </li><li>".join(
                ["{0} : {1}".format(key, "; ".join([str for str in value[1]]))
                 for key, value in clientHelloAlgo[i][1].items()
                 if value[0] == lvl])
            self.__comment += "</li></ul>"

            if self.__result == 1:
                # On récupère les suites présentes dans le ClientHello et on
                # calcule leur niveaux de sécurité (par rapport aux niveaux
                # respectifs des algorithmes les composant). En principe le
                # calcul se résume à prendre le niveau le plus critique parmi
                # les algos de la suite, mais dans notre cas, faire une somme
                # revient au même.
                valCSList = []
                for cs in chCS:
                    try:
                        lvlSum = 0
                        algoList = self.__cscDict.cipherSuitesAlgos[cs]
                        for j in range(4):
                            propDict = self.__cscDict.properties[j]
                            algoLbl = algoList[j]
                            lvlSum += propDict[algoLbl][0]

                        # Si la somme vaut toujours 0, alors la suite est sûre
                        if lvlSum == 0:
                            valCSList.append(
                                self.__cscDict.cipherSuitesAlgos[cs][4])
                    except Exception:
                        # On ignore les suite non reconnues
                        continue
                if len(valCSList) > 0:
                    self.__comment += "Les suites chiffrantes suivantes sont \
                    donc sûres :<ul><li>"
                    self.__comment += ", </li><li>"\
                        .join([x for x in valCSList])
                    self.__comment += "</li></ul>"
                else:
                    self.__comment += "Cependant votre configuration ne \
                    propose aucune suite entièrement sûre."
            else:
                self.__comment += "</li></ul>Par conséquent les suites \
                chiffrantes suivantes sont déconseillées :<ul><li>"

                # On récupère ici les suites chiffrantes présentes dans le
                # ClientHello
                algoDict = self.__cscDict.cipherSuitesAlgos
                propDict = self.__cscDict.properties[i]
                if len(clientHelloAlgo[i][1].keys()) > 0:
                    for algoLbl in clientHelloAlgo[i][1].keys():
                        self.__comment += ", </li><li>".join(
                            [value[4] for key, value in algoDict.items()
                             if (key in chCS and value[i] == algoLbl and
                                 propDict[algoLbl][0] == lvl)])
                    self.__comment += "</li></ul>"

            # Envoie du rapport au worker de SSLTester
            try:
                self.reports.append(tls.getpeername()[0], {
                    "tag": self.__tag,
                    "name": self.__name,
                    "description": self.__description,
                    "criticity": self.__criticity,
                    "result": self.__result,
                    "comment": self.__comment
                })
            except Exception as err:
                logging.error("CheckLowLevelCiphers : {0}".format(err))
