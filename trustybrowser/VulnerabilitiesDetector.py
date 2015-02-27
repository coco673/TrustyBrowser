#!/usr/bin/env python
# encoding: utf-8

from threading import Lock
import functools
import logging


class VulnerabilitiesDetector(object):

    """ Classe répertoriant diverses attaques sur SSL/TLS et les conditions
    requises pour que celles-ci soient possible.

    Chaque attaques dont tous les prérequis ont été vérifié par les plugins
    seront présenté dans le diagnostic final. """

    def __init__(self):
        # un dictionnaire de la forme {ip : [{rapport test unitaire}]}
        self.__value = {}
        # Le verrou permettant de synchroniser les modifications.
        self.__lock = Lock()

        # Dictionnaire répertoriant les attaques, les préconditions, leur
        # descriptions, causes, conséquence et contre-mesure
        self.__vuln = {
            "POODLE": {
                "cond": {"SSL3": False, "CBC": False, "MacThenEncrypt": True},
                "desc": "Padding Oracle On Downgraded Legacy Encryption : \
                        Vulnérabilité présente dans SSL 3.0 permettant de \
                        déchiffrer les informations échangées entre le client \
                        et le serveur par une attaque de type MITM.",
                "causes": "à l'emploi de SSL3.0 et du mode opératoire CBC",
                "cons": "le déchiffrement des paquets transmits",
                "ctrms": "l'utilisation de TLS 1.0 au minimum"
            },

            "BEAST": {
                "cond": {"TLS1": False, "CBC": False, "MacThenEncrypt": True},
                "desc": "Browser Exploit AgainstSS/TLS : Exploit permettant le\
                        MITM dû aux faiblesses du mode opératoire CBC. \
                        L'attaquant peut ainsi déchiffrer discrètement les \
                        données échangées.",
                "causes": "aux IV qui deviennent prédictibles avec l'emploi de\
                           TLS1.0 et du mode opératoire CBC",
                "cons": "le déchiffrement des paquets (généralement des \
                        cookies)",
                "ctrms": "l'utilisation de TLS 1.1 au minimum"
            },

            "CRIME": {
                "cond": {"TLScompression": False},
                "desc": "Compression Ratio Info-leak Made Easy : Exploit \
                        contre les cookies secrets à travers une connexion \
                        employant la compression de données du protocole TLS.",
                "causes": "à la compression des données avant chiffrement",
                "cons": "le détournement de session (session hijacking) en \
                        récupérant le cookie d'authentification",
                "ctrms": "soit de désactiver la compression des données par \
                         TLS soit d'installer une protection contre les CSRF \
                         (exemple pour Firefox: les extensions CsFire et \
                         RequestPolicy)"
            },

            "LUCKY13": {
                "cond": {"MacThenEncrypt": True, "CBC": False},
                "desc": "Attaque temporelle contre les implémentations TLS.",
                "causes": "l'ordre d'exécution des opérations cryptographiques\
                           (Mac-Then-Encrypt : Mac sur la payload puis \
                           chiffrement du paquet entier) qui ne permet aucun \
                           contrôle sur les données chiffrées",
                "cons": "l'exposition des données chiffrées",
                "ctrms": "de passer en Encrypt-Then-Mac"
            }
        }

    def setVuln(self, ip, cond, value):
        """ Donne la valeur pour une précondition de vulnérabilité.

        @param ip: l'ip dont on veut indiqué la possibilité de vulnérabilité.
        @type ip: str
        @param cond: la précondition dont on veut donner la valeur.
        @type cond: str
        @param value: la valeur à donner à la condition.
        @type value: bool
        """
        with self.__lock:
            failles = self.__value[ip]
            for faille in failles:
                if cond in failles[str(faille)]["cond"]:
                    self.__value[ip][str(faille)]["cond"][cond] = value

    def get(self, ip):
        """ Renvoie le dictionnaire des vulnérabilité associé à une IP.

        @param ip: L'ip dont on veut obtenir le dictionnaire des
                   vulnérabilités.
        @type ip: str

        @return Le dictionnaire demandé.
        @rtype dict
        """
        with self.__lock:
            v = self.__value[ip]
        return v

    def checkVuln(self, reports, addr):
        """ Parcours le dictionnaire et renvoie un rapport par attaque.

        @param reports: l'ensemble des rapports
        @param addr: l'identifiant de session sur lequel seront indexés les
        rapports générés ici
        """
        result = 0
        with self.__lock:
            failles = self.__value[addr]

            # Pour chaque attaque référencée, on complète le rapport
            for att in failles:

                # Si la vulnérabilité est avérée, on signale comme non
                # sécurisé et on rajoute des détails
                # (causes, conséquence, etc).

                if self.__isVulnTo(att, addr):
                    result = 0
                    comment = "Vous êtes vulnérable à ce type d'attaque.<br>Ceci \
                              est dû à {0}, ce qui rend possible {1}.<br>Nous \
                              recommandons {2}."\
                              .format(self.__value[addr][att]["causes"],
                                      self.__value[addr][att]["cons"],
                                      self.__value[addr][att]["ctrms"])
                # Sinon on signale que la configuration est sûre.
                else:
                    result = 1
                    comment = "Vous êtes protégé contre ce type d'attaque."

                # Stockage du rapport
                reports.append(addr, {
                    "tag": "Vulnérabilités potentielles",
                    "name": "Détection de l'attaque {0}".format(att),
                    "description": self.__vuln[att]["desc"],
                    "criticity": 8,
                    "result": result,
                    "comment": comment
                })

    def __isVulnTo(self, attName, ip):
        """ Renvoie True si toutes les condition de l'attaque sont remplie.

        @param attName: Le nom de l'attaque
        @return Un booléen indiquant si l'attaque est possible ou pas.
        """
        return functools.reduce(
            lambda x, y: x and y, self.__value[ip][attName]["cond"].values()
        )

    def delete(self, ip):
        """ Supprime le dictionnaire des vulnérabilités associé à une ip.

        @param ip: l'ip dont on veut supprimer le rapport.
        """
        with self.__lock:
            try:
                self.__value[ip]
            except KeyError as k:
                logging.info("VulnerabilitesDetector : {0}".format(k))
                pass
            else:
                del self.__value[ip]

    def add(self, ip):
        """ Créé une entrée pour les vulnérabilités d'une IP.

        @param ip: Le ip à laquelle on veut ajouter le rapport.
        """
        with self.__lock:
            try:
                self.__value[ip]
            except KeyError:
                self.__value[ip] = self.__vuln.copy()
            else:
                raise KeyError()
