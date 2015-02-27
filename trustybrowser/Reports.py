#!/usr/bin/env python
# encoding: utf-8

from threading import Lock
from threading import Timer


class Reports(object):

    """ Classe représentant une liste de  rapports de tests associé à une
    connexion."""

    # Durée de vie d'une ip, en secondes
    TIMEOUT = 30

    def __init__(self):
        # un dictionnaire de la forme {ip : [{rapport test unitaire}]}
        self.__value = {}
        # Le verrou permettant de synchroniser les modifications.
        self.__lock = Lock()

    def get(self, ip, name=None):
        """ Retourne une copie du rapport associé à un ip, ou une entrée
        particulière dans ce rapport.

        @param ip: l'ip dont on veut obtenir le rapport.
        @param name: le nom d'une entrée dans le rapport. Si celui-ci vaut
        None, tout le rapport est retourné.
        @return Une entrée dans un rapport ou le rapport entier.
        """
        with self.__lock:
            v = []
            for r in self.__value[ip]["report"]:
                if name and name == r.name:
                    v = r.copy()
                    break
                else:
                    v.append(r.copy())
        return v

    def append(self, ip, report, token=None):
        """ Ajoute une nouvelle entrée à un rapport.

        @param ip: l'ip du client dont on veut modifier le rapport.
        @param report: une nouvelle entrée dans le rapport affecté à l'ip.
        """
        with self.__lock:
            try:
                t = self.__value[ip]["token"]
                for r in self.__value[ip]["report"]:
                    if report["name"] == r["name"]:
                        raise KeyError()
            except KeyError:
                pass
            else:
                if not token or token == t:
                    self.__value[ip]["report"].append(report)

    def delete(self, ip, token=None):
        """ Supprime le rapport associé à une ip dans la liste.

        @param ip: l'ip dont on veut supprimer le rapport.
        @param token: le token associé à l'ip. Ce paramètre est utilisé par le
        système de suppression automatique des ip pour ne pas supprimer une ip
        réallouée.
        """
        with self.__lock:
            try:
                t = self.__value[ip]["token"]
            except KeyError:
                pass
            else:
                if not token or token == t:
                    del self.__value[ip]

    def add(self, ip, token):
        """Ajoute un ip et un rapport à la liste.

        @param ip: Le ip à laquelle on veut ajouter le rapport.
        @param report: le rapport à ajouter.
        """
        with self.__lock:
            try:
                self.__value[ip]
            except KeyError:
                self.__value[ip] = {"token": token, "report": []}
                Timer(self.TIMEOUT, self.delete, [ip, token]).start()
            else:
                raise KeyError()

    def __repr__(self):
        return repr(self.__value)
