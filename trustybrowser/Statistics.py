#!/usr/bin/env python
# encoding: utf-8

import threading
import json
import logging


class Statistics(object):

    """ Classe pour la génération de rapports statistiques sur les
    implémentations auditées.
    """

    def __init__(self, database, timer):
        # Verrou sur le contenu du rapport
        self.__lock = threading.Lock()
        # Écriture sur le disque programmée ou non
        self.__writePending = False
        # Contenu du rapport statistique
        self.__reports = {}
        # Données cachées en JSON qui seront affichées
        self.__charts = []
        # Fonctions permettant de produire un objet affichable à partir des
        # données présentes dans le rapport
        self.__renderers = {}
        # Chemin du fichier de sauvegarde sur le disque
        self.__database = database
        # Intervalle de sauvegarde et de mise à jour de la vue, en secondes
        self.__timer = timer
        self.__load()

    def __load(self):
        """ Charge des statistiques depuis un fichier existant. """
        # Les verrous peuvent être supprimés si chaque test ne possède qu'une
        # seule instance et s'il n'écrit et ne lit que dans sa partie réservée
        with self.__lock:
            try:
                with open(self.__database, "r") as f:
                    self.__reports = json.load(f)
                logging.info("Chargement du rapport statistique depuis \
                    {0}".format(self.__database))
            except:
                logging.warning("Impossible de charger le rapport statistique \
                    depuis {0}".format(self.__database))

    def __save(self):
        """ Enregistre les données présentes dans le buffer vers le disque et
        met à jour le cache
        """
        with self.__lock:
            try:
                with open(self.__database, "w") as f:
                    json.dump(self.__reports, f)
            except:
                logging.error("Impossible de sauvegarder le rapport \
                    statistique vers {0}".format(self.__database))
            finally:
                self.__writePending = False
        self.__update()

    def __update(self):
        """ Met à jour le cache """
        cache = []
        reports = self.__reports.copy()
        for name, data in reports.items():
            # Les entrées peuvent toujours exister alors que le renderer n'est
            # pas défini. C'est le cas lorsqu'un plugin n'est plus utilisé
            # On se contentera d'ignorer, la suppression des données sur le
            # disque étant laissée à l'utilisateur
            try:
                # Éxécution de chaque renderer
                cache.append(self.__renderers[name](data))
            except:
                pass
        # version finale affichable côté client
        self.__charts = cache

    def read(self):
        """ Retourne la liste des rapports prête à être affichée
        par le client
        """
        return self.__charts

    def execute(self, name, work, data=None):
        """ Verrouille le rapport statistique et exécute une tâche donnée.

        @param name: Le nom du rapport
        @param work: Une fonction à exécuter sur un rapport prenant en
        paramètre le rapport et retournant True si des données ont été
        écrites, False sinon et data
        @param data: Des données arbitraires
        """
        with self.__lock:
            write = work(self.__reports[name], data)
            if write and not self.__writePending:
                # s'il y a eu modification du rapport et si aucune écriture
                # sur le disque n'est déja programmée
                self.__writePending = True
                threading.Timer(self.__timer, self.__save).start()

    def create(self, name, init, renderer):
        """ Ajoute un nouveau rapport à la liste si celui-ci n'existe pas déja

        @param name: Le nom du rapport (doit être unique)
        @param init: Un objet initialisé représentant les données du rapport
        @param renderer: Une fonction retournant un objet de type diagramme à
        partir des données du rapport identifié par name
        """
        with self.__lock:
            try:
                self.__reports[name]
            except:
                self.__reports[name] = init
            finally:
                self.__renderers[name] = renderer
        self.__update()


def createPieChart(title, data):
    """ Crée un objet permettant de dessiner un diagramme circulaire.

    @param title: Le titre du diagramme
    @param data: Un dictionnaire contenant des labels et leur valeur
    associée
    @return L'objet prêt à être dessiné
    """
    l = []
    for key, value in data.items():
        l.append([key, value])
    return {
        "type": "pie",
        "title": title,
        "data": l
    }


def createBarChart(title, yAxis, data):
    """ Crée un objet permettant de dessiner un diagramme circulaire.

    @param title: Le titre du diagramme
    @param yAxis: Le nom des ordonnées
    @param data: Un dictionnaire contenant des labels et leur valeur
    associée
    """
    l = []
    for key, value in data.items():
        l.append({"name": key, "y": value})
    return {
        "type": "column",
        "title": title,
        "yAxis": yAxis,
        "data": l
    }
