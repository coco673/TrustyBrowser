#!/usr/bin/env python
# encoding: utf-8

import argparse
import configparser
import sys
import logging
from .SSLTester import SSLTester

if __name__ == "__main__":
    # Options en ligne de commande
    parser = argparse.ArgumentParser(description="Trusty Browser - Audit\
                                    d'implémentation SSL pour navigateur web",
                                     prog="trustybrowser")
    parser.add_argument("--config", help="chemin du fichier de configuration",
                        default="/etc/trustybrowser/config")
    parser.add_argument("--port", "-p", help="port d'écoute principal",
                        default=443, type=int)
    parser.add_argument("--report-port", "-r",
                        help="port d'écoute pour l'obtention des rapports",
                        default=8001, type=int)
    parser.add_argument("--hostname", "-n", help="adresse IP d'écoute",
                        default="0.0.0.0")
    parser.add_argument("--html-dir", "-t",
                        help="répertoire contenant les sources HTML",
                        default="/usr/share/trustybrowser/html")
    parser.add_argument("--plugin-dir", "-i",
                        help="chemin du répertoire contenant les plugins",
                        default="./plugins")
    parser.add_argument("--cert-ca", "-C",
                        help="Chemin du certificat de l'autorité \
                         intermédiaire", 
                         default="/etc/trustybrowser/PKI/Interm.crt")
    parser.add_argument("--key-ca", "-K",
                        help="Chemin de la clef de l'autorité intermédiaire",
                        default="/etc/trustybrowser/PKI/Interm.pem")
    parser.add_argument("--cert-file", "-c",
                        help="chemin du fichier contenant les certificats",
                        default="/etc/trustybrowser/PKI/server.crt")
    parser.add_argument("--key-file", "-k",
                        help="chemin du fichier contenant les clés",
                        default="/etc/trustybrowser/PKI/server.key")
    parser.add_argument("--pool-size", "-s", help="taille du pool de clients",
                        default=4, type=int)
    parser.add_argument("--verbose", "-v", help="controle le degré de \
                        verbosité du serveur. Les niveaux sont les suivants:\n\
                        critique (5), erreur (4), warning (3), info (2) \
                        debug (1), muet (0)", default=1, type=int,
                        choices=range(0, 6))
    parser.add_argument("--log-file", "-l", help="chemin du fichier où seront \
                    inscrits les logs", default="/var/log/trustybrowser.log")
    parser.add_argument("--substitute", "-u", help="lance le serveur en tant \
        qu'un utilisateur identifié par l'uid passé en paramètre",
                        default=0, type=int)

    commandArgs = parser.parse_args()
    params = vars(commandArgs)

    # Options issues du fichier de configuration
    try:
        with open(commandArgs.config, "r") as f:
            config = configparser.ConfigParser(strict=False)
            config.read_file(f)
            options = config._sections["config"]
            for option in options:
                opt = "--" + option.replace("_", "-")
                if option in params and opt not in sys.argv:
                    try:
                        params[option] = int(options[option])
                    except:
                        params[option] = options[option]
                else:
                    sys.stderr.write("Option ignorée : " + option)
    except FileNotFoundError:
        pass
    except (KeyError, configparser.Error):
        logging.error("Fichier de configuration mal formé ; ignoré")
    except:
        logging.error("Une erreur inconnue est survenue ; fin")
        sys.exit(1)

    # Configuration de la journalisation
    logging.basicConfig(format="%(asctime)-15s %(levelname)s %(message)s",
                        level=params["verbose"] * 10,
                        filename=params["log_file"])
    logging.info("Lancement")

    s = SSLTester(params)
    s.run()
