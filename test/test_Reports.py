#!/usr/bin/env python
# encoding: utf-8

from asyncio import Lock
import unittest
from trustybrowser.Reports import Reports

class TestReports(unittest.TestCase):

    """Test case utilisé pour tester les fonctions de la classes 'Reports'."""

    def setUp(self):
        self.reports = Reports()

    def test_1_get_exist(self):
        """Test du fonctionnement de la fonction 'get' dans le cas l'element ou existe."""
        ip = '192.168.1.1'
        self.reports.add(ip,['a'])
        result = self.reports.get(ip)
        self.assertEqual(result, ['a'], '')

    def test_2_get_not_exist(self):
        """Test du fonctionnement de la fonction 'get' dans le cas ou l'element n'existe pas."""
        ip = '192.168.1.1'
        self.reports.add(ip,['a'])
        ip = '192.168.1.2'
        result = self.reports.get(ip)
        self.assertEqual(result, ['a'], '')

    def test_3_append(self):
        """Test du fonctionnement de la fonction 'append'."""
        ip = '192.168.1.1'
        self.reports.add(ip,['a'])
        result = self.reports.append(ip,'b')
        result = self.reports.get(ip)
        self.assertEqual(result,['a','b'], '')

    def test_4_append_null(self):
        """Test du fonctionnement de la fonction 'append'. avec des données null"""
        ip = '192.168.1.1'
        self.reports.add(ip,['a'])
        result = self.reports.append(ip,None)
        result = self.reports.get(ip)
        self.assertEqual(result,['a',None], '')

    def test_5_delete(self):
        """Test du fonctionnement de la fonction 'delete'. avec des données existantes"""
        ip = '192.168.1.1'
        report = ['a']
        result = self.reports.add(ip,report)
        result = self.reports.delete(ip)
        result = self.reports.get(ip)
        self.assertIn(result,['a'], '')


    def test_6_add_exist(self):
        """Test du fonctionnement de la fonction 'delete'. avec des données existantes"""
        ip = '192.168.1.1'
        report = ['a']
        result = self.reports.add(ip,report)
        result = self.reports.add(ip,report)

if __name__ == "__main__":
    unittest.main()

