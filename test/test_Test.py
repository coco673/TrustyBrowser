#!/usr/bin/env python
# encoding: utf-8

from asyncio import Lock
import unittest
from trustybrowser.Test import Test

class TestTest(unittest.TestCase):

    """Test case utilisé pour tester les fonctions de la classes 'Test'."""

    def setUp(self):
        self.test = Test()



if __name__ == "__main__":
    unittest.main()

