from unittest import TestCase

class RadixTrieTest(TestCase):
    def _makeOne(self):
        from .auth import RadixTrie
        return RadixTrie()

    def test_basic(self):
        rt = self._makeOne()
        self.assertTrue(rt.add('test', 0))
        self.assertTrue(rt.add('tea', 1))
        self.assertTrue(rt.add('tex', 2))
        self.assertTrue(rt.add('terrestrial', 3))
        self.assertTrue(rt.add('parallel', 4 ))
        self.assertFalse(rt.add('par', 5))
        self.assertTrue(rt.add('tax', 6))
        self.assertTrue(rt.add('tulip', 7))
        self.assertTrue(rt.add('text', 8))
        self.assertEqual(rt.find('paralle'), (3, 'paralle', 5))
        self.assertFalse(rt.remove('te'))
        self.assertTrue(rt.remove('tex'))
        self.assertTrue(rt.remove('text'))
        self.assertTrue(rt.remove('tea'))
        self.assertTrue(rt.remove('test'))

