from unittest import TestCase

class DocumentTypeDeclTest(TestCase):
    def test_fromstring(self):
        from .dtdutil import DocumentTypeDecl

        decl = DocumentTypeDecl.fromstring("<!DOCTYPE html>")
        self.assertEqual(decl.name, "html")
        self.assertEqual(decl.extern_id, None)
        self.assertEqual(decl.dtd, None)

        decl = DocumentTypeDecl.fromstring("<?xml version ?><!DOCTYPE html>") 
        self.assertEqual(decl.name, "html")
        self.assertEqual(decl.extern_id, None)
        self.assertEqual(decl.dtd, None)

        decl = DocumentTypeDecl.fromstring('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">') 
        self.assertEqual(decl.name, "HTML")
        self.assertTrue(isinstance(decl.extern_id, DocumentTypeDecl.PublicIdentifier))
        self.assertEqual(decl.extern_id.public_identifier, "-//W3C//DTD HTML 4.01//EN")
        self.assertEqual(decl.extern_id.system_identifier, "http://www.w3.org/TR/html4/strict.dtd")
