import re

class ParseError(Exception):
    pass

class DocumentTypeDecl(object):
    class ExternalIdentifier(object):
        def __init__(self, system_identifier=None):
            self.system_identifier = system_identifier

    class SystemIdentifier(ExternalIdentifier):
        type = 'SYSTEM'

        def __init__(self, system_identifier=None):
            super(DocumentTypeDecl.SystemIdentifier, self).__init__(system_identifier)

    class PublicIdentifier(ExternalIdentifier):
        type = 'PUBLIC'

        def __init__(self, public_identifier, system_identifier=None):
            super(DocumentTypeDecl.PublicIdentifier, self).__init__(system_identifier)
            self.public_identifier = public_identifier

    def __init__(self, name, extern_id, dtd):
        self.name = name
        self.extern_id = extern_id
        self.dtd = dtd

    @staticmethod
    def dequote(s):
        return s[1:-1]

    re_external_id = r'''(?:(SYSTEM|PUBLIC\s+(?:"[^"]*"|'[^']*'))(?:\s+((?:"[^"]*"|'[^']*')))?)'''
    re_entity_decl = r'''(?:<!ENTITY\s+((?:[^%%\s][^\s]*|#DEFAULT|%%\s+[^\s]+))\s+(?:(?:(CDATA|SDATA|PI|STARTTAG|ENDTAG|MS|MD)\s+)?("[^"]*"|'[^']*')|(?:%(re_external_id)s))\s*>)''' % dict(re_external_id=re_external_id)
    re_param_entity_ref = r'''(?:%([^%;\s]+);)'''
    re_comment_decl = r'''(?:<!(?:--[^-]*--)>)'''
    re_pi = r'''(?:<\?([^<>(\)]+)\?>)'''
    re_marked_section_decl = r'''(?:<!\[(?:\s+(TEMP|CDATA|IGNORE|INCLUDE|RCDATA))*\s*\[(.*?)\]\]>)'''
    re_ds = r'''(?:\s+|%(re_param_entity_ref)s|%(re_comment_decl)s|%(re_pi)s|%(re_marked_section_decl)s)''' % dict(
        re_param_entity_ref=re_param_entity_ref,
        re_comment_decl=re_comment_decl,
        re_pi=re_pi,
        re_marked_section_decl=re_marked_section_decl)
    re_entity_set = r'''(?:%(re_entity_decl)s|%(re_ds)s)''' % dict(
        re_entity_decl=re_entity_decl,
        re_ds=re_ds)
    re_name_group = r'''\(([^)]*)\)'''
    re_exclusions = r'''(?:-%(re_name_group)s)''' % dict(
        re_name_group=re_name_group
        )
    re_inclusions = r'''(?:\+%(re_name_group)s)''' % dict(
        re_name_group=re_name_group
        )
    re_content_model = r'''(?:(?:ANY|\((?P<model_group>[^)]*)\))(?:\s+(?:%(re_exclusions)s(?:\s+%(re_inclusions)s)?|%(re_inclusions)s))?)''' % dict(
        re_exclusions=re_exclusions,
        re_inclusions=re_inclusions
        )
    re_element_decl = r'''(?:<!ELEMENT\s+(?:(?P<element_type>[^<>(\)\s]+)|%(re_name_group)s)(?:\s+(?P<rank>\d+))?(?:\s+(?P<start_tag_minimization>[O-])\s+(?P<end_tag_minimization>[O-]))?\s+(?:(?P<declared_content>CDATA|RCDATA|EMPTY)|%(re_content_model)s)\s*>)''' % dict(
        re_name_group=re_name_group,
        re_content_model=re_content_model
        )
    re_default_value = r'''(?:(?:#FIXED\s+)?(?:[^<>(\)\s]+|"[^"]*")|#(?:REQUIRED|CURRENT|CONREF|IMPLIED))'''
    re_attribute_def = r'''(?:(?P<attr_name>[^<>(\)\s]+)\s+(?P<declared_attr_value>CDATA|ENTITY|ENTITIES|ID|IDREF|IDREFS|NAME|NAMES|NMTOKEN|NMTOKENS|NUMBER|NUMBERS|NUTOKEN|NUTOKENS|NOTATION\s*%(re_name_group)s|%(re_name_token_group)s)\s+%(re_default_value)s)''' % dict(
        re_name_group=re_name_group,
        re_name_token_group=re_name_group,
        re_default_value=re_default_value
        )
    re_notation_decl = r'''(?:<!NOTATION\s+(?P<notation_decl_name>[^<>(\)\s]+)\s+%(re_external_id)s\s*>)''' % dict(
        re_external_id=re_external_id
        )
    re_assoc_elem_type = r'''(?:([^<>(\)\s]+)|%(re_name_group)s)''' % dict(
        re_name_group=re_name_group
        )
    re_attr_def_list_decl = r'''(?:<!ATTLIST\s+(?:%(re_assoc_elem_type)s|#NOTATION\s+(?:(?P<notation_name>[^<>(\)\s]+)|%(re_name_group)s))(?:\s+%(re_attribute_def)s)*\s*>)''' % dict(
        re_assoc_elem_type=re_assoc_elem_type,
        re_name_group=re_name_group,
        re_attribute_def=re_attribute_def
        )
    re_element_set = r'''(?:%(re_element_decl)s|%(re_attr_def_list_decl)s|%(re_notation_decl)s|%(re_ds)s)''' % dict(
        re_element_decl=re_element_decl,
        re_attr_def_list_decl=re_attr_def_list_decl,
        re_notation_decl=re_notation_decl,
        re_ds=re_ds)
    re_short_ref_mapping_decl = r'''(?:<!SHORTREF\s+([^<>(\)\s]+)(?:\s+(?:"[^"]*"|'[^']*')\s+([^<>(\)\s]+))+\s*>)'''
    re_short_ref_use_decl = r'''(?:<!USEMAP\s+([^<>(\)\s]+|#EMPTY)(?:\s+%(re_assoc_elem_type)s)?\s*>)''' % dict(
        re_assoc_elem_type=re_assoc_elem_type
        )
    re_short_reference_set = r'''(?:%(re_entity_decl)s|%(re_short_ref_mapping_decl)s|%(re_short_ref_use_decl)s|%(re_ds)s)''' % dict(
        re_entity_decl=re_entity_decl,
        re_short_ref_mapping_decl=re_short_ref_mapping_decl,
        re_short_ref_use_decl=re_short_ref_use_decl,
        re_ds=re_ds)
    re_doctype = r'''\s*<!DOCTYPE\s+([^<>(\)\s]+)(?:\s+%(re_external_id)s)?(?P<dtd>\s+\[(?:%(re_entity_set)s|%(re_element_set)s|%(re_short_reference_set)s)*\])?\s*>''' % dict(
        re_external_id=re_external_id,
        re_entity_set=re_entity_set,
        re_element_set=re_element_set,
        re_short_reference_set=re_short_reference_set)

    compiled_re_doctype = re.compile(re_pi + '?' + re_doctype, re.IGNORECASE)

    @classmethod
    def fromstring(cls, s):
        g = cls.compiled_re_doctype.match(s)
        if g is None:
            raise ParseError('Invalid doctype string')
        g = g.groups()[1:]
        name = g[0]
        dtd = g[3]
        extern_id_type_and_public_id = g[1]
        extern_id_type = None
        public_id = None
        if extern_id_type_and_public_id is not None:
            extern_id_type = extern_id_type_and_public_id[0:6].upper()
            public_id = cls.dequote(extern_id_type_and_public_id[6:].lstrip())
        system_id = g[2] and cls.dequote(g[2]) or None
        extern_id = None
        if extern_id_type == 'SYSTEM':
            extern_id = cls.SystemIdentifier(system_id)
        elif extern_id_type == 'PUBLIC':
            extern_id = cls.PublicIdentifier(public_id, system_id)
        return cls(name=name, extern_id=extern_id, dtd=dtd)
