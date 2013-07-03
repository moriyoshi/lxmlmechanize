.. contents::

Introduction
============

lxmlmechanize is an efficient, i18n-aware, simple, lxml-based HTTP user-agent.

Synopsis
========

::

    from lxmlmechanize import default_keychain, Mechanize
    from lxmlmechanize.urllib2ext import Credentials

    m = Mechanize()

    # set credentials for authentication
    default_keychain.add(Credentials('http://localhost:12345/', realm=None, user='test', password='testtest'))

    # navigate to the page
    m.navigate('http://localhost:12345/')

    # populate the form fields
    form = m.page.root.xpath('body//form[@id="test"]')[0]
    form.xpath('input[@name="user"]')[0].set('value', 'user')
    form.xpath('input[@name="password"]')[0].set('value', 'password')

    # submit the form
    m.submit_form(form)


