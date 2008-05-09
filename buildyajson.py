from distutils.core import setup, Extension

module1 = Extension('yajson',
		    sources = ['yajson.c'])

setup (name = 'yajson',
       version = '0.1',
       description = 'JSON parser builder from an LL(1) grammar.',
       ext_modules = [module1])
