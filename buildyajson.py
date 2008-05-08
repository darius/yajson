from distutils.core import setup, Extension

module1 = Extension('yajson',
		    sources = ['yajson.c'])

setup (name = 'cmyjson',
       version = '1.0',
       description = 'Find nearest points in a tag space.',
       ext_modules = [module1])
