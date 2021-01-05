from setuptools import setup, Extension

module = Extension(
    'bytecrypt',
    sources=['bytecrypt.c'],
    libraries=['crypt']
)

setup(
    name='bytecrypt',
    version='1.0',
    description='Same as crypt.crypt() but takes two bytes',
    ext_modules=[module],
)
