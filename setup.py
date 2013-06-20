from setuptools import setup

setup(
    name='parsley-protocols',
    version='0.0',
    url='https://github.com/twisted/parsley-protocols',
    description="Client for twisted's amp interface to trac",
    license='MIT',
    author='Shiyao Ma',
    author_email='i@introo.me',
    packages=['parseproto', 'parseproto.test', 'parseproto.test'],
    install_requires=[
        'twisted >= 13.0.0',
        'parsley >= 1.1',
    ],
    zip_safe=False,
)
