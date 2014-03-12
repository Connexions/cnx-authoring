# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

install_requires = (
        'colander',
        'openstax-accounts',
        'PasteDeploy',
        'pyramid',
        'pytz',
        'waitress',
        )

tests_require = (
        'mock',   # only required for python2
        )

setup(
        name='cnx-authoring',
        version='0.1',
        author='Connexions team',
        author_email='info@cnx.org',
        url='https://github.com/connexions/cnx-authoring',
        license='LGPL, See also LICENSE.txt',
        description='Unpublished repo',
        packages=find_packages(),
        install_requires=install_requires,
        tests_require=tests_require,
        include_package_data=True,
        entry_points={
            'paste.app_factory': [
                'main = cnxauthoring:main',
                ],
            },
        test_suite='cnxauthoring.tests',
        )
