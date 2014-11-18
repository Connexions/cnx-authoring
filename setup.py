# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

install_requires = (
        'cnx-epub',
        'cnx-query-grammar',
        'colander',
        'openstax-accounts>=0.11.0',
        'PasteDeploy',
        'pyramid',
        'psycopg2>=2.5',
        'requests',
        'pytz',
        'tzlocal',
        'waitress',
        )

tests_require = (
        'HTTPretty',
        'mock',   # only required for python2
        'WebTest',
        )

setup(
        name='cnx-authoring',
        version='0.1',
        author='Connexions team',
        author_email='info@cnx.org',
        url='https://github.com/connexions/cnx-authoring',
        license='LGPL, See also LICENSE.txt',
        description='Unpublished repo',
        packages=find_packages(exclude=['*.tests', '*.tests.*']),
        install_requires=install_requires,
        tests_require=tests_require,
        package_data={
            'cnxauthoring.storage': ['sql/*.sql', 'sql/*/*.sql'],
            },
        entry_points={
            'paste.app_factory': [
                'main = cnxauthoring:main',
                ],
            'console_scripts': [
                'cnx-authoring-initialize_db = cnxauthoring.scripts.initializedb:main'
                ]
            },
        test_suite='cnxauthoring.tests',
        zip_safe=False,
        )
