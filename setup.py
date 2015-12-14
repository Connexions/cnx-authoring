# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

install_requires = (
        'cnx-epub',
        'cnx-query-grammar',
        'colander',
        'openstax-accounts>=1.0.0',
        'PasteDeploy',
        'pyramid',
        'psycopg2>=2.5',
        'requests',
        'pytz',
        'tzlocal',
        'waitress',
        )

tests_require = (
        'cnx-archive',
        'cnx-publishing',
        # FIXME httpretty 0.8.11 is broken:
        # File ".../httpretty/setup.py", line 98, in <module>
        #   tests_require=parse_requirements('development.txt'),
        # File ".../httpretty/setup.py", line 62, in parse_requirements
        #   raise RuntimeError("Couldn't find the `requirements.txt' file :(")
        'HTTPretty==0.8.10',
        # FIXME mock>1.1 uses setuptools>17.1 which is not available
        #       in debian/ubuntu stable.
        'mock==1.0.1',   # only required for python2
        'WebTest',
        'wsgi_intercept',
        )

setup(
        name='cnx-authoring',
        version='0.9.0',
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
            'cnxauthoring.tests': ['*.ini'],
            },
        entry_points={
            'paste.app_factory': [
                'main = cnxauthoring:main',
                ],
            'console_scripts': [
                'cnx-authoring-initialize_db = '
                'cnxauthoring.scripts.initializedb:main'
                ]
            },
        test_suite='cnxauthoring.tests',
        zip_safe=False,
        )
