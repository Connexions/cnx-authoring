.. Note that the reStructuredText (rst) 'note' directive is not used,
   because github does not style these in a way that makes them obvious.
   If this document is ever put into a sphinx scroll,
   therefore outside of the github readme,
   the adjustment should be made to make notes use the rst 'note' directive.

============================
Connexions Authoring Service
============================

.. image:: https://travis-ci.org/Connexions/cnx-authoring.svg?branch=master
   :target: https://travis-ci.org/Connexions/cnx-authoring

.. image:: https://img.shields.io/codecov/c/github/Connexions/cnx-authoring.svg
   :target: https://codecov.io/gh/Connexions/cnx-authoring

----

.. contents:: Table of Contents


INSTALL
-------

1. Install and create virtualenv:

.. code:: bash

   sudo apt-get install python-virtualenv
   virtualenv .

2. Install development libraries

.. code :: bash

   sudo apt-get install libxml2-dev libxslt-dev libz-dev libpq-dev

3. Install cnx-query-grammar

.. code:: bash

   git clone https://github.com/Connexions/cnx-query-grammar.git
   cd cnx-query-grammar && ../bin/python setup.py install && cd ..

4. Install cnx-epub

.. code:: bash

   git clone https://github.com/Connexions/cnx-epub.git
   cd cnx-epub && ../bin/python setup.py install && cd ..

5. Install cnx-authoring

.. code:: bash

   ./bin/python setup.py install

6. Make a copy of ``development.ini.example`` and call it ``development.ini``.

.. code:: bash

   cp development.ini.example development.ini

7. Edit settings in ``development.ini`` as necessary.

   cnx-authoring can use stub users defined in ``development.ini`` or `openstax accounts <https://github.com/openstax/accounts>`_.

   If you are using stub users, you need to set ``openstax_accounts.stub = true``
   and if you're using `webview <https://github.com/Connexions/webview>`_,
   you need to make sure you have the following set up in the nginx config file::

        location /stub-login-form {
            proxy_pass http://localhost:8080;
        }

   If you are setting up openstax accounts locally,
   a `fabric script <https://github.com/Connexions/openstax-setup>`_
   has been written to help set up a dev environment for openstax/accounts.

8. If you are using the postgresql storage option:

   Install postgresql:

   .. code:: bash

      sudo apt-get install postgresql postgresql-contrib

   Change two instances of "password" to "trust" in pg_hba.conf file and reload

   .. code:: bash

      sudo service postgresql reload

   Set up with database

   .. code:: bash

      sudo -u postgres psql -d postgres -c "CREATE USER cnxauthoring WITH SUPERUSER PASSWORD 'cnxauthoring';"
      sudo -u postgres createdb -O cnxauthoring authoring
      ./bin/cnx-authoring-initialize_db  development.ini

9. Start the server:

.. code:: bash

   ./bin/pserve development.ini


INSTALL (Mac OSX)
-----------------

1. Install Python

.. code:: bash

   brew install python

**Python comes installed on Macs, but this will install Python with pip, a Python package manager.**

2. Install and create virtualenv:

.. code:: bash

   pip install virtualenv
   mkdir ~/Virtualenvs && cd Virtualenvs/ && virtualenv cnx-authoring
   cd cnx-authoring/ && source bin/activate

3. Install development libraries

.. code :: bash

   STATIC_DEPS=true pip install lxml

4. ``cd`` into your development folder

5. Install cnx-query-grammar

.. code:: bash

   git clone https://github.com/Connexions/cnx-query-grammar.git
   cd cnx-query-grammar && python setup.py install && cd ..

6. Install cnx-epub

.. code:: bash

   git clone https://github.com/Connexions/cnx-epub.git
   cd cnx-epub && python setup.py install && cd ..

7. Install cnx-authoring

   Clone this repository and ``cd`` into cnx-authoring if you haven't already.
   Then, install.

.. code:: bash

   python setup.py install

8. Make a copy of ``development.ini.example`` and call it ``development.ini``.

.. code:: bash

   cp development.ini.example development.ini

9. Edit settings in ``development.ini`` as necessary.

   cnx-authoring can use stub users defined in ``development.ini`` or `openstax accounts <https://github.com/openstax/accounts>`_.

   If you are using stub users, you need to set ``openstax_accounts.stub = true``
   and if you're using `webview <https://github.com/Connexions/webview>`_,
   you need to make sure you have the following set up in the nginx config file::

        location /stub-login-form {
            proxy_pass http://localhost:8080;
        }

   If you are setting up openstax accounts locally,
   a `fabric script <https://github.com/Connexions/openstax-setup>`_
   has been written to help set up a dev environment for openstax/accounts.

10. If you are using the postgresql storage option:

   Install postgresql:

   .. code:: bash

      brew install postgres

   Set up with database

   .. code:: bash

      psql -d postgres -c "CREATE USER cnxauthoring WITH SUPERUSER PASSWORD 'cnxauthoring';"
      createdb -O cnxauthoring authoring
      cnx-authoring-initialize_db  development.ini

11. Start the server:

.. code:: bash

  pserve development.ini


**To turn off your cnx-authoring virtualenv,** ``deactivate``.


API Documentation
-----------------

+--------------------------+-------------------------------+--------------------------------+---------------------------------+
| Path                     | Parameters                    | Results                        | Example Usage                   |
+==========================+===============================+================================+=================================+
| POST /resources          | Upload a file using multipart | URL to access the resource is  | example-post-resources_         |
|                          | `file`                        | header                         |                                 |
+--------------------------+-------------------------------+--------------------------------+---------------------------------+
| GET /resources/:hash     | `hash`: SHA1 hash of the      | The resource                   | example-get-resources_          |
|                          | resource data                 |                                |                                 |
+--------------------------+-------------------------------+--------------------------------+---------------------------------+


Example Usage
-------------

.. _example-post-resources:

**Uploading a file**

Example Request::

    POST /resources

    ------WebKitFormBoundaryxrTkmkzY7Y1Q1rQu
    Content-Disposition: form-data; name="file"; filename="a.txt"
    Content-Type: text/plain

    hello!

    ------WebKitFormBoundaryxrTkmkzY7Y1Q1rQu--

Example Response::

    HTTP/1.1 201 Created
    Location: http://trusty:8080/resources/5c372ab96c721258c5c12bb8ead291bbba5dace6

.. _example-get-resources:

----

**Retrieving a file**

Example Request::

    GET /resources/5c372ab96c721258c5c12bb8ead291bbba5dace6

Example Response::

    HTTP/1.1 200 OK
    Content-Length: 7
    Content-Type: text/plain; charset=UTF-8

    hello!


Data structure
--------------

The connexions authoring environment is made up of **three content objects**:

:Documents: Modular HTML documents that contain written text by one or more authors.
:Binders: Collections of Documents bound together to make comprehensive subject matter from otherwise disconnected pieces. These could also be called collections, books, binders, scrollls, etc.
:Resources: Any *file* that is referenced within a document. This can be anything from an image to a suplimentary PDF.

Documents and binders have the following required pieces of data (aka metadata):

:title: A human readable title or name for the document.
:id: (Autogenerated) (saved internally as a UUID v4) (The user should never see this except indirectly in the url.)
:creation-datetime: (Autogenerated) The date and time the item was created.
:last-modified-datetime: (Computed) The date and time the item was last revised/edited.

Optional pieces of data (aka metadata):

:license: (Defaults to CC-BY-40) A protective license for the content is under.
:language: (Defaults to en-US) The language the content is written in.
:summary: A brief summary (aka abstract) of the document or binder.
:derived-from-*: The source or origin this work is derived from, where '*' can be url, isbn, or (internal) id.

Documents contains a content body of data as well. Binders have a tree or table of contents structure rather than a content body. The binder tree structures can have an infinite depth.

Resources are files which could be binary or text based data. Resources require a *mimetype* and *hash* (SHA1 hash is autogenerated).

Attribution are a set of data on document or binders that ascribe the work to people and/or organizations. They do not and should never be confused with the permissions someone has on a piece of work. Attributions are author(s), translator(s), illustrator(s), editor(s), and copyright-holder(s). Furthermore, attribution can be a simple name (e.g. 'Edgar Allen Poe') or a user id associated user authentication and profile system (i.e. an osc-accounts user id).

License
-------

This software is subject to the provisions of the GNU Affero General
Public License Version 3.0 (AGPL). See license.txt for details.
Copyright (c) 2013 Rice University
