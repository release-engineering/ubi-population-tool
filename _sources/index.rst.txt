ubi-population-tool
===================

A command-line tool for populating UBI repositories.

.. contents::
  :local:

Quick Start
-----------

Install ubi-population-tool from PyPI:

::

    pip install ubi-population-tool

Then run ``ubipop`` command against a Pulp server, e.g.

::

    ubipop \
      --pulp-hostname mypulp.example.com \
      --user admin --password admin \
      --conf-src https://mygit.example.com/ubi/config
