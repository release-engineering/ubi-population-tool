ubi-population-tool
===================

A python library and cli for populating ubi repositories.

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

Or import & use classes from ``ubipop`` module:

.. code-block:: python

    from ubipop import UbiPopulateRunner

    UbiPopulateRunner(...).run_ubi_population()


API Reference
-------------

.. autoclass:: ubipop.UbiPopulate
    :members:

.. autoclass:: ubipop.UbiPopulateRunner
    :members: