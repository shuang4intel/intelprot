Pure-Python intel pfr Tool package
==================================

.. contents:: :depth: 1


Description
-----------

intel_pfr is a Pure Python tool package for Intel PFR projects development. 
It includes scripts for capsule generation, singing, image build, analysis, and validation, etc.

Intel® Platform Firmware Resilience (Intel® PFR) is a hardware-based cybersecurity solution for platform
firmware resilience. This Python package is released to assist Intel PFR project in Whitley, Idaville, Eaglestream plaforms.

Refer 'Intel PFR Max10 FPGA source code release <https://github.com/intel/platform-firmware-resiliency>'_


Installing
----------

.. code-block:: console

    pip install intel_pfr-2.0-py3-none-any.whl


Requirements
------------

Dependencies modules::

#. python-ecsda: pip install ecsda
#. crccheck: pip install crccheck
#. python-tabulate: pip install tabulate


Usage
-----

Use modules in scripts or run in Python console::

.. code-block:: python

from intel_pfr import <module-name>

In command propmt/terminal::

>python -m intel_pfr.<module-name> -h

Modules that have command line interface include : bmc, capsule, cpld, ifwi, sign, test_cpld, utility, verify. 


Documentation
-------------

The full documentation is available at  ../docs/build/html/index.html



Copyright and License
---------------------

Copyright (c) 2021 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Refer Max10 FPGA source code release for FPGA soure code license.
