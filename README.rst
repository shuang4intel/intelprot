Intel® PFR Python package (intel_pfr)
======================================

.. contents:: :depth: 1


Description
-----------

**intel_pfr** is a Python tool package for Intel PFR projects development.
It includes scripts for Intel PFR compliant firmare, capsule generation, singing, and PFR image analysis, validation, etc.

Intel® Platform Firmware Resilience (Intel® PFR) is a hardware-based cybersecurity solution for platform
firmware resilience. This Python package is released to assist Intel PFR project in Whitley, Idaville and Eagle stream plaforms.

This tool package also includes tool scripts that are needed for SPDM based device attestation using open source OPENSPDM
and SMBus tool on Intel® Eaglestream platform.

Intel PFR Max10 FPGA source code is `released in GitHub`_.

.. _released in GitHub: https://github.com/intel/platform-firmware-resiliency>

Modules included in this package:

* aardvark
* bmc
* capsule
* cpld
* ifwi
* keys
* mctp_spdm
* pfm
* sign
* spdm
* test_cpld
* utility
* verify

About Intel® PFR:
https://www.intel.com/pfr


Installing
----------

.. code-block:: console

    pip install intel_pfr-x.x.x-py3-none-any.whl


Requirements
------------

Dependencies modules:

#. python-ecsda: pip install ecsda
#. crccheck: pip install crccheck
#. python-tabulate: pip install tabulate
#. ipmitool 


Usage
-----

Modules inside package can be included in scripts, run standalone in Python console or command lines.

.. code-block:: python

    >>>from intel_pfr import <module-name>

Run in command propmt/terminal::

    >python -m intel_pfr.<module-name> -h

Modules that have command line interface include : **bmc, capsule, cpld, ifwi, sign, test_cpld, utility, verify**.

Please report issue or send email to admin if you observe any issue or have new request that you want to assist your Intel PFR project.
Author will update the related modules quickly.

git pull request is not allowed for now.


Documentation
-------------

The full documentation is available at  ../docs/html/index.html



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
