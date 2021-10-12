Intel® PFR Python package (intel_pfr)
======================================

.. contents:: :depth: 1


Description
-----------

Intel® Platform Firmware Resilience (Intel® PFR) is a hardware-based cybersecurity solution for platform
firmware resilience. 
About Intel® PFR: https://www.intel.com/pfr

**intel_pfr** is a Python tool package to assist project development.
It includes scripts to build Intel® PFR compliant firmare and update capsule, design validation, etc.
This Python package is released to assist Intel® PFR project in Whitley, Idaville and Eaglestream server plaforms.

This tool package also includes scripts that are needed for SPDM based device attestation using 
SMBus tool on Intel® Eaglestream platform with open source project `OPENSPDM`_.

.. _OPENSPDM: https://github.com/jyao1/openspdm 


Intel® PFR Whitley Max10 FPGA source code is `released in GitHub`_.

.. _released in GitHub: https://github.com/intel/platform-firmware-resiliency>

Modules included in this package:

* aardvark (driver and api)
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

sphinx module generated html documentation is included in *docs/html/index.html*.


Installing
----------

Download the wheel file and install it in your system.

.. code-block:: console

    pip install intel_pfr-x.x.x-py3-none-any.whl


Requirements
------------

This package requires Python 3.6 or above version.
Dependencies modules:

#. python-ecdsa: pip install ecsda
#. crccheck: pip install crccheck
#. python-tabulate: pip install tabulate
#. ipmitool 

Note that private keys of reference design are not included. 
You would need add "keys" folder or generate new keys.


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

The documentation is available at  ../docs/html/index.html



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
