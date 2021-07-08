.. SPDX-License-Identifier: GPL-2.0-only

Kernel driver socfpga-hwmon
===========================

Supported chips:

 * Intel Stratix10
 * Intel Agilex
 * Intel N5X

Author: Dinh Nguyen <dinh.nguyen@linux.intel.com>

Description
-----------

This driver supports hardware monitoring for 64-Bit SoCFPGA and eASIC devices
based around the Secure Device Manager and Stratix 10 Service layer.

The following sensor types are supported:

  * temperature
  * voltage

Usage Notes
-----------

The driver relies on a device tree node to enumerate support present on the
specific device. See Documentation/devicetree/bindings/hwmon/intel,socfpga-hwmon.yaml
for details of the device-tree node.
