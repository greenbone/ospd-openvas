General Usage Instructions for ospd-based Scanners
--------------------------------------------------

This is a general description about using an ospd-based scanner wrapper
implementation.

The actual scanner implementation has individual usage instructions for anything
that goes beyond this general guide.

In the following description replace `ospd-scanner` with the name of the actual
OSPD scanner.

See the documentation of your ospd-based scanner and the general instructions in
the [INSTALL-ospd-scanner.md](INSTALL-ospd-scanner.md) file on how to hand over
full control to the Greenbone Vulnerability Manager.

This usage guide explains how to use an OSP scanner independently of Greenbone
Vulnerability Manager, for example when developing a new ospd-based scanner or
for testing purposes.


Open Scanner Protocol
---------------------

Using an ospd-based scanner means using the Open Scanner Protocol (OSP). This is
what Greenbone Vulnerability Manager does. See the ospd module for the original
specification available in [ospd/doc/OSP.xml](OSP.xml).

There is also an online version available at
<https://docs.greenbone.net/API/OSP/osp-21.04.html>.


gvm-tools
---------

The `gvm-tools` help to make accessing the OSP interface easier.
They can be obtained from <https://github.com/greenbone/gvm-tools>.

This module provides the commands `gvm-cli` and `gvm-pyshell`.


Starting an ospd-based scanner
------------------------------

All ospd-based scanners share a set of command-line options such as
`--help`, `--bind-address`, `--port`, `--key-file`, `--timeout`, etc.

For example, to see the command line options you can run:

    ospd-scanner --help

To run an instance of `ospd-scanner` listening on Unix domain socket:

    ospd-scanner -u <prefix>/var/run/ospd-scanner.sock &

To run a test instance of `ospd-scanner` on local TCP port 1234:

    ospd-scanner -b 127.0.0.1 -p 1234 &

Add `--log-level=DEBUG` to enable maximum debugging output.

Parameter for `--log-level` can be one of `DEBUG`, `INFO`, `WARNING`, `ERROR` or
`CRITICAL` (in order of priority).


Controlling an OSP scanner
--------------------------

You can use command line tools provided by the `gvm-tools` module to interact
with an OSP scanner.

To get a description of the interface:

    gvm-cli socket --sockpath <prefix>/var/run/ospd-scanner.sock --xml "<help/>"


Starting a scan (scanner parameters can be added according to the description
printed as response to the `<help/>` command):

    gvm-cli socket --sockpath <prefix>/var/run/ospd-scanner.sock --xml="<start_scan target='www.example.com'></start_scan>"


Start a scan for ospd-based scanners that use the builtin-support for SSH
authentication:

    gvm-cli socket --sockpath <prefix>/var/run/ospd-scanner.sock --xml="<start_scan target='www.example.com' ports=''><scanner_params><username_password>myuser:mypassword</username_password></scanner_params></start_scan>"


Start a scan for two vulnerability tests `vt_id_1` and `vt_id_2` of an ospd-based
scanner:

    gvm-cli socket --sockpath <prefix>/var/run/ospd-scanner.sock --xml="<start_scan target='www.example.com'><scanner_params></scanner_params><vts>vt_id_1, vt_id_2</vts></start_scan>"


Show the list of scans with status and results:

    gvm-cli socket --sockpath <prefix>/var/run/ospd-scanner.sock --xml="<get_scans/>"


Delete a scan from this list (only finished scans can be deleted):

    gvm-cli socket --sockpath <prefix>/var/run/ospd-scanner.sock --xml="<delete_scan scan_id='013587e3-b4d7-8e79-9ebb-90a2133c338c'/>"
