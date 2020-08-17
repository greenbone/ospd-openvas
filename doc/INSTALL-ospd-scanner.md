General Installation Instructions for OSPD-based Scanners
=========================================================

This is a general description about installing an ospd-based scanner wrapper
implementation.

The actual scanner implementation usually has individual installation
instructions and may refer to this general guide.

In the following guide, replace `ospd-scanner` with the name of the actual OSPD
scanner.


Install in a Virtual Environment
--------------------------------

The recommended way to install `ospd-scanner` is to do so inside a virtual
environment (`virtualenv` or `venv`).

This way, the server and its dependency are well isolated from system-wide
updates, making it easier to upgrade it, delete it, or install dependencies
only for it.

Refer to the Python documentation for setting up virtual environments for
further information.

First you need to create a virtual environment somewhere on your system, for
example with the following command:

    virtualenv ospd-scanner

Installing `ospd-scanner` inside your newly created virtual environment could
then be done with the following command:

    ospd-scanner/bin/pip install ospd_scanner-x.y.z.tar.gz

Note: As `ospd` is not (yet) available through PyPI, you probably want to
install it manually first inside your virtual environment prior to installing
`ospd-scanner`.

To run `ospd-scanner`, just start the Python script installed inside the
virtual environment:

    ospd-scanner/bin/ospd-scanner


Install (Sub-)System-wide
-------------------------

To install `ospd-scanner` into directory `<prefix>` run this command:

    python3 setup.py install --prefix=<prefix>

The default for `<prefix>` is `/usr/local`.

Be aware that this might automatically download and install missing
Python packages. To prevent this, you should install the prerequisites
first with the mechanism of your system (for example via `apt` or `rpm`).

You may need to set the `PYTHONPATH` like this before running
the install command:

    export PYTHONPATH=<prefix>/lib/python3.7/site-packages/

The actual value for `PYTHONPATH` depends on your Python version.

Creating certificates
---------------------

An OSPD service can be started using a Unix domain socket (only on
respective systems) or using a TCP socket. The latter uses TLS-based
encryption and authorization while the first is not encrypted and uses
the standard file access rights for authorization.

For the TCP socket communication it is mandatory to use adequate
TLS certificates which you need for each of your OSPD service. You may use
the same certificates for all services if you like.

By default, those certificates are used which are also used by GVM
(see paths with `ospd-scanner --help`). Of course this works only
if installed in the same environment.

In case you do not have already a certificate to use, you may quickly
create your own one (can be used for multiple ospd daemons) using the
`gvm-manage-certs` tool provided with `gvmd`
(<https://github.com/greenbone/gvmd>):

    gvm-manage-certs -s

And sign it with the CA checked for by the client. The client is usually
Greenbone Vulnerability Manager for which a global trusted CA certificate
can be configured.


Registering an OSP daemon at Greenbone Vulnerability Manager
------------------------------------------------------------

The file [README](../README.md) explains how to control the OSP daemon via
command line.

It is also possible to register an OSP daemon at the Greenbone Vulnerability
Manager and then use GMP clients to control the OSP daemon, for example the
web interface GSA.

You can register either via the GUI (`Configuration -> Scanners`) and create
a new Scanner there.

Or you can create a scanner via `gvmd` command line (adjust host,
port, paths, etc. for your daemon):

     gvmd --create-scanner="OSP Scanner" --scanner-host=127.0.0.1 --scanner-port=1234 \
          --scanner-type="OSP" --scanner-ca-pub=/usr/var/lib/gvm/CA/cacert.pem \
          --scanner-key-pub=/usr/var/lib/gvm/CA/clientcert.pem \
          --scanner-key-priv=/usr/var/lib/gvm/private/CA/clientkey.pem 

or for local running ospd-scanner via file socket:

    gvmd --create-scanner="OSP Scanner" --scanner-type="OSP" --scanner-host=/var/run/ospd-scanner.sock

Please note that the scanner created via `gvmd` like above will be created with
read permissions to all pre-configured roles.

Check whether Greenbone Vulnerability Manager can connect to the OSP daemon:

    $ gvmd --get-scanners
    08b69003-5fc2-4037-a479-93b440211c73  OpenVAS Default
    3566ddf1-cecf-4491-8bcc-5d62a87404c3  OSP Scanner

    $ gvmd --verify-scanner=3566ddf1-cecf-4491-8bcc-5d62a87404c3
    Scanner version: 1.0.

Of course, using GMP via command line tools provided by
[gvm-tools](https://github.com/greenbone/gvm-tools) to register an OSP Scanner
is also possible as a third option.


Documentation
-------------

Source code documentation can be accessed over the usual methods,
for example (replace "scanner" by the scanner name):

    $ python3
    >>> import ospd_scanner.wrapper
    >>> help (ospd_scanner.wrapper)

An equivalent to this is:

    pydoc3 ospd_scanner.wrapper

To explore the code documentation in a web browser:

    $ pydoc3 -p 12345
    pydoc server ready at http://localhost:12345/

For further options see the `man` page of `pydoc`.


Creating a source archive
-------------------------

To create a .tar.gz file for the `ospd-scanner` module run this command:

   python3 setup.py sdist

This will create the archive file in the subdirectory `dist`.
