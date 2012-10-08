Profile Manager CLI
===================

A command line interface for Profile Manager administration.


Usage
-----

You can specify the server, username, and password on the command line:

    ./pmcli.py -u pmserver.example.com -u diradmin -p apple

Or you can set defaults (but command line options will override):

    defaults write se.gu.it.pmcli server pmserver.example.com
    defaults write se.gu.it.pmcli username diradmin
    defaults write se.gu.it.pmcli password apple


### • import

Import a CSV file with devices:

    ./pmcli.py import file.csv

The first line of the CSV should have a header, with the following keys:

* name (required) - name of the placeholder device
* group (optional) - group to add the placeholder device to
* serial/imei/meid/udid (required, select one) - unique identifier for the device

The CSV file should be plain ascii or UTF-8 encoded.
