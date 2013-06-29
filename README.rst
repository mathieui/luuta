Luuta
=====

Luuta (it means “broom” in finnish) is a tool used for jabber
server administration.


It makes use of the `XEP-0133`_ to fetch connected users,
detailed information about them, and uses the GeoIP
database to approximate their geographical position.

Dependencies
------------

- python-gobject (and gtk)
- SleekXMPP
- pygeoip (you will need to install the geoip database with a package manager)


SleekXMPP and pygeoip can be installed with:

::

    pip3 install -r requirements.txt


Configuration
-------------

To run the script, you need to use your jabber account
(the one with admin privileges on the server), the password,
and the domain you want to manage.

Running the script with **-h** will show all the available
options.

You can also provide the options in a config.py file located
in the same directory, in caps lock (see the beginning of
luuta.py).

Usage
-----

Run the script with the right options, and you will get a
window with the JID of the online users and some info. You
can then expand them to show all their online resources,
with their IP addresses.

You can select them by clicking the checkbox on the right,
to mark them for deletion. Accounts are only deleted when
you click the “Delete” button and confirm your choice.

If the “autoremove” option is enabled (the default), all
accounts sharing IP addresses with a deleted account will
also be deleted.

Clicking the “Dump addresses” button will open a file chooser
to let you choose where you want the IP addresses to be saved.
They will be stored with the format chosen (one IP address
per line, by default).


Author
------

Mathieu Pasquet (mathieui) <luuta@mathieui.net>

A few patches from Link Mauve (http://linkmauve.fr)

.. _XEP-0133: http://xmpp.org/extensions/xep-0133.html
