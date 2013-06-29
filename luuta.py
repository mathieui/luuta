#!/usr/bin/env python3
"""
A simple administration tool for XMPP servers.

It allows you to check quickly which accounts have a lot of resources,
and which are from countries prone to be abusers.

You can delete the accounts and/or dump the IPs into a file
(for iptables use, for example).
"""
import logging
log = logging.getLogger(__name__)

import sleekxmpp
import pygeoip
import sys

from collections import Counter

from argparse import ArgumentParser

from getpass import getpass

from gi.repository import Gtk, GObject, Gdk

# geoip
IPV4 = pygeoip.GeoIP('/usr/share/GeoIP/GeoIP.dat', pygeoip.MEMORY_CACHE)
IPV6 = pygeoip.GeoIP('/usr/share/GeoIP/GeoIPv6.dat', pygeoip.MEMORY_CACHE)

# namespaces
ONLINE_USERS = "http://jabber.org/protocol/admin#get-online-users"
USER_STATS = "http://jabber.org/protocol/admin#user-stats"
USER_DELETE = "http://jabber.org/protocol/admin#delete-user"
ADMIN = 'http://jabber.org/protocol/admin'

try:
    import config
except ImportError:
    config = {
            'jid': None,
            'password': None,
            'domain': None,
            'format': '{ip}\n',
            'host': None,
            'port': None,
            'log': None,
            'autoremove': True,
    }
else:
    config = {
            'jid': getattr(config, 'JID', None),
            'password': getattr(config, 'PASSWORD', None),
            'domain': getattr(config, 'DOMAIN', None),
            'format': getattr(config, 'LINE_FORMAT', '{ip}\n'),
            'host': getattr(config, 'HOST', None),
            'port': getattr(config, 'PORT', None),
            'log': getattr(config, 'LOG', None),
            'autoremove': getattr(config, 'AUTOREMOVE', True),
    }

class Connection(sleekxmpp.ClientXMPP):
    """
    Simple wrapper class that overrides the ClientXMPP base to
    register plugins and take our configuration into account
    """
    def __init__(self):
        sleekxmpp.ClientXMPP.__init__(self, config['jid'], config['password'])
        self.register_plugin('xep_0004')
        self.register_plugin('xep_0030')
        self.register_plugin('xep_0050')

    def start(self):
        """
        Connect to the server and start the handlers
        """
        if config['port'] or config['host']:
            port = config['port'] or 5222
            host = config['host'] or sleekxmpp.JID(config['jid']).host
            addr = (host, port)
        else:
            addr = tuple()
        self.connect(addr)
        self.process(threaded=True)

class AdminUI(Gtk.Window):
    """
    Main UI class,
    contains a TreeView and three buttons,
    references a TreeStore shared with the Admin class
    """

    def __init__(self):
        Gtk.Window.__init__(self)
        self.set_title('Online users on %s' % config['domain'])
        self.store = Gtk.TreeStore(str, int, int, str, str, bool)

        box = Gtk.Box(False, 0)
        box.set_orientation(Gtk.Orientation.VERTICAL)
        self.add(box)

        delbutton = Gtk.Button("Remove selected accounts")
        delbutton.connect("clicked", self.delete_selected)
        ipbutton = Gtk.Button("Dump selected IP addresses")
        ipbutton.connect("clicked", self.dump_ips)

        hbox = Gtk.Box(True)
        hbox.pack_start(delbutton, True, True, 1)
        hbox.pack_start(ipbutton, True, True, 1)

        win = Gtk.ScrolledWindow()
        win.set_policy(Gtk.PolicyType.NEVER,
                Gtk.PolicyType.AUTOMATIC)
        self.tree = Gtk.TreeView(self.store)
        self.init_tree()
        win.add(self.tree)

        box.pack_start(win, True, True, 0)

        box.pack_start(hbox, False, False, 0)
        self.show_all()
        self.admin = Admin(self.store)
        def leave(*args, **kwargs):
            self.admin.xmpp.disconnect()
            Gtk.main_quit(*args, **kwargs)
        self.connect("delete-event", leave)

    def get_lines(self, criteria):
        """
        Get the list of checked lines
        """
        rootiter = self.store.get_iter_first()
        lines = []

        def sub_get_lines(treeiter):
            """
            Get the checked children
            """
            while treeiter != None:
                tup = self.store[treeiter]
                if criteria(tup):
                    lines.append({
                        'jid': tup[0],
                        'country': tup[3],
                        'ip': tup[4]})
                if self.store.iter_has_child(treeiter):
                    childiter = self.store.iter_children(treeiter)
                    sub_get_lines(childiter)
                treeiter = self.store.iter_next(treeiter)
        sub_get_lines(rootiter)
        return lines

    def dump_ips(self, widget):
        """
        Dump the IPs to a file, according to LINE_FORMAT
        """
        fchooser = Gtk.FileChooserDialog("Please select a file", self,
                Gtk.FileChooserAction.SAVE,
                (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_OPEN, Gtk.ResponseType.OK))
        response = fchooser.run()
        try:
            if response == Gtk.ResponseType.OK:
                filename = fchooser.get_filename()
                lines = self.get_lines(lambda tup: tup[5] and tup[4])
                with open(filename, 'wt') as fd:
                    built = [config['format'].format(**item) for item in lines]
                    fd.writelines(built)
                    fd.flush()
        except Exception:
            import traceback
            log.debug(traceback.format_exc())

        fchooser.destroy()

    def main(self):
        Gtk.main()

    def init_tree(self):
        """
        Intitialize the TreeView
        """
        tree = self.tree

        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("JID", renderer, text=0)
        column.set_resizable(True)
        column.set_sizing(Gtk.TreeViewColumnSizing.AUTOSIZE)
        column.set_expand(True)
        column.set_sort_column_id(0)
        tree.append_column(column)

        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Roster size", renderer, text=1)
        column.set_sort_column_id(1)
        tree.append_column(column)

        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Resources", renderer, text=2)
        column.set_sort_column_id(2)
        tree.append_column(column)
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Country", renderer, text=3)
        column.set_sort_column_id(3)
        tree.append_column(column)

        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("IP", renderer, text=4)
        column.set_sort_column_id(4)
        tree.append_column(column)

        renderer_toggle = Gtk.CellRendererToggle()
        renderer_toggle.connect("toggled", self.on_cell_toggled)
        column_toggle = Gtk.TreeViewColumn("Ban", renderer_toggle, active=5)
        column_toggle.set_sort_column_id(5)
        column_toggle.set_expand(False)
        tree.append_column(column_toggle)

        select = tree.get_selection()
        select.set_mode(Gtk.SelectionMode.MULTIPLE)

    def on_cell_toggled(self, widget, path):
        """
        Change the bool value in the store,
        and propagate the change to the children
        """
        self.store[path][5] = not self.store[path][5]
        # propagate the choice to the direct children
        treeiter = self.store.get_iter(path)
        if self.store.iter_has_child(treeiter):
            childiter = self.store.iter_children(treeiter)
            while childiter != None:
                self.store[childiter][5] = self.store[treeiter][5]
                childiter = self.store.iter_next(childiter)

    def delete_selected(self, button):
        """
        Delete the accounts for the selected lines
        """
        lines = self.get_lines(lambda tup: tup[4] and tup[5])
        if not lines:
            return
        if config['autoremove']:
            ips_to_delete = {line['ip'] for line in lines}
            accounts = self.get_lines(lambda tup: tup[4] in ips_to_delete)
        else:
            accounts = lines
        to_delete = {sleekxmpp.JID(account['jid']).bare for account in accounts}
        if len(to_delete) == 1:
            message = 'Are you sure you want to delete this account?'
        else:
            message = 'Are you sure you want to delete the %s selected accounts?' % len(to_delete)
        dialog = Gtk.MessageDialog(self,
                Gtk.DialogFlags.MODAL,
                Gtk.MessageType.QUESTION,
                Gtk.ButtonsType.YES_NO,
                message)
        response = dialog.run()
        dialog.destroy()
        if response == Gtk.ResponseType.NO:
            return
        self.admin.delete_users(list(to_delete))
        self.store.clear()
        self.admin.get_online_users()

class Admin(object):
    """
    “Model” class, links the Connection class and  the TreeStore
    """

    def __init__(self, store):
        self.store = store
        self.data = {}
        self.xmpp = Connection()
        self.xmpp.add_event_handler('session_start', self.session_start)
        self.xmpp.start()

    def session_start(self, ignored):
        """
        Fill the TreeStore when we connect to the server
        """
        self.get_online_users()

    def get_user_statistics(self, jid):
        """
        Get the "user statistics" of a given jid
        """
        self.data[jid] = {}

        iq = self.xmpp.plugin['xep_0050'].send_command(
                config['domain'],
                USER_STATS)
        sessionid = iq['command']['sessionid']

        form = self.xmpp.plugin['xep_0004'].make_form(ftype='submit')
        field = form.add_field(
                ftype='hidden',
                type='hidden',
                var='FORM_TYPE',
                value=ADMIN)
        field['type'] = 'hidden'
        form.add_field(var='accountjid', value=jid)

        result = self.xmpp.plugin['xep_0050'].send_command(
                config['domain'],
                USER_STATS,
                sessionid=sessionid,
                payload=form)
        fields = result['command']['form']['fields']

        for field in fields.values():
            if field['type'] != 'hidden':
                if field['var'] == 'onlineresources':
                    value = field['value'].split('\n')
                elif field['var'] == 'ipaddresses':
                    value = []
                    for ip in field['value'].split('\n'):
                        lookup = ip_lookup(ip)
                        if not lookup:
                            lookup = 'Unknown'
                        value.append((ip, lookup))
                else:
                    value = field['value']
                self.data[jid][field['var']] = value

    def delete_users(self, jids):
        """
        Delete a list of users from the server
        """
        iq = self.xmpp.plugin['xep_0050'].send_command(
                config['domain'],
                USER_DELETE)
        sessionid = iq['command']['sessionid']

        form = self.xmpp.plugin['xep_0004'].make_form(ftype='submit')
        field = form.add_field(
                ftype='hidden',
                type='hidden',
                var='FORM_TYPE',
                value=ADMIN)
        field['type'] = 'hidden'
        field = form.add_field(var='accountjids')
        field['value'] = jids

        self.xmpp.plugin['xep_0050'].send_command(
                config['domain'],
                USER_DELETE,
                sessionid=sessionid,
                payload=form)

    def get_online_users(self):
        """
        Fetch all the 100 first online users in domain
        """
        self.data = {}
        iq = self.xmpp.plugin['xep_0050'].send_command(
                config['domain'],
                ONLINE_USERS)
        sessionid = iq['command']['sessionid']

        form = self.xmpp.plugin['xep_0004'].make_form(ftype='submit')
        field = form.add_field(
                ftype='hidden',
                type='hidden',
                var='FORM_TYPE',
                value=ADMIN)
        field['type'] = 'hidden'
        form.add_field(var='max_items', value='100')

        result = self.xmpp.plugin['xep_0050'].send_command(
                config['domain'],
                ONLINE_USERS,
                sessionid=sessionid,
                payload=form)

        field = result['command']['form']['fields']['onlineuserjids']

        if not field['value']: # no user online, abort
            return

        for item in field['value'].split('\n'):
            self.get_user_statistics(item)
        Gdk.threads_enter()
        for jid in self.data:
            data = self.data[jid]
            row = self.store.append(None, [
                    jid, int(data['rostersize']),
                    len(data['onlineresources']),
                    '', '', False
                ])
            resources = self.data[jid]['onlineresources']
            for index, resource in enumerate(resources):
                self.store.append(row,
                        [
                            '%s/%s' % (jid, resource),
                            int(data['rostersize']),
                            len(data['onlineresources']),
                            data['ipaddresses'][index][1],
                            data['ipaddresses'][index][0],
                            False
                        ]
                )
            countries = []
            for addr in data['ipaddresses']:
                countries.append(addr[1])
            countries = Counter(countries)
            self.store.set_value(row, 3, max(countries.items(), key=lambda tup: tup[1])[0])
        Gdk.threads_leave()


def parse_args():
    def boolean(arg):
        if arg.lower() == 'true':
            return True
        elif arg.lower() == 'false':
            return False
        elif arg.isdecimal():
            return bool(int(arg))
        return bool(arg)

    parser = ArgumentParser()
    parser.add_argument('-j', '--jid', dest='jid', default='',
            help='JID used to manage the domain')
    parser.add_argument('-H', '--host', dest='host', default='',
            help='Server to connect to (overrides the DNS for the JID domain)')
    parser.add_argument('-P', '--port', dest='port', type=int, default=0,
            help='Port to connect to'
            '(overrides the DNS records for the JID domain)')
    parser.add_argument('-d', '--domain', dest='domain', default='',
            help='XMPP server to manage')
    parser.add_argument('-p', '--password', dest='password', default='',
            help='Password (if none is present,'
            ' it will be asked interactively)')
    parser.add_argument('-f', '--format', dest='format', default='{ip}\n',
            help='Format used to dump the ip addresses into a file,'
            ' {ip}, {country} and {jid} can be used')
    parser.add_argument('-l', '--logfile', dest='logfile', default='',
            help='Enable debugging and log everything to LOGFILE')
    parser.add_argument('-a', '--autoremove', dest='autoremove', default=None,
            type=boolean,
            help='Remove all accounts associated with the IP of '
            'a deleted account (default: true)')
    options = parser.parse_args()
    if options.jid:
        config['jid'] = options.jid
    if options.port:
        config['port'] = options.port
    if options.host:
        config['host'] = options.host
    if options.domain:
        config['domain'] = options.domain
    if options.password:
        config['password'] = options.password
    if options.format and options.format != '{ip}\n':
        config['format'] = options.format

    if options.autoremove is not None:
        config['autoremove'] = options.autoremove

    if not config['password']:
        config['password'] = getpass()

    if not config['log']:
        config['log'] = options.logfile

    if not config['domain'] or not config['jid'] or not config['password']:
        sys.exit(1)

    if config['log']:
        logging.basicConfig(filename=config['log'], level=logging.DEBUG)


def ip_lookup(ip):
    lookup = IPV6 if ':' in ip else IPV4
    result = lookup.country_name_by_addr(ip)
    return result

if __name__ == '__main__':
    GObject.threads_init()
    parse_args()
    AdminUI()
    Gdk.threads_enter()
    Gtk.main()
    Gdk.threads_leave()
