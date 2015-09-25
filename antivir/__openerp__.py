# -*- coding: utf-8 -*-
{
    'name': 'Odoo Antivirus',
    'version': '0.1 alpha',
    'author': 'Nuncjo',
    'website': 'https://github.com/nuncjo',
    'category': 'Extra Tools',
    'depends': ['base', 'mail', 'knowledge', 'document'],
    'description': """
Attachments antivirus scanner.
====================================================
Clamav daemon and virustotal quickstart:
----------------------------------------------------
* To install clamav deamon: [ubuntu/debian]: > sudo apt-get install clamav clamav-daemon
* To update virus definitions: > sudo freshclam
* To check if it's running: > ps ax | grep [c]lamd
* To edit options like max filesize etc. > sudo nano /etc/clamav/clamd.conf then sudo /etc/init.d/clamav-daemon restart
* For other distributions check clamav manual
* For use of virustotal api: pip install virustotal-api
* Virustotal api needs api key, it can be obtained after registering www.virustotal.com

Features:
----------------------------------------------------
* Scans files on attachments create
* Full list of ClamAV features at http://www.clamav.net/
* Online scan by Virustotal api: manual hash checking for quarantined files analysis, could be simply extended if needed.

Policy:
----------------------------------------------------
* Default infected files policy: delete in frontend, store in quarantine for further analysis, blacklisting etc.
* Unsafe files scanned by cron are hidden from user. This can be customized by using ir.rule in security.xml.

Notice:
----------------------------------------------------
* Clamav offers only basic protection compared to commercial antivirus software, I encourage You to extend this plugin to use more sophisticated protection. Use of Python multiav library is suggested.
* Odoo antivirus is rather skeleton for extending with dedicated commercial antivirus solutions.

Warning:
----------------------------------------------------
* Use at own risk !

Future extension possibilites for e.g.
----------------------------------------------------
* Scanning website urls in mails in external services/checking in phising databases etc.
* More pre defined scanners: suggested use of https://github.com/nuncjo/multiav
* Predefined hash databases (like http://virusshare.com/)
* Hash checking for every file in archives
* Antispam mail extension
* Periodic reports and statistics

""",
    'data': [
        'security/ir.model.access.csv',
        'security/security.xml',
        'antivir_view.xml',
        'quarantine_view.xml',
        'whitelist_view.xml',
        'blacklist_view.xml',
        'config_view.xml',
        'scanner_view.xml',
        'ir_attachment_view.xml',
        'cron.xml',
    ],
    'demo': [],
    'installable': True,
    'auto_install': False,
}
# vim:expandtab:smartindent:tabstop=4:softtabstop=4:shiftwidth=4:
