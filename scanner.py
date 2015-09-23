# -*- coding: utf-8 -*-

##############################################################################
#
#    Author: Nuncjo
#    Copyright 2015 https://github.com/nuncjo
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
##############################################################################

from openerp.osv import osv, fields
from openerp.tools.translate import _
from datetime import datetime
import base64
import hashlib
import logging
from contextlib import contextmanager

_logger = logging.getLogger(__name__)


class antivir_scanner(osv.osv):
    _name = 'antivir.scanner'
    _av_engine = None

    _columns = {
        'name': fields.char("Scanner name"),
        'is_active': fields.boolean("Use this scanner"),
        'config_id': fields.many2one('antivir.config', 'Config')
    }

    def register_engine(self, cr, uid, name, context=None):
        """
        Registers new antivirus scanner by adding record to db and binding to active configuration
        :return: boolean
        """
        registered = False

        sql = "SELECT 1 FROM information_schema.tables WHERE table_name = 'antivir_config'"

        cr.execute(sql)
        config_exists = cr.fetchone()

        if config_exists:
            config_obj = self.pool.get("antivir.config")
            config_ids = config_obj.search(cr, uid, [('active_config', '=', True)], context=context)

            if config_ids and len(config_ids) == 1:
                scanner_ids = self.search(cr, uid, [('name', '=', self._av_engine)], context=context)

                if not scanner_ids:
                    self.create(cr, uid, {'name': name, 'is_active': False, 'config_id': config_ids[0]}, context=context)
                    _logger.warning(_("Scanner '{}' added to config, scanner is not active by default.".format(self._av_engine)))

        return registered

    def extract_files(self):
        # not implemented yet
        return False

    def run(self, cr, uid, stream, context=None):
        return False

    def scan(self, cr, uid, stream, results=None, context=None):
        """
        :return: list for example [{'scanner_name':('FOUND':'Virus name')}]
        """
        if not results:
            results = []
        return results

    def bulk_scan(self, cr, uid, limit):
        """ Chooses attachments without scan date (not scanned yet) and then runs scan. """

        config_obj = self.pool.get('antivir.config')
        active_config_ids = config_obj.search(cr, uid, [('active_config', '=', True)])
        config = config_obj.browse(cr, uid, active_config_ids)[0]

        if config.scan_cron:
            attachment_obj = self.pool.get('ir.attachment')
            attachment_ids = attachment_obj.search(cr, uid, [('virus_scan_date', '=', False),
                                                             ('type', '=', 'binary')], limit=limit)

            for id in attachment_ids:
                attachment = attachment_obj.browse(cr, uid, id)
                datas = attachment.datas

                if datas:
                    decoded_datas = base64.b64decode(datas)
                    SHA256 = hashlib.sha256(datas).hexdigest()
                    result = self.scan(cr, uid, decoded_datas)

                    if any(x.values()[0] for x in result):
                        threat = ','.join([val[1] for d in result for key, val in d.iteritems() if val is not None])
                        quarantine_obj = self.pool.get('antivir.quarantine')

                        vals = {'name': '{}-{}'.format(str(attachment.datas_fname), str(datetime.now())),
                                'filename': str(attachment.datas_fname),
                                'threat': threat,
                                'scan_results': str(result),
                                'file_data': datas,
                                'SHA256': SHA256,
                                'user_id': uid,
                                'quarantined': datetime.now()}

                        quarantine_id = quarantine_obj.create(cr, uid, vals)
                        attachment_obj.write(cr, uid, id, {'virus_scan_date': str(datetime.now()),
                                                           'virus_safe': False,
                                                           'virus_found_name': threat,
                                                           'quarantine_id': quarantine_id})
                        cr.commit()
                        _logger.info(_("Virus Found in attachment. File added to quarantine."))

                    else:
                        attachment_obj.write(cr, uid, id, {'virus_scan_date': str(datetime.now()),
                                                           'virus_safe': True})
                else:
                    attachment_obj.write(cr, uid, id, {'virus_scan_date': str(datetime.now()),
                                                       'virus_safe': True})

    @contextmanager
    def active_scanner(self, cr, uid, context=None):
        is_active = False
        scanner_ids = self.search(cr, uid, [('name', '=', self._av_engine)], context=context)
        try:
            if scanner_ids:
                scanner = self.browse(cr, uid, scanner_ids, context=context)
                is_active =scanner[0].is_active
                if is_active:
                    yield True
                else:
                    yield False
        finally:
            if is_active:
                _logger.info("File scanned with {}".format(str(self._av_engine)))
            else:
                _logger.info("Scanner {} is not active".format(str(self._av_engine)))
