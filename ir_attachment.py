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
from .exceptions import VirusFound, ScanError
import logging
import os

_logger = logging.getLogger(__name__)


class ir_attachment(osv.osv):
    _inherit = 'ir.attachment'

    _columns = {
        'virus_safe': fields.boolean("Virus Safe"),
        'virus_scan_date': fields.datetime("Virus scan date"),
        'virus_found_name': fields.char("Virus name"),
        'quarantine_id': fields.many2one("antivir.quarantine", "Quarantine item", ondelete='cascade'),
        'active': fields.boolean('Active',
                                 help="If the active field is set to False, it will allow you to hide the payment term without removing it."),
    }

    _defaults = {'virus_safe': False,
                 'active': True}

    @staticmethod
    def check_extension(disallowed_extensions, datas_fname):
        if disallowed_extensions:
            extensions = disallowed_extensions.split(",")
            filename, file_extension = os.path.splitext(datas_fname)
            if file_extension in extensions:
                raise ScanError(_("Antivirus Warning!"), _("Extension not allowed!"))

    def name_get(self, cr, uid, ids, context=None):
        if not ids:
            return []
        if isinstance(ids, (int, long)):
            ids = [ids]
        reads = self.read(cr, uid, ids, ['name', 'virus_safe', 'virus_found_name'], context=context)
        res = []
        for record in reads:
            name = record['name']
            if record.get('virus_found_name') and record.get('virus_safe') == False:
                name = "Virus: {} {}".format(str(record.get('virus_found_name')), str(name))
            res.append((record['id'], name))
        return res

    def create(self, cr, uid, vals, context=None):
        """
        Checks whitelist and blacklist for hashes if file hash not found in any list then checking for viruses with
        available scanners
        """

        config_obj = self.pool.get('antivir.config')
        active_config_ids = config_obj.search(cr, uid, [('active_config', '=', True)], context=context)

        if active_config_ids:
            config = config_obj.browse(cr, uid, active_config_ids, context=context)[0]
            self.check_extension(config.disallowed_extensions, vals.get('datas_fname'))

            if config.scan_create:
                datas = vals.get('datas')

                if datas:
                    decoded_datas = base64.b64decode(datas)
                    SHA256 = hashlib.sha256(datas).hexdigest()
                    whitelist_obj = self.pool.get('antivir.whitelist')
                    whitelisted_ids = whitelist_obj.search(cr, uid, [('SHA256', '=', SHA256)], context=context)

                    if not whitelisted_ids:
                        blacklist_obj = self.pool.get('antivir.blacklist')
                        blacklisted_ids = blacklist_obj.search(cr, uid, [('SHA256', '=', SHA256)], context=context)

                        if blacklisted_ids:
                            raise VirusFound(_("Antivirus Warning!"), _("This file is blocked and cannot be uploaded."))

                        else:
                            scanner_obj = self.pool.get('antivir.scanner')
                            result = scanner_obj.scan(cr, uid, decoded_datas)

                            if any(x.values()[0] for x in result):
                                threat = ','.join(
                                    [val[1] for d in result for key, val in d.iteritems() if val is not None])
                                quarantine_obj = self.pool.get('antivir.quarantine')

                                q_vals = {'name': '{}-{}'.format(str(vals.get('datas_fname')), str(datetime.now())),
                                          'filename': vals.get('datas_fname'),
                                          'threat': threat,
                                          'scan_results': str(result),
                                          'file_data': datas,
                                          'SHA256': SHA256,
                                          'user_id': uid,
                                          'quarantined': datetime.now()}

                                quarantine_obj.create(cr, uid, q_vals, context=context)

                                cr.commit()
                                raise VirusFound(_("Antivirus Warning!"),
                                                 _("Virus Found in attachment. File added to quarantine."))

            else:
                _logger.warning(_("Upload antivirus check not enebled in configuration."))

        return super(ir_attachment, self).create(cr, uid, vals, context=context)
