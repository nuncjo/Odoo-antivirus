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

import os
import base64
import hashlib
import logging
from datetime import datetime

from .exceptions import VirusFound, ScanError

from odoo import models, fields, api, _
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT

_logger = logging.getLogger(__name__)


class IrAttachment(models.Model):
    _inherit = 'ir.attachment'

    virus_safe = fields.Boolean(
        default=False
    )

    virus_scan_date = fields.Datetime()

    virus_found_name = fields.Char(
        string="Virus name"
    )

    quarantine_id = fields.Many2one(
        comodel_name="antivir.quarantine", 
        string="Quarantine item", 
        ondelete='cascade'
    )

    active = fields.Boolean(
        help="If the active field is set to False, it will allow you to hide the payment term without removing it.",
        default=True        
    )

    @staticmethod
    def check_extension(disallowed_extensions, datas_fname):
        if disallowed_extensions:
            extensions = disallowed_extensions.split(",")
            filename, file_extension = os.path.splitext(datas_fname)
            if file_extension in extensions:
                raise ScanError(_("Antivirus Warning!"), _("Extension not allowed!"))

    @api.multi
    @api.depends('name', 'virus_safe', 'virus_found_name')
    def name_get(self):
        result = []
        for record in self:
            name = record.name
            if record.virus_found_name and record.virus_safe == False:
                name = "Virus: {} {}".format(record.virus_found_name, record.name)            
            result.append((record.id, name))
        return result

    @api.model
    def create(self, vals):
        """
        Checks whitelist and blacklist for hashes if file hash not found in any list then checking for viruses with
        available scanners
        """
        active_config_ids = self.env['antivir.config'].search([('active_config', '=', True)])
        if active_config_ids.exists():
            config = active_config_ids[0]
            IrAttachment.check_extension(config.disallowed_extensions, vals.get('datas_fname'))
            if config.scan_create:
                datas = vals.get('datas')
                if datas:
                    SHA256 = hashlib.sha256(datas).hexdigest()

                    whitelisted_ids = self.env['antivir.whitelist'].search([
                        ('SHA256', '=', SHA256)
                    ])
                    if not whitelisted_ids.exists():
                        blacklisted_ids = self.env['antivir.blacklist'].search([
                            ('SHA256', '=', SHA256)
                        ])

                        if blacklisted_ids.exists():
                            raise VirusFound(_("Antivirus Warning!\nThis file is blocked and cannot be uploaded."))
                        else:
                            result = self.env['antivir.scanner'].scan(base64.b64decode(datas))
                            if any(x.values()[0] for x in result):
                                threat = ','.join([
                                    val[1] for d in result for key, val in d.iteritems() if val is not None
                                ])
                                now = datetime.now().strftime(DEFAULT_SERVER_DATETIME_FORMAT)
                                self.env['antivir.quarantine'].create({
                                    'name': '{}-{}'.format(vals.get('datas_fname'), now),
                                    'filename': vals.get('datas_fname'),
                                    'threat': threat,
                                    'scan_results': result,
                                    'file_data': datas,
                                    'SHA256': SHA256,
                                    'user_id': self.env.user.id,
                                    'quarantined': now
                                })

                                self.env.cr.commit()
                                raise VirusFound(
                                    _("Antivirus Warning!\nVirus Found in attachment. File added to quarantine.")
                                )

        return super(IrAttachment, self).create(vals)
