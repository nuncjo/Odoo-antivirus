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

import base64
import hashlib
import logging
from contextlib import contextmanager
from datetime import datetime

from odoo import models, fields, api, _
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT

_logger = logging.getLogger(__name__)


class AntivirScanner(models.Model):
    _name = 'antivir.scanner'
    _av_engine = None

    name = fields.Char(
        string="Scanner name"
    )

    is_active = fields.Boolean(
        string="Use this scanner"
    )

    config_id = fields.Many2one(
        comodel_name='antivir.config', 
        string='Config'
    )

    def register_engine(self, cr, uid, name, context=None):
        """
        Registers new antivirus scanner by adding record to db and binding to active configuration
        :return: boolean
        """
        cr.execute("SELECT 1 FROM information_schema.tables WHERE table_name = 'antivir_config';")
        config_exists = cr.fetchone()

        if config_exists:
            cr.execute("SELECT id FROM antivir_config WHERE active_config;")
            active = cr.fetchone()

            if active:
                # If not exists then create!
                cr.execute('SELECT id FROM antivir_scanner WHERE "name" = %s;', (name,))
                exists = cr.fetchone()

                if not exists:
                    cr.execute("INSERT INTO antivir_scanner(\"name\", is_active, config_id) VALUES (%s, %s, %s)", (
                        name,
                        False,
                        active[0]
                    ))
                    _logger.warning(_("Scanner '{}' added to config, scanner is not active by default.".format(self._av_engine)))

    @api.multi
    def extract_files(self):
        # not implemented yet
        return False

    @api.multi
    def run(self, stream):
        return False

    @api.multi
    def scan(self, stream, results=None):
        """
        :return: list for example [{'scanner_name':('FOUND':'Virus name')}]
        """
        if not results:
            results = []
        return results

    @api.multi
    def bulk_scan(self, limit):
        """ Chooses attachments without scan date (not scanned yet) and then runs scan. """
        config = self.env['antivir.config'].search([
            ('active_config', '=', True)
        ])

        if config.exists() and config.scan_cron:
            attachment_ids = self.env['ir.attachment'].search([('virus_scan_date', '=', False), ('type', '=', 'binary')], limit=limit)

            for attachment in attachment_ids:
                datas = attachment.datas
                if datas:
                    decoded_datas = base64.b64decode(datas)
                    SHA256 = hashlib.sha256(datas).hexdigest()
                    result = self.scan(decoded_datas)

                    if any(x.values()[0] for x in result):
                        threat = ','.join([
                            val[1] for d in result for key, val in d.iteritems() if val is not None
                        ])

                        now = datetime.now().strftime(DEFAULT_SERVER_DATETIME_FORMAT)

                        quarantine_id = self.env['antivir.quarantine'].create({
                            'name': '{}-{}'.format(attachment.datas_fname, now),
                            'filename': attachment.datas_fname,
                            'threat': threat,
                            'scan_results': result,
                            'file_data': datas,
                            'SHA256': SHA256,
                            'user_id': uid,
                            'quarantined': now
                        })

                        attachment.write({
                            'virus_scan_date': now,
                            'virus_safe': False,
                            'virus_found_name': threat,
                            'quarantine_id': quarantine_id
                        })
                        cr.commit()
                        _logger.info(_("Virus Found in attachment. File added to quarantine."))
                    else:
                        now = datetime.now().strftime(DEFAULT_SERVER_DATETIME_FORMAT)
                        attachment.write({
                            'virus_scan_date': now,
                            'virus_safe': True
                        })
                else:
                    now = datetime.now().strftime(DEFAULT_SERVER_DATETIME_FORMAT)
                    attachment.write({
                        'virus_scan_date': now,
                        'virus_safe': True
                    })

    @contextmanager
    @api.model
    def active_scanner(self):
        is_active = False
        scanner_ids = self.search([
            ('name', '=', self._av_engine)
        ])
        try:
            if scanner_ids.exists():
                is_active = scanner_ids[0].is_active
                if is_active:
                    yield True
                else:
                    yield False
        finally:
            if is_active:
                _logger.info("File scanned with {}".format(self._av_engine))
            else:
                _logger.info("Scanner {} is not active".format(str(self._av_engine)))
