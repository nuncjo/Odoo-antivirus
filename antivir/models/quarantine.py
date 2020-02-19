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

from datetime import datetime
from virus_total_apis import PublicApi as VirusTotalPublicApi

from .exceptions import ConfigError

from odoo import models, fields, api, _
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT


class AntivirQuarantine(models.Model):
    _name = 'antivir.quarantine'
    _description = 'Store blocked files'
    _inherit = ['ir.needaction_mixin']

    name = fields.Char()
    
    filename = fields.Char()
    
    threat = fields.Char(
        string='Threat name'
    )
    
    scan_results = fields.Text()

    file_data = fields.Binary()

    SHA256 = fields.Char(
        string='SHA256'
    )

    user_id = fields.Many2one(
        comodel_name='res.users', 
        string='User'
    )

    quarantined = fields.Datetime(
        string='Quarantined date'
    )

    virustotal_summary = fields.Html()

    blacklisted = fields.Boolean()

    whitelisted = fields.Boolean()

    attachment_ids = fields.One2many(
        comodel_name='ir.attachment', 
        inverse_name='quarantine_id', 
        string='Attachments'
    )

    @api.model    
    def _needaction_domain_get(self):
        return [(1, '=', 1)]

    @api.multi
    def add_to(self, model=None):
        self.ensure_one()
        if self.exists():
            obj_ids = self.env[model].search([
                ('SHA256', '=', self.SHA256)
            ])

            if not obj_ids.exists():
                now = datetime.now().strftime(DEFAULT_SERVER_DATETIME_FORMAT)
                self.env[model].create({
                    'name': "{}-{}".format(self.threat, now),
                    'SHA256': self.SHA256,
                    'short_description': self.threat
                })

                self.write({"whitelisted" if model == 'antivir.whitelist' else "blacklisted": True})

                for attachment_id in self.attachment_ids:
                    attachment_id.write({
                        'virus_safe': True
                    })
                return True
            else:
                obj_ids.unlink()

                if model == 'antivir.whitelist':
                    data = {'whitelisted': False}
                else:
                    data = {'blacklisted': False}
                
                self.write(data)
                return True

    @api.multi
    def add_to_whitelist(self):
        return self.add_to(model='antivir.whitelist')

    @api.multi
    def add_to_blacklist(self):
        return self.add_to(model='antivir.blacklist')

    @api.multi
    def remove_from_quarantine(self):
        #TODO: implementation removig files from quarantine
        pass

    @api.multi
    def check_virustotal(self):
        self.ensure_one()

        config_obj = self.env['antivir.config'].search([
            ('active_config', '=', True)
        ])

        if config_obj.exists():
            config = config_obj[0]
            if config.virustotal_api_url and config.virustotal_api_key:
                vt = VirusTotalPublicApi(config.virustotal_api_key)
                response = vt.get_file_report(self.SHA256)
                scans = response['results'].get('scans')

                if scans:
                    scans_results = [
                        "<li>[{}] detected:{} result:{}</li>".format(
                            key, val.get('detected'), val.get('result')
                        ) for key, val in scans.iteritems()
                    ]
                    virustotal_summary = "<ul>{}</ul>".format(''.join(scans_results))
                else:
                    virustotal_summary = _("Couldn't fetch virustotal_summary, try again later.")

                self.write({
                    'virustotal_summary': virustotal_summary
                })
        else:
            raise ConfigError(_("There is no active config."))
