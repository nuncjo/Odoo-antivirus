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

from odoo import models, fields, api


class AntivirConfig(models.Model):
    _name = "antivir.config"

    name = fields.Char(
        string="Config name"
    )

    scan_create = fields.Boolean(
        help="Enable check on attachment create (including mail fetching).",
        default=True
    )

    scan_cron = fields.Boolean(
        help="Enable check by cron.",
        default=False
    )
                
    disallowed_extensions = fields.Char(
        help="Disallowed extensions (coma separated .exe,.gif,.png)."
    )

    virustotal_api_key = fields.Char(
        string="VirusTotal API key"
    )
    
    virustotal_api_url = fields.Char(
        string="VirusTotal API url"
    )
                
    active_config = fields.Boolean(
        string="Use this config"
    )

    notes = fields.Text(
        string="Notes"
    )

    scanner_ids = fields.One2many(
        comodel_name='antivir.scanner', 
        inverse_name='config_id', 
        string="Scanners"
    )

    
    @api.model
    def create(self, vals):
        """ There can be only one """
        if vals.get('active_config'):
            self.env.cr.execute("UPDATE antivir_config SET active_config = FALSE;")
            self.env.cr.commit()

        return super(AntivirConfig, self).create(vals)

    @api.multi
    def write(self, vals):
        """ There can be only one """
        if vals.get('active_config'):
            self.env.cr.execute("UPDATE antivir_config SET active_config = FALSE;")
            self.env.cr.commit()

        return super(AntivirConfig, self).write(vals)
