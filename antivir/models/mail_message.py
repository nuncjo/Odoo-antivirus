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

from odoo import models, fields, api, _
from .exceptions import VirusFound


class MailMessage(models.Model):
    _inherit = 'mail.message'

    @api.model
    def create(self, vals):
        try:
            result = super(MailMessage, self).create(vals)
            return result
        except VirusFound:
            body = values.get('body')
            new_body = "{}\n{}".format(body, _("Virus found. Attachment deleted."))
            values.update({'body': new_body})
            values.update({'attachment_ids': []})
            return super(MailMessage, self).create(vals)
