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


class AntivirBlacklist(models.Model):
    _name = 'antivir.blacklist'
    _inherit = ['ir.needaction_mixin']
    _description = 'Disallowed files'

    _sql_constraints = [
        ('field_unique', 'unique(SHA256)', 'SHA256 has to be unique!')
    ]

    name = fields.Char()

    SHA256 = fields.Char()

    short_description = fields.Char()

    @api.model
    def _needaction_domain_get(self):
        return [(1, '=', 1)]

    