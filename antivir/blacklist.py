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

class antivir_blacklist(osv.osv):

    _name = 'antivir.blacklist'
    _description = 'Disallowed files'
    _inherit = ['ir.needaction_mixin']

    _columns = {
        'name': fields.char('Name'),
        'SHA256': fields.char('SHA256'),
        'short_description': fields.char("Short description")
    }

    def _needaction_domain_get(self, cr, uid, context=None):
        return [(1, '=', 1)]

    _sql_constraints = [('field_unique', 'unique(SHA256)', 'SHA256 has to be unique!')]