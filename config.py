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


class antivir_config(osv.osv):
    _name = "antivir.config"

    _columns = {'name': fields.char("Config name"),
                'scan_create': fields.boolean("Enable check on attachment create (including mail fetching)."),
                'scan_cron': fields.boolean("Enable check by cron."),
                'disallowed_extensions': fields.char("Disallowed extensions (coma separated .exe,.gif,.png)."),
                'virustotal_api_key': fields.char("VirusTotal API key"),
                'virustotal_api_url': fields.char("VirusTotal API url"),
                'active_config': fields.boolean("Use this config"),
                'notes': fields.text("Notes"),
                'scanner_ids': fields.one2many('antivir.scanner', 'config_id', "Scanners")}

    _defaults = {'scan_create': True,
                 'scan_cron': False}

    def create(self, cr, uid, vals, context=None):
        """ There can be only one """
        if vals.get('active_config'):
            cr.execute("UPDATE antivir_config SET active_config=FALSE")
            cr.commit()

        return super(antivir_config, self).create(cr, uid, vals, context=context)

    def write(self, cr, uid, ids, vals, context=None):
        """ There can be only one """
        if vals.get('active_config'):
            cr.execute("UPDATE antivir_config SET active_config=FALSE")
            cr.commit()

        return super(antivir_config, self).write(cr, uid, ids, vals, context=context)
