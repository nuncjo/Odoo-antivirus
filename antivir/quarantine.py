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
from openerp.osv import osv, fields
from openerp.tools.translate import _
from virus_total_apis import PublicApi as VirusTotalPublicApi
from .exceptions import ConfigError

class antivir_quarantine(osv.osv):
    _name = 'antivir.quarantine'
    _description = 'Store blocked files'
    _inherit = ['ir.needaction_mixin']

    _columns = {
        'name': fields.char('Name'),
        'filename': fields.char('Filename'),
        'threat': fields.char('Threat name'),
        'scan_results': fields.text("Scan results"),
        'file_data': fields.binary('File data'),
        'SHA256': fields.char('SHA256'),
        'user_id': fields.many2one('res.users', 'User ID'),
        'quarantined': fields.datetime('Quarantined date'),
        'virustotal_summary': fields.html('VirusTotal summary'),
        'blacklisted': fields.boolean('Blacklisted'),
        'whitelisted': fields.boolean('Whitelisted'),
        'attachment_ids': fields.one2many('ir.attachment', 'quarantine_id', 'Attachments'),
    }

    def _needaction_domain_get(self, cr, uid, context=None):
        return [(1, '=', 1)]

    def add_to(self, cr, uid, ids, model=None, context=None):

        quarantine_item = self.browse(cr, uid, ids, context=context)
        if quarantine_item:

            obj = self.pool.get(model)
            obj_ids = obj.search(cr, uid, [('SHA256', '=', quarantine_item[0].SHA256)])

            if not obj_ids:
                obj.create(cr, uid, {'name': "{}-{}".format(quarantine_item[0].threat, str(datetime.now())),
                                     'SHA256': quarantine_item[0].SHA256,
                                     'short_description': quarantine_item[0].threat},
                           context=context)

                if model == 'antivir.whitelist':
                    data = {'whitelisted': True}

                else:
                    data = {'blacklisted': True}

                self.write(cr, uid, ids, data, context=context)

                attachment_obj = self.pool.get('ir.attachment')
                for attachment_id in quarantine_item[0].attachment_ids:
                    attachment_obj.write(cr, uid, [attachment_id.id], {'virus_safe': True}, context=context)
                return True

            else:
                obj.unlink(cr, uid, obj_ids, context=context)

                if model == 'antivir.whitelist':
                    data = {'whitelisted': False}

                else:
                    data = {'blacklisted': False}

                self.write(cr, uid, ids, data, context=context)
                return True
        else:
            return False

    def add_to_whitelist(self, cr, uid, ids, context=None):
        return self.add_to(cr, uid, ids, model='antivir.whitelist', context=context)

    def add_to_blacklist(self, cr, uid, ids, context=None):
        return self.add_to(cr, uid, ids, model='antivir.blacklist',  context=context)

    def remove_from_quarantine(self, cr, uid, ids, context=None):
        #TODO: implementation removig files from quarantine
        pass
        #quarantied = self.browse(cr, uid, ids, context=context)
        #detach_list = [[3, attachment.id, False] for attachment in quarantied[0].attachment_ids]
        #self.write(cr, uid, ids, {'attachment_ids': detach_list}, context=context)

    def check_virustotal(self, cr, uid, ids, context=None):

        config_obj = self.pool.get('antivir.config')
        config_ids = config_obj.search(cr, uid, [('active_config', '=', True)], context=context)

        if config_ids:
            config = config_obj.browse(cr, uid, config_ids, context=context)

            if config[0].virustotal_api_url and config[0].virustotal_api_key:
                quarantine_item = self.browse(cr, uid, ids, context=context)
                vt = VirusTotalPublicApi(config[0].virustotal_api_key)
                response = vt.get_file_report(quarantine_item[0].SHA256)
                scans = response['results'].get('scans')

                if scans:
                    scans_results = ["<li>[{}] detected:{} result:{}</li>".format(str(key), str(val.get('detected')),
                                                                                  str(val.get('result')))
                                     for key, val in scans.iteritems()]

                    virustotal_summary = "<ul>{}</ul>".format(''.join(scans_results))
                else:
                    virustotal_summary = _("Couldn't fetch virustotal_summary, try again later.")

                self.write(cr, uid, ids, {'virustotal_summary': virustotal_summary}, context=context)
        else:
            raise ConfigError(_("There is no active config."))


class res_users(osv.osv):
    _inherit = 'res.users'
    _columns = {
        'quarantine_files_ids': fields.one2many('antivir.quarantine', 'user_id', 'Quarantine files')
    }
