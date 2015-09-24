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

from openerp import SUPERUSER_ID
from openerp.osv import osv, fields
from .pyclamd import ClamdAgnostic


class antivir_scanner_clamav(osv.osv):
    _inherit = 'antivir.scanner'
    _av_engine = 'antivir.scanner.clamav'

    def __init__(self, registry, cr):
        super(antivir_scanner_clamav, self).__init__(registry, cr)
        self.register_engine(cr, SUPERUSER_ID, self._av_engine)

    def scan(self, cr, uid, stream, results=None, context=None):

        if not results:
            results = []

        with self.active_scanner(cr, uid, context=context) as active:

            if active:
                result = self.run(stream)

                if result:
                    results.append({self._av_engine: result})
                else:
                    results.append({self._av_engine: None})

        return super(antivir_scanner_clamav, self).scan(cr, uid, stream, results=results, context=context)

    @staticmethod
    def run(stream):
        """ Place for code executing scan - this function should return tuple for example ('FOUND', 'Eicar-Test-Signature')
        :param stream: str file data
        :return: tuple
        """
        cd = ClamdAgnostic()
        scan_stream = cd.scan_stream(stream)
        result = scan_stream.get('stream')
        return result