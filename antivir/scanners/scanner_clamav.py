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

from odoo import models, fields, api, _, SUPERUSER_ID
from .pyclamd import ClamdAgnostic


class AntivirScannerClamav(models.Model):
    _inherit = 'antivir.scanner'
    _av_engine = 'antivir.scanner.clamav'

    def __init__(self, registry, cr):
        super(AntivirScannerClamav, self).__init__(registry, cr)
        self.register_engine(cr, SUPERUSER_ID, self._av_engine)

    @api.multi
    def scan(self, stream, results=None):
        if not results:
            results = []

        with self.active_scanner() as active:
            if active:
                result = self.run(stream)

                if result:
                    results.append({self._av_engine: result})
                else:
                    results.append({self._av_engine: None})

        return super(AntivirScannerClamav, self).scan(stream, results=results)

    @staticmethod
    def run(stream):
        """ Place for code executing scan - this function should return tuple for example ('FOUND', 'Eicar-Test-Signature')
        :param stream: str file data
        :return: tuple
        """
        scan_stream = ClamdAgnostic().scan_stream(stream)
        return scan_stream.get('stream') if scan_stream else False