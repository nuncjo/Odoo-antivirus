# Odoo antivirus
<p>Openerp 7 antivirus plugin.</p>

<h4>Clamav daemon and virustotal quickstart:</h4>
<ul>
<li>To install clamav deamon: [ubuntu/debian]: > <b>sudo apt-get install clamav clamav-daemon</b></li>
<li>To update virus definitions: > <b>sudo freshclam</b></li>
<li>To check if it's running: > <b>ps ax | grep [c]lamd</b></li>
<li>To edit options like max filesize etc. > <b>sudo nano /etc/clamav/clamd.conf then sudo /etc/init.d/clamav-daemon restart</b></li>
<li>For other distributions check clamav manual</li>
<li>For use of virustotal api: <b>pip install virustotal-api</b></li>
<li>Virustotal api needs api key, it can be obtained after registering www.virustotal.com</li>
</ul>



Source code: https://github.com/nuncjo/Odoo-antivirus
