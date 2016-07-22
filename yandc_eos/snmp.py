import re
#
import yandc_snmp as snmp


class Client(snmp.Client):
    def os_version(self):
        re_match = re.match(
            r'Arista Networks EOS version (.+) running on an Arista Networks (.+)$',
            self.sysDescr()
        )
        if re_match is not None:
            return re_match.groups()[0]
        return None
