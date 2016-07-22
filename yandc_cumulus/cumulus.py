import yandc_base as base
import yandc_snmp as snmp
import yandc_ssh as ssh


class Client(base.Client):
    def __init__(self, *args, **kwargs):
        super(Client, self).__init__(*args, **kwargs)

        grouped_kwargs = base.Utils.group_kwargs('snmp_', 'ssh_', **kwargs)

        if 'snmp_' in grouped_kwargs:
            snmp_client = snmp.Client(kwargs['host'], **grouped_kwargs['snmp_'])
            try:
                sys_object_id = snmp_client.sysObjectID()
            except snmp.SNMP_Exception:
                pass
            else:
                if not self.is_cumulus(sys_object_id):
                    raise base.ClientError('Not a Cumulus device')
                self.snmp_client = snmp_client

        if 'ssh_' in grouped_kwargs:
            if 'username' not in grouped_kwargs['ssh_'] and 'username' in kwargs:
                grouped_kwargs['ssh_']['username'] = kwargs['username']

            if 'password' not in grouped_kwargs['ssh_'] and 'password' in kwargs:
                grouped_kwargs['ssh_']['password'] = kwargs['password']

            self.ssh_client = ssh.Client(kwargs['host'], **grouped_kwargs['ssh_'])

            shell_prompt = ssh.ShellPrompt(ssh.ShellPrompt.regexp_prompt(r'[^@]+@[^\$]+\$ '))
            if self.can_snmp() and 'username' in grouped_kwargs['ssh_']:
                shell_prompt.add_prompt(
                    grouped_kwargs['ssh_']['username'] + '@' + self.snmp_client.sysName() + '$ '
                )
            self.ssh_shell = ssh.Shell(self.ssh_client, shell_prompt)

    def cli_command(self, *args, **kwargs):
        return self.ssh_command(*args, **kwargs)

    def configure_via_cli(self, new_config):
        return False

    def disconnect(self):
        if self.can_ssh() and hasattr(self, 'ssh_shell'):
            self.ssh_shell.exit('logout')
            del self.ssh_shell
        super(Client, self).disconnect()

    @staticmethod
    def is_cumulus(sys_object_id):
        if sys_object_id.startswith('1.3.6.1.4.1.40310'):
            return True
        return False

    def get_config(self, config_source='running', config_filter=None):
        return []

    def get_interface_config(self, if_name):
        return self.ssh_command('ifquery ' + if_name)

    def software_version(self):
        if self.can_ssh():
            cli_output = self.ssh_command('lsb_release -r')
            if cli_output != []:
                return cli_output[0][8:].strip()
        return ''

    def ssh_command(self, *args, **kwargs):
        if not self.can_ssh():
            raise base.ClientError('No SSH client')
        if not hasattr(self, 'ssh_shell'):
            raise base.ClientError('No shell channel')
        return self.ssh_shell.command(*args, **kwargs)

    @staticmethod
    def vendor():
        return ('Cumulus', 'Cumulus Linux')
