import re
#
import yandc_base as base
try:
    import yandc_snmp as snmp
    HAVE_SNMP = True
except:
    HAVE_SNMP = False
import yandc_ssh as ssh


class Client(base.Client):
    def __init__(self, *args, **kwargs):
        super(Client, self).__init__(*args, **kwargs)

        grouped_kwargs = base.Utils.group_kwargs('snmp_', 'ssh_', **kwargs)

        if HAVE_SNMP and 'snmp_' in grouped_kwargs:
            snmp_client = snmp.Client(kwargs['host'], **grouped_kwargs['snmp_'])

            try:
                sys_object_id = snmp_client.sysObjectID()
            except snmp.SNMP_Exception:
                pass
            else:
                if not self.is_cisco(sys_object_id):
                    raise base.DeviceMismatchError('Not a Cisco device')
                self.snmp_client = snmp_client

        if 'ssh_' in grouped_kwargs:
            if 'username' not in grouped_kwargs['ssh_'] and 'username' in kwargs:
                grouped_kwargs['ssh_']['username'] = kwargs['username']
            if 'password' not in grouped_kwargs['ssh_'] and 'password' in kwargs:
                grouped_kwargs['ssh_']['password'] = kwargs['password']

            self.ssh_client = ssh.Client(kwargs['host'], **grouped_kwargs['ssh_'])

            shell_prompt = ssh.ShellPrompt(ssh.ShellPrompt.regexp_prompt(r'.+[#>]$'))
            shell_prompt.add_prompt(ssh.ShellPrompt.regexp_prompt(r'.+\(config[^\)]*\)#$'))

            shell_args = {
                'combine_stderr': True,
                'initial_commands': [
                    'terminal length 0',
                    'terminal no monitor',
                    'terminal width 160',
                ],
                'terminal_width': 160,
            }
            self.ssh_shell = ssh.Shell(self.ssh_client, shell_prompt, optional_args=shell_args)
#            self.ssh_shell.channel.set_combine_stderr(True)
#            self.ssh_shell.command('terminal length 0')
#            self.ssh_shell.command('terminal no monitor')
#            self.ssh_shell.command('terminal width 160')

        self._in_configure_mode = False

    def cli_command(self, *args, **kwargs):
        if self.can_ssh():
            return self.ssh_command(*args, **kwargs)
        raise base.ClientError('No valid CLI handlers')

    def configure_via_cli(self, new_config):
        if self.can_ssh():
            try:
                cli_output = self.ssh_command('configure terminal')
                if not cli_output[0].startswith("'Enter configuration commands, one per line."):
                    self._in_configure_mode = True
                else:
                    raise base.ClientError(cli_output[0])

                for config_line in new_config:
                    stripped_line = config_line.strip()
                    if stripped_line in ['end', 'exit']:
                        continue
                    cli_output = self.ssh_command(stripped_line)
                    if cli_output != []:
                        raise base.ClientError(cli_output[0])
            finally:
                cli_output = self.ssh_command('end')
                if cli_output == []:
                    self._in_configure_mode = False

                    return True
                else:
                    raise base.ClientError(cli_output[0])
        return False

    def disconnect(self):
        if self.can_ssh() and hasattr(self, 'ssh_shell'):
            self.ssh_shell.exit('logout')
            del self.ssh_shell
        super(Client, self).disconnect()

    def get_config(self, source='running', section=None):
        if self.can_ssh():
            config_command = 'show {}-config'.format(source)
            if section is not None:
                config_command += ' | section {}'.format(section)
            return self.ssh_command(config_command)
        return []

    @property
    def in_configure_mode(self):
        mode_mismatch = False
        config_prompt = self.ssh_shell.last_prompt.endswith('(config)#')
        if self._in_configure_mode:
            if not config_prompt:
                mode_mismatch = True
        else:
            if config_prompt:
                mode_mismatch = True
        if mode_mismatch:
            raise base.ClientError(
                'Mistmatch between in_configure_mode [{}] and prompt [{}]'.format(
                    self._in_configure_mode,
                    self.ssh_shell.last_prompt
                )
            )
        return self._in_configure_mode
        
    @staticmethod
    def is_cisco(sys_object_id):
        if sys_object_id.startswith('1.3.6.1.4.1.9.1'):
            return True
        return False

    def persist_configuration(self):
         if self.in_configure_mode:
             pass
         cli_output = self.ssh_command('write memory')
         if cli_output[0] != 'Building configuration...' and cli_output[-1] != '[OK]':
             raise base.ClientError(cli_output[0])
         return True

    def privilege_level(self):
        cli_output = self.ssh_command('show privilege')
        partial_output = 'Current privilege level is '
        if not cli_output[0].startswith(partial_output):
            raise base.ClientError(cli_output)
        return int(cli_output[0][len(partial_output):])

    def software_version(self):
        if self.can_snmp():
            return self._ios_version(self.snmp_client.sysDescr())
        elif self.can_ssh():
            return self._ios_version(self.ssh_shell.command('show version')[0])
        return ''

    def ssh_command(self, *args, **kwargs):
        if not self.can_ssh():
            raise base.ClientError('No SSH client')
        if not hasattr(self, 'ssh_shell'):
            raise base.ClientError('No shell channel')
        return self.ssh_shell.command(*args, **kwargs)

    @staticmethod
    def vendor():
        return ('Cisco', 'IOS')

    @staticmethod
    def _ios_version(version_string):
        re_match = re.match(r'Cisco IOS Software, .+, Version ([^\,]+),', version_string)
        if re_match is not None:
            return re_match.groups()[0]
        return None
