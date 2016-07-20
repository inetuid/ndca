import re
#
from yandc import ssh


class Shell(ssh.Shell):
	control_char_regexp = re.compile(r'{}\[(9999B|c)'.format(chr(0x1B)))

	def on_output_line(self, *args, **kwargs):
		return re.sub(
			Shell.control_char_regexp,
			'',
			super(Shell, self).on_output_line(*args, **kwargs)
		).lstrip('\r')
