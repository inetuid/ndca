import re
#
from yandc_ssh import Shell as BaseShell


class Shell(BaseShell):
    def __init__(self, *args, **kwargs):
        self.output_re_sub_regexp = re.compile(r'{}\[(9999B|c)'.format(chr(0x1B)))
        super(Shell, self).__init__(*args, **kwargs)

    def on_output_line(self, *args, **kwargs):
        return re.sub(
            self.output_re_sub_regexp,
            '',
            super(Shell, self).on_output_line(*args, **kwargs)
        ).lstrip('\r')
