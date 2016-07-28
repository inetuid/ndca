from yandc_ssh import Shell as BaseShell, utils


class Shell(BaseShell):
    def tidy_output_line(self, *args, **kwargs):
        return super(Shell, self).tidy_output_line(*args, **kwargs).lstrip('\r')
