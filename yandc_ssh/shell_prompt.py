"""Shell prompt class for SSH Client"""

import re
#
from .exception import PromptError


class ShellPrompt(object):
    """Prompt handling class for Shell"""
    def __init__(self, prompt=None):
        self.prompts = {}
        if prompt is not None:
            self.add_prompt(prompt)

    def __repr__(self):
        return '{}.prompts={}'.format(type(self).__name__, repr(self.prompts))

    def add_prompt(self, prompt):
        if isinstance(prompt, basestring):
            if prompt not in self.prompts:
                self.prompts[prompt] = {
                    'prompt_type': basestring,
                    'prompt_value': prompt
                }
        elif isinstance(prompt, dict):
            if 'prompt_type' in prompt and 'prompt_value' in prompt:
                if prompt['prompt_value'] not in self.prompts:
                    self.prompts[prompt['prompt_value']] = prompt
            else:
                raise PromptError('Invalid prompt specified')
        else:
            raise PromptError('Unsupported prompt type - [{}]'.format(type(prompt)))

    def is_prompt(self, candidate_prompt):
        if candidate_prompt in self.prompts and \
                self.prompts[candidate_prompt]['prompt_type'] is basestring:
            return True
        for prompt in self.prompts.values():
            if prompt['prompt_type'] is basestring:
                continue
            elif prompt['prompt_type'] == 'regexp':
                if re.match(prompt['prompt_regexp'], candidate_prompt):
                    return True
            else:
                raise PromptError(
                    'Unsupported prompt type - [{}]'.format(prompt['prompt_type'])
                )
        return False

    @staticmethod
    def regexp_prompt(re_prompt):
        return {
            'prompt_type': 'regexp',
            'prompt_value': re_prompt,
            'prompt_regexp': re.compile(re_prompt)
        }
