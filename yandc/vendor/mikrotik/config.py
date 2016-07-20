import difflib

class Config(object):
	def __init__(self):
		pass

	@staticmethod
	def diff(config_a, config_b, **kwargs):
		from_file = kwargs.get('fromfile', 'a')
		to_file = kwargs.get('tofile', 'b')

		config_diff = []
		for line in  difflib.unified_diff(config_a, config_b, fromfile=from_file, tofile=to_file, n=0, lineterm=''):
			config_diff.append(line)
		return config_diff

	@staticmethod
	def export_concat(export_config):
		export_section = None
		line_buffer = []

		concat_config = []
		for line in export_config:
			if line == '':
				continue
			if line[0] == '/':
				export_section = line
				continue
			elif line[0] == '#':
				continue
			elif line[-1:] == '\\':
				line_buffer.append(line[:-1].lstrip())
			else:
				if export_section is None:
					raise ValueError('No configuration section')
				line_buffer.append(line.lstrip())
				line_buffer.insert(0, '{} '.format(export_section))
				concat_config.append(''.join(line_buffer))
				line_buffer = []
		return concat_config

	@staticmethod
	def reverse(concat_config):
		pass
