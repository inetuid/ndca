import sys


class Utils(object):
    @staticmethod
    def debug(func):
        def func_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            sys.stderr.write(
                'DEBUG: {}({}, {}) = [{}][{}]\n'.format(
                    func.__name__,
                    args,
                    kwargs,
                    result,
                    result.encode('hex') if isinstance(result, str) else ''
                )
            )
            return result
        return func_wrapper

    @staticmethod
    def group_kwargs(*groups, **kwargs):
        grouped_kwargs = {}
        for key, value in kwargs.iteritems():
            for group in groups:
                group_length = len(group)
                if key.startswith(group):
                    if group not in grouped_kwargs:
                        grouped_kwargs[group] = {}
                    grouped_kwargs[group][key[group_length:]] = value
        return grouped_kwargs
