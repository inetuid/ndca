import sys


class Utils(object):
    @staticmethod
    def debug(func):
        def func_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            hex_result = ''
            if isinstance(result, str):
                hex_result = result.encode('hex')
            elif isinstance(result, list):
                if len(result) == 1 and isinstance(result[0], str):
                    hex_result = result[0].encode('hex')
            sys.stderr.write(
                'DEBUG: {}({}, {}) = [{}][{}]\n'.format(
                    func.__name__,
                    args,
                    kwargs,
                    result,
                    hex_result
                )
            )
            return result
        return func_wrapper
