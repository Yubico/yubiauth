__all__ = [
    'setting'
]

from yubiauth.config import settings


class setting(object):
    """
    Runs a block of code with specific settings.
    After the block has run, the original settings are restored.
    Usage:
        with setting(key1=value1, key2=value2):
            ...
            <code with settings set>
            ...
    """
    def __init__(self, **kwargs):
        self.settings = kwargs
        self.original_settings = {}
        for key in self.settings:
            self.original_settings[key] = settings[key]

    def __enter__(self):
        for key, value in self.settings.items():
            settings[key] = value

    def __exit__(self, type, value, traceback):
        for key, value in self.original_settings.items():
            settings[key] = value
