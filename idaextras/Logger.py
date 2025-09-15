class Logger(object):
    def __init__(self):
        pass

    def log(self, plugin_name, section, message, address=None):
        print(f'[*] IDAExtras - {plugin_name} - {section} {"(" + hex(address) + ")" if address else ""}: {message}')
