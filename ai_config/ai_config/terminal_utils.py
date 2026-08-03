import os
import pexpect
import threading

def start_shell(handle_output):
    env = os.environ.copy()
    env['TERM'] = 'xterm-256color'
    shell = pexpect.spawn('/bin/bash', ['-i'], env=env, encoding='utf-8')

    def read_output():
        try:
            while True:
                output = shell.read_nonblocking(size=1024, timeout=None)
                if output:
                    handle_output(output)
        except pexpect.exceptions.EOF:
            pass
        except Exception as e:
            print(f"read_output error: {e}")

    threading.Thread(target=read_output, daemon=True).start()

    def write_input(data):
        shell.send(data)

    return write_input, shell, shell.pid