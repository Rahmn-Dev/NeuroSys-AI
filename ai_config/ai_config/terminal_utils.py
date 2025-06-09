import pexpect
import threading

def start_shell(handle_output):
    shell = pexpect.spawn('/bin/bash', ['-i'], encoding='utf-8', echo=False)

    def read_output():
        try:
            while True:
                output = shell.readline()
                if output:
                    handle_output(output)
        except pexpect.exceptions.EOF:
            pass
        except Exception as e:
            print(f"read_output error: {e}")

    threading.Thread(target=read_output, daemon=True).start()

    def write_input(data):
        shell.send(data)
        if not data.endswith('\n'):
            shell.send('\n')

    return write_input, shell