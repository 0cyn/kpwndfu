import os.path as path

def get_shellcode_file_path(filename):
    return path.dirname(__file__) + '/bin/' + filename