from os import path
import json

meta_file = None


def meta_for(cpid):
    global meta_file
    if not meta_file:
        with open(path.dirname(__file__) + path.sep + f'devices{path.sep}devices.json', 'r') as fp:
            meta_file = json.load(fp)
    return meta_file[cpid]
