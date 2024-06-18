import json

import yaml
import os
import requests

entryTypes = {'note': 1, 'error': 2, 'pending': 3}
formats = {'html': 'html', 'table': 'table', 'json': 'json', 'text': 'text', 'markdown': 'markdown'}

_params = {}
_args = {
}
_headers = {}
_results = {}
_errors = {}
_instance_configs = {}


def getParam(param: str):
    return _params.get(param, None)


def getArg(arg: str):
    return _args.get(arg, None)


def getHeader(header: str):
    return _headers.get(header, None)


def command():
    pass


def error(err):
    _errors.update(err)


def get_results():
    return _results


def get_errors():
    return _errors


def set_input_args(args: dict):
    _args.update(args)


def set_params(params: dict):
    _params.update(params)


def set_headers(headers: dict):
    _headers.update(headers)


def error(err):
    return {'Type': entryTypes['error'], 'Contents': str(err), 'ContentsFormat': 'text'}


def convert(results):
    """ Convert whatever result into entry """
    if type(results) is dict:
        if 'Type' in results and 'Contents' in results and 'ContentsFormat' in results:
            return results
        else:
            return {'Type': entryTypes['note'], 'Contents': json.dumps(results), 'ContentsFormat': 'json'}
    if type(results) is list:
        res = []
        for r in results:
            res.append(convert(r))
        return res
    return {'Type': entryTypes['note'], 'Contents': str(results), 'ContentsFormat': 'text'}


def results(results):
    res = []
    converted = convert(results)
    if type(converted) is list:
        res = converted
    else:
        res.append(converted)

    _results.update({'Type': 'result', 'results': res})


def isError(entry):
    """
       Check if the given entry is an error entry
       :type entry: ``dict``
       :return: True if the entry is an error entry, false otherwise
       :rtype: ``bool``
    """
    return type(entry) is dict and entry['Type'] == entryTypes['error']


def load_integration(config_file: str):
    with open(config_file) as file:
        integration_configs = yaml.load(file, Loader=yaml.FullLoader)


def load_instance(config_file: str):
    with open(config_file) as file:
        _instance_configs = yaml.load(file, Loader=yaml.FullLoader)
        if 'configuration' in _instance_configs:
            _params.update(_instance_configs.get('configuration'))


def upload_file(path, content_type):
    if not os.path.exists(path):
        raise Exception("{} is not exist".format(path))
    if content_type is None:
        content_type = "application/x-binary"

    with open(path, 'rb') as f:
        files = {
            'file': f,
            'content-type': content_type
        }
        upload_url = 'http://10.255.250.84:9333/submit'
        r = requests.post(url=upload_url, files=files, verify=False)
        if r.status_code != 201:
            raise Exception(r.status_code)
        data = r.json()
        return data.get('fid'), content_type

