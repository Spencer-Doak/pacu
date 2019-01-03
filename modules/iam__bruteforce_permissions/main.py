#!/usr/bin/env python3
"""Module to Bruceforce IAM permissions."""
import argparse
import json
import os
import re
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, ParamValidationError

from . import param_generator

module_info = {
    'name': 'iam__bruteforce_permissions',
    'author': (
        'Alexander Morgenstern at RhinoSecurityLabs. '
        'Slight edits by Spencer-Doak.'
    ),
    'category': 'ENUM',
    'one_liner': 'Enumerates permissions using brute force',
    'description': (
        'This module will automatically run through all possible API calls of '
        'supported services in order to enumerate permissions without the use '
        ' of the IAM API.'
    ),
    'services': ['all'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--services'],
}


parser = argparse.ArgumentParser(
    add_help=False,
    description=module_info['description']
)
parser.add_argument(
    '--services',
    required=False,
    default=None,
    help='A comma separated list of services to brute force permissions'
)

SUPPORTED_SERVICES = [
    'ec2',
    's3',
]

current_client = None
current_region = None
current_service = None

summary_data = {}

_STAR_SEPARATORS = '*' * 25


def complete_service_list():
    """Return a list of all supported boto3 services."""
    session = boto3.session.Session()
    return session.get_available_services()


def missing_param(param):
    """Set param to 'dummy_data'."""
    out = {param: 'dummy_data'}
    return out


def invalid_param(valid_type):
    """Return an object matching the requested valid type."""
    print('Checking for invalid types')
    types = {
        'datetime.datetime': datetime(2015, 1, 1),
        'list': ['test'],
        'int': 1,
        'dict': {},
        'bool': True
    }
    return types[valid_type]


def error_delegator(error):
    """Process complete error message.

    Trims the error response to not overwrite missing data with a valid type
    error.
    """
    kwargs = {}
    # Ignore first line of error message and process in reverse order.
    err_msg_lines = str(error).split('\n')[::-1][:-1]
    for line in err_msg_lines:
        print('    Processing Line: {}'.format(line))
        if 'Missing required parameter in input' in line:
            if line[line.find('"') + 1:-1] not in kwargs.keys():
                d_missed_params = missing_param(line.split()[-1][1:-1])
                kwargs = {
                    **kwargs,
                    **d_missed_params
                }
        elif 'Missing required parameter in' in line:
            # Grabs the parameter to build a dictionary of
            dict_name = line.split(':')[0].split()[-1]
            if '[' in dict_name:
                # Need to populate missing parameters for a sub type
                param = dict_name[:dict_name.find('.')]
                sub_param = dict_name[
                    dict_name.find('.') + 1:dict_name.find('[')
                ]
                missing_parameter = line[line.find('"') + 1:-1]
                kwargs.update(
                    {
                        param: {
                            sub_param: [
                                missing_param(missing_parameter)
                            ]
                        }
                    }
                )
            else:
                param = line.split(':')[1].strip()[1:-1]
                if dict_name not in kwargs:
                    kwargs = {dict_name: {param: ''}}
                else:
                    kwargs[dict_name].update({param: ''})

        elif 'Invalid type for parameter' in line:
            param_name = line.split()[4][:-1]
            if '.' in param_name:
                # This invalid type is a sub type within a parameter
                dict_name = param_name.split('.')[0]
                param_name = param_name.split('.')[1]
                if '[' in param_name:
                    # The invalid parameter is a list, within a dict within
                    # another dict.
                    param_name = param_name[:param_name.find('[')]
                    valid_type = line.split("'")[3]
                    temp_dict = {param_name: [invalid_param(valid_type)]}
                else:
                    # The invalid parameter is a basic key value
                    valid_type = line.split("'")[-2]
                    temp_dict = {param_name: invalid_param(valid_type)}
                if dict_name not in kwargs:
                    kwargs.update({dict_name: temp_dict})
                else:
                    kwargs[dict_name].update(temp_dict)
            else:
                # Convert list of strings to list of dicts if invalid list
                # subtype found.
                if param_name[:-3] == '[0]':
                    kwargs[param_name] = [{'DryRun': True}]
                else:
                    valid_type = line.split("'")[3]
                    kwargs[param_name] = invalid_param(valid_type)
    return kwargs


def generate_preload_actions():
    """Retrieve list of Preloaded Actions for use within KWArgs.

    Certain actions require parameters that cannot be easily discerned from the
    error message provided by preloading kwargs for those actions.
    """
    module_dir = os.path.dirname(__file__)
    path = os.path.join(module_dir, 'preload_actions.json')
    with open(path) as actions_file:
        data = actions_file.read()
    return json.loads(data)


def read_only_function(service, func):
    """Return boolean indicating if a given action is read-only.

    By verifying actions being ran are ReadOnlyAccess, the module can minimize
    unexpecteed changes to the AWS enviornment.
    """
    module_dir = os.path.dirname(__file__)
    path = os.path.join(module_dir, 'ReadOnlyAccessPolicy.json')
    with open(path) as file:
        data = json.load(file)
        formatted_func = service + ':' + camel_case(func)
        for action in data['Statement'][0]['Action']:
            if re.match(action, formatted_func) is not None:
                return True
    return False


def valid_func(service, func):
    """Return False for service functions that don't use an AWS API action."""
    if func[0] == '_':
        return False
    BAD_FUNCTIONS = [
        # Common boto3 methods.
        'can_paginate',
        'get_waiter',
        'waiter_names',
        'get_paginator',
        'generate_presigned_url',
        'generate_presigned_post',
        'exceptions',
        'meta',

        # S3 Function to manage multipart uploads.
        'list_parts',
    ]
    if func in BAD_FUNCTIONS:
        return False
    return read_only_function(service, func)


def convert_special_params(func, kwargs):
    """Perform additional argument parsing to substitute dummy_data.

    Certain actions go through additional argument parsing. If such a case
    exists, the dummy_data will be filled with valid data so that the action
    can successfully pass validation and reach and query correctly determine
    authorization.
    """
    SPECIAL_PARAMS = [
        'Bucket',
        'Attribute',
        'Key',
    ]
    # Filter list
    for param in kwargs:
        # If the parameter is not 'dummy_data', then we do not need to look for
        # substitutions and we can continue forward to the next parameter.
        if kwargs[param] != 'dummy_data':
            continue

        if param in SPECIAL_PARAMS:
            print('      Found special param')
            kwargs[param] = param_generator.get_special_param(
                current_client,
                func,
                param
            )
            if kwargs[param] is None:
                print('    Failed to fill in a valid special parameter.')
                return False
            else:
                print('    Successfully filled in valid special parameter.')
                return True

    print('    No special paramaters found for function: {}'.format(func))
    return False


def build_service_list(services=None):
    """Return a list of valid services."""
    if not services:
        return SUPPORTED_SERVICES

    unsupported_services = [
        service for service in services if service not in SUPPORTED_SERVICES
    ]
    summary_data['unsupported'] = unsupported_services

    unknown_services = [
        service for service in unsupported_services
        if service not in complete_service_list()
    ]
    summary_data['unknown'] = unknown_services
    service_list = [
        service for service in services if service in SUPPORTED_SERVICES
    ]
    return service_list


def error_code_special_parameter(code):
    """Detemine if an error code is a special type."""
    COMMON_CODE_AFFIXES = [
        'Malformed',
        'NotFound',
        'Unknown',
        'NoSuch',
        '404',
    ]
    if code == 'InvalidRequest':
        return True
    elif code == 'InvalidParameterValue':
        return True
    elif any(word in code for word in COMMON_CODE_AFFIXES):
        return True
    else:
        return False


def exception_handler(func, kwargs, error):
    """Handle exceptions to output useful info."""
    if isinstance(error, ParamValidationError):
        if 'Unknown parameter in input: "DryRun"' in str(error):
            print('DryRun failed. Retrying without DryRun parameter')
            del kwargs['DryRun']
        else:
            _AvZ_CONST = 'AvailabilityZone'
            if _AvZ_CONST not in kwargs and _AvZ_CONST in str(error):
                print("Adding Availability Zone")
                kwargs[_AvZ_CONST] = current_region + 'a'
            else:
                print('Parameter Validation Error: {}'.format(error))
                kwargs.update(error_delegator(error))
    elif isinstance(error, ClientError):
        # Error with request raised.
        print('ClientError: {}'.format(error))
        code = error.response['Error']['Code']
        ACCESS_DENIED_RESP_CODES = [
            'AccessDeniedException',
            'OptInRequired',
        ]
        if code in ACCESS_DENIED_RESP_CODES or 'Unauthorized' in str(error):
            print(
                'Unauthorized for permission: {}:{}'.format(
                    current_service,
                    func
                )
            )
            return True
        elif code == 'MissingParameter':
            param = str(error).split()[-1]
            param = param[0].upper() + param[1:]
            kwargs.update(**missing_param(param))
        # If action is not supported, skip.
        elif code == 'UnsupportedOperation':
            return True
        elif error_code_special_parameter(code):
            print('  Special Parameter Found')
            if not convert_special_params(func, kwargs):
                print('    No suitable valid data could be found')
                return True
        else:
            print('Unknown error:')
            print(error)
            return True
    elif isinstance(error, TypeError):
        if 'unexpected keyword argument \'DryRun\'' in str(error):
            print('  DryRun failed. Retrying without DryRun parameter')
            del kwargs['DryRun']
        elif 'required positional argument' in str(error):
            param = str(error).split()[-1]
            param = param[1:-1]
            kwargs.update(**missing_param(param))
        else:
            print(
                'Unknown Error. Type: {} Full: {}'.format(
                    type(error), str(error)
                )
            )
    else:
        print(
            'Unknown Error. Type: {} Full: {}'.format(
                type(error), str(error)
            )
        )
    return False


def valid_exception(error):
    """Determine if Exception type/message indicates successful authorization.

    There are certain Exceptions raised that indicate successful authorization.
    This method will return True if one of those Exceptions is raised
    """
    VALID_EXCEPTIONS = [
        'DryRunOperation',
        # S3
        'NoSuchCORSConfiguration',
        'ServerSideEncryptionConfigurationNotFoundError',
        'NoSuchConfiguration',
        'NoSuchLifecycleConfiguration',
        'ReplicationConfigurationNotFoundError',
        'NoSuchTagSet',
        'NoSuchWebsiteConfiguration',
        'NoSuchKey',

        # EC2
        'InvalidTargetArn.Unknown',
    ]
    for exception in VALID_EXCEPTIONS:
        if exception in str(error):
            return True
    return False


def main(args, pacu_main):
    """Handle main orchestration of IAM Bruteforce module."""
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print

    preload_actions = generate_preload_actions()
    # Build out the service list, or use provided list if present.
    service_list = build_service_list(
        args.services.split(',') if args.services else []
    )

    summary_data['services'] = service_list
    allow_permissions = {}
    deny_permissions = {}

    for service in service_list:
        global current_service
        current_service = service
        allow_permissions[service] = []
        deny_permissions[service] = []

        # Only checking against 'us-east-1'.
        # TODO: To store more granular permission the DB needs to be changed.
        regions = ['us-east-1']
        for region in regions:
            global current_region
            current_region = region
            global current_client
            current_client = pacu_main.get_boto3_client(service, region)
            functions = [
                func for func in dir(current_client)
                if valid_func(service, func)
            ]
            index = 1
            for func in functions:
                print(
                    _STAR_SEPARATORS +
                    'NEW FUNCTION({}/{})'.format(index, len(functions)) +
                    _STAR_SEPARATORS
                )
                index += 1
                kwargs = {}
                if func in preload_actions:
                    preload_actions[func]

                # TODO, prepend DryRun argument only when it is accepted.
                kwargs['DryRun'] = True
                while True:
                    # Note: 57 seems really arbitrary, but this is the value
                    # that was present before.
                    print('-' * 57)
                    print('Trying {}...'.format(func))
                    print('Kwargs: {}'.format(kwargs))
                    caller = getattr(current_client, func)
                    try:
                        caller(**kwargs)
                        allow_permissions[service].append(func)
                        print('Authorization exists for: {}'.format(func))
                        break
                    except Exception as error:
                        if valid_exception(error):
                            allow_permissions[service].append(func)
                            print('Authorization exists for: {}'.format(func))
                            break
                        elif exception_handler(func, kwargs, error):
                            deny_permissions[service].append(func)
                            break
                print(
                    _STAR_SEPARATORS +
                    'END FUNCTION' +
                    _STAR_SEPARATORS +
                    '\n'
                )

    print('Allowed Permissions: \n')
    print_permissions(allow_permissions)
    print('Denied Permissions: \n')
    print_permissions(deny_permissions)

    # Condenses the following dicts to a list that fits the standard
    # "service:Action" format.
    if allow_permissions:
        full_allow = [
            service + ':' + camel_case(perm)
            for perm in allow_permissions[service]
            for service in allow_permissions
        ]
    if deny_permissions:
        full_deny = [
            service + ':' + camel_case(perm)
            for perm in deny_permissions[service]
            for service in deny_permissions
        ]

    active_aws_key = session.get_active_aws_key(pacu_main.database)
    active_aws_key.update(
        pacu_main.database,
        allow_permissions=full_allow,
        deny_permissions=full_deny
    )

    summary_data['allow'] = sum(
        [len(allow_permissions[region]) for region in allow_permissions]
    )
    summary_data['deny'] = sum(
        [len(deny_permissions[region]) for region in deny_permissions]
    )

    return summary_data


def print_permissions(permission_dict):
    """Help print permissions."""
    for service in permission_dict:
        print('  {}:'.format(service))
        for action in permission_dict[service]:
            print('    {}'.format(action))
        print('')


def camel_case(name):
    """Help snake_case to CamelCase."""
    split_name = name.split('_')
    return ''.join([name[0].upper() + name[1:] for name in split_name])


def summary(data, pacu_main):
    """Summarize results of module's run."""
    out = 'Services: \n'
    out += '  Supported: {}.\n'.format(data['services'])
    if 'unsupported' in data:
        out += '  Unsupported: {}.\n'.format(data['unsupported'])
    if 'unknown' in data:
        out += '  Unknown: {}.\n'.format(data['unknown'])
    out += '{} allow permissions found.\n'.format(data['allow'])
    out += '{} deny permissions found.\n'.format(data['deny'])
    return out
