#!/usr/bin/env python3
from botocore.exceptions import ClientError
import argparse
import json
import sys
import os
import boto3
from retrying import retry
from dateutil.tz import tzutc
import datetime
import warnings
warnings.filterwarnings("ignore")

transition_states = [
    'CREATE_IN_PROGRESS', 'DELETE_IN_PROGRESS',
    'ROLLBACK_IN_PROGRESS',
    'UPDATE_IN_PROGRESS',
    'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
    'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
    'UPDATE_ROLLBACK_IN_PROGRESS',
    'REVIEW_IN_PROGRESS']

update_states = ['CREATE_COMPLETE',
                 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE']
delete_states = ['ROLLBACK_COMPLETE', 'ROLLBACK_FAILED',
                 'DELETE_FAILED', 'DELETE_COMPLETE']

# boto3.set_stream_logger('botocore', level=boto3.logging.DEBUG)


def wait_for_complete(cft_client, cft_stack_name):

    @retry(
        wait_fixed=60 * 1000,
        retry_on_result=lambda result: result is None,
        retry_on_exception=lambda ex: False)
    def wait_loop():
        stack_status = get_stack_status(cft_client, cft_stack_name)
        if stack_status not in transition_states:
            return stack_status
        print(f'StackStatus of {cft_stack_name} : {stack_status}.Waiting till State changes ..... ')

    status = wait_loop()

    return status


def get_stack_status(cft_client, cft_stack_name):

    paginator = cft_client.get_paginator('describe_stacks')

    stack_iterator = paginator.paginate()
    for response in stack_iterator:
        for stack in response['Stacks']:
            if cft_stack_name == stack['StackName']:
                return stack['StackStatus']

    return False


def role_arn_to_session(role_arn, session_name):

    lab = boto3.Session(profile_name='default')
    # role_arn = "arn:aws:iam::" + account_id + ":role/" + role_name
    client = lab.client('sts', verify=False)
    response = client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
    )
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])


def cft_create_stack(role, parameter_data, cft_params):

    cft_stack_name = parameter_data['StackName']
    cft_client = role_arn_to_session(role, 'cftsession').client(
        'cloudformation', region_name=parameter_data['RegionId'], verify=False)

    current_stack_status = get_stack_status(cft_client, cft_stack_name)

    # Validate the template before creating stacks.
    cft_validate_stack(cft_client, cft_stack_name, parameter_data, cft_params)

    if current_stack_status:
        if current_stack_status not in transition_states and current_stack_status in update_states:
            print(
                f"{cft_stack_name} will be UPDATED due to its current statue -->  {current_stack_status}")

            cft_update_stack(cft_client, cft_stack_name, parameter_data, cft_params)

        else:
            print(f"{cft_stack_name} Stack exists and couldnt be UPDATED due to its current transition/failed state --> {current_stack_status}.")

        if current_stack_status in delete_states:
            print(f"{cft_stack_name} will be DELETED due to its current state")

            cft_delete_stack(cft_client, cft_stack_name, parameter_data, cft_params)

    else:
        print(f"{cft_stack_name} being CREATED")
        try:
            response = cft_client.create_stack(
                StackName=cft_stack_name,
                TemplateURL=parameter_data['TemplateUrl'],
                Parameters=cft_params,
                OnFailure='ROLLBACK',
                Capabilities=['CAPABILITY_IAM'],
                Tags=list(parameter_data.get('Tags', ''))
            )

            if response['ResponseMetadata']['HTTPStatusCode'] == 200:

                stack_completion_status = wait_for_complete(
                    cft_client, cft_stack_name)

                if stack_completion_status == 'CREATE_COMPLETE':
                    print(
                        f'{cft_stack_name} Stack CREATED successfully.Current State {stack_completion_status}')
                else:
                    for event in cft_client.describe_stack_events(StackName=cft_stack_name)['StackEvents']:
                        del event['Timestamp']
                        print(f'{json.dumps(event,indent=2)}')
                    raise Exception(
                        f"ERROR: {cft_stack_name} Stack Couldn't be CREATED.Current State {stack_completion_status}.Stack Events logged")
            else:
                print(
                    f"{cft_stack_name} Stack Couldnt be CREATED.Error Calling API {json.dumps(response)}")

        except Exception as e:
            raise Exception("ERROR: Exception CREATING Stack", e)


def cft_update_stack(cft_client, stack_name, parameter_data, cft_params):

    try:
        response = cft_client.update_stack(
            StackName=stack_name,
            TemplateURL=parameter_data['TemplateUrl'],
            Parameters=cft_params,
            Capabilities=['CAPABILITY_IAM'],
            Tags=list(parameter_data.get('Tags', '')))

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:

            stack_completion_status = wait_for_complete(cft_client, stack_name)

            if stack_completion_status == 'UPDATE_COMPLETE':

                print(
                    f'{stack_name} Stack UPDATED successfully.Current State {stack_completion_status}')
            else:
                for event in cft_client.describe_stack_events(StackName=stack_name)['StackEvents']:
                    del event['Timestamp']
                    print(f'{json.dumps(event,indent=2)}')
                raise Exception(
                    f"ERROR: {stack_name} Stack Couldn't be UPDATED.Current State {stack_completion_status}.Stack Events logged")

        else:
            print(
                f"ERROR: {stack_name} Stack Couldnt be UPDATED.Error Calling API {json.dumps(response)}")

    except ClientError as e:
        if e.response['Error']['Message'] == 'No updates are to be performed.':
            print(f'Stack {stack_name}  Already Updated.Nothing to update')
        else:
            raise Exception(
                f"ERROR: Exception UPDATING Stack {stack_name} {e}")
    except Exception as e:
        raise Exception(f"ERROR: Exception UPDATING Stack {stack_name} :: {e}")


def cft_delete_stack(cft_client, stack_name, parameter_data, cft_params):

    try:
        response = cft_client.delete_stack(StackName=stack_name)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:

            stack_completion_status = wait_for_complete(cft_client, stack_name)

            if not stack_completion_status:
                print(f'{stack_name} Stack DELETED successfully')
            else:
                raise Exception(
                    f"ERROR: {stack_name} Stack Couldn't be DELETED.Check Stack Events.")

    except Exception as e:
        raise Exception(f"ERROR: {stack_name} Stack Couldn't be DELETED.")


def cft_validate_stack(cft_client, cft_stack_name, parameter_data, cft_params):

    print(
        f'Validating Stack {cft_stack_name} template for any Validation errors')
    try:
        response = cft_client.validate_template(
            TemplateURL=parameter_data['TemplateUrl']
        )
    except ClientError as e:
        raise Exception(
            f'ERROR: Validation error occurred in template and exception logged as : ', e)


def parse_parameters(param_file):

    try:
        with open(param_file) as f:
            parameter_data = json.load(f)
            cft_params = []
        mandatory_params = ['RegionId', 'TemplateUrl', 'StackName']
        if all(k in parameter_data for k in mandatory_params):
            for k in parameter_data.keys():
                if k not in mandatory_params and k != 'Tags':
                    cft_params.append(
                        {"ParameterKey": k, "ParameterValue": parameter_data[k]})
            return parameter_data, cft_params
        else:
            sys.exit(
                f'Mandatory parameters:{mandatory_params} are missing in Parameters file.Exiting ')
    except IOError:
        print("Error: Cant open or read file")
    except Exception as e:
        raise Exception('ERROR : Issue loading Paramater file ', e)


def main():

    parser = argparse.ArgumentParser(
        description='Deployment script parameters')

    parser.add_argument(
        '-p',
        '--params',
        dest='param_file',
        required=True,
        help="Parmater template file for CFT")
    parser.add_argument(
        '-r',
        '--role',
        dest='role',
        required=True,
        help="Role to Assume")

    args = parser.parse_args()

    parameter_data, cft_params = parse_parameters(args.param_file)

    cft_create_stack(args.role, parameter_data, cft_params)


if __name__ == '__main__':
    main()
