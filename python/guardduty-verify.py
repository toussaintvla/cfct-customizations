# ©2021 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#
# This AWS Content is provided subject to the terms of the AWS Customer Agreement
# available at http://aws.amazon.com/agreement or other written agreement between
# Customer and either Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.
"""
The purpose of this script is to check if GuarDuty is enabled in all regions within a delegated admin account:
Settings verified:
  auto-enable = True
  s3 auto-enable = True

Run the script within the AWS Organization management account with a role that can assume the AWSControlTowerExecution
role

usage: python3 guardduty-org-config-verify.py
"""
import argparse
import boto3
import logging

from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time as now

# Logging Settings
LOGGER = logging.getLogger()
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
logging.getLogger("s3transfer").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

SESSION = boto3.Session()
STS_CLIENT = boto3.client('sts')
AWS_PARTITION = "aws"
ASSUME_ROLE_NAME = "AWSControlTowerExecution"  # Change if cross account role is different in the AWS Organization
MAX_THREADS = 16


def assume_role(aws_account_number, role_name, session_name):
    """
    Assumes the provided role in the provided account and returns a session
    :param aws_account_number: AWS Account Number
    :param role_name: Role name to assume in target account
    :param session_name: Session name
    :return: session for the account and role name
    """
    try:
        response = STS_CLIENT.assume_role(
            RoleArn=f"arn:{AWS_PARTITION}:iam::{aws_account_number}:role/{role_name}",
            RoleSessionName=session_name,
        )
        # Storing STS credentials
        session = boto3.Session(
            aws_access_key_id=response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
            aws_session_token=response["Credentials"]["SessionToken"],
        )
        LOGGER.debug(f"Assumed session for {aws_account_number}")

        return session
    except Exception as ex:
        LOGGER.info(f"Unexpected error: {ex}")
        raise ValueError("Error assuming role") from ex


def get_all_organization_accounts(account_info: bool):
    """
    Gets a list of active AWS Accounts in the AWS Organization
    :param account_info: True = return account info dict, False = return account id list
    :return: accounts dict or account_id list
    """
    accounts = []  # used for create_members
    account_ids = []  # used for disassociate_members

    try:
        organizations = boto3.client("organizations")
        paginator = organizations.get_paginator("list_accounts")

        for page in paginator.paginate(PaginationConfig={"PageSize": 20}):
            for acct in page["Accounts"]:
                account_record = {"AccountId": acct["Id"], "Email": acct["Email"]}
                accounts.append(account_record)
                account_ids.append(acct["Id"])
    except ClientError as ex:
        LOGGER.info(f"get_all_organization_accounts error: {ex}")
        raise ValueError("Error getting accounts") from ex
    except Exception as ex:
        LOGGER.info(f"get_all_organization_accounts error: {ex}")
        raise ValueError("Unexpected error getting accounts") from ex

    if account_info:
        return accounts

    return account_ids


def is_region_available(region):
    """
    Check if the region is available
    :param region:
    :return:
    """
    regional_sts = boto3.client('sts', region_name=region)
    try:
        regional_sts.get_caller_identity()
        return True
    except Exception as error:
        if "InvalidClientTokenId" in str(error):
            LOGGER.info(f"Region: {region} is not available")
        elif "endpoint" in str(error):
            LOGGER.info(f"Could not connect to the sts endpoint for the {region} region.")
            LOGGER.debug(f"{error}")
        else:
            LOGGER.error(f"{error}")
        return False


def get_available_service_regions(user_regions: str, aws_service: str,
                                  control_tower_regions_only: bool = False) -> list:
    """
    Get the available regions for the AWS service
    :param: user_regions
    :param: aws_service
    :param: control_tower_regions_only
    :return: available region list
    """
    avail_regions = []
    try:
        if user_regions.strip():
            LOGGER.info(f"USER REGIONS: {str(user_regions)}")
            service_regions = [value.strip() for value in user_regions.split(",") if value != '']
        elif control_tower_regions_only:
            cf_client = SESSION.client('cloudformation')
            paginator = cf_client.get_paginator("list_stack_instances")
            region_set = set()
            for page in paginator.paginate(
                    StackSetName="AWSControlTowerBP-BASELINE-CLOUDWATCH"
            ):
                for summary in page["Summaries"]:
                    region_set.add(summary["Region"])
            service_regions = list(region_set)
        else:
            service_regions = boto3.session.Session().get_available_regions(
                aws_service
            )
        LOGGER.info(f"REGIONS: {service_regions}")
    except ClientError as ex:
        LOGGER.info(f"get_available_service_regions error: {ex}")
        raise ValueError("Error getting service regions") from ex

    for region in service_regions:
        if is_region_available(region):
            avail_regions.append(region)

    LOGGER.info(f"AVAILABLE REGIONS: {avail_regions}")
    LOGGER.info(f"{len(avail_regions)} Available regions found")
    return avail_regions


def get_service_client(aws_service: str, aws_region: str, session=None):
    """
    Get boto3 client for an AWS service
    :param session:
    :param aws_service:
    :param aws_region:
    :return: service client
    """
    if aws_region:
        if session:
            service_client = session.client(aws_service, region_name=aws_region)
        else:
            service_client = boto3.client(aws_service, aws_region)
    else:
        if session:
            service_client = session.client(aws_service)
        else:
            service_client = boto3.client(aws_service)
    return service_client


def get_guardduty_delegated_admin():
    """
    Get GuardDuty delegated admin
    :return: delegated_admin
    """
    guardduty_client = boto3.client('guardduty')
    response = guardduty_client.list_organization_admin_accounts()

    if len(response['AdminAccounts']) != 1:
        LOGGER.info(f"Expecting 1 Delegated admin. Found: {len(response['AdminAccounts'])}")
        return None
    delegated_admin = response['AdminAccounts'][0]['AdminAccountId']
    LOGGER.info(f'Delegated GuardDuty Admin Acct: {delegated_admin}')
    return delegated_admin


def get_account_config(account_id, regions, assume_role_name):
    """
    get account config
    :param account_id:
    :param regions:
    :param assume_role_name:
    :return:
    """
    try:
        session = assume_role(account_id, assume_role_name, "guardduty_check")
    except Exception as error:
        session = None
        LOGGER.error(f"Unable to assume {assume_role_name} in {account_id}")
        exit(0)

    region_count = 0
    s3logs_count = 0
    detector_count = 0

    for region in regions:
        region_count += 1
        session_config = get_service_client("guardduty", region, session)
        response = session_config.list_detectors()

        if len(response['DetectorIds']) == 0:
            LOGGER.info(f"no detector found in {account_id} in {region}")
            continue

        detector_count += 1
        member_detector_id = response['DetectorIds'][0]
        member_info = session_config.get_detector(DetectorId=member_detector_id)
        s3_logs = member_info['DataSources']['S3Logs']['Status']

        if s3_logs == "ENABLED":
            s3logs_count += 1
        else:
            LOGGER.info(f"{account_id} in {region} does NOT have S3 enabled")
    return account_id, region_count, s3logs_count, detector_count


def get_member_configs(regions, account_ids, assume_role_name):
    """
    Get member GuardDuty configs
    :param regions:
    :param account_ids:
    :param assume_role_name:
    :return: total_s3logs_count
    :return: total_regions_count
    :return: total_detector_count
    """
    total_regions_count = 0
    total_s3logs_count = 0
    total_detector_count = 0

    start = now()
    processes = []
    if MAX_THREADS > len(account_ids):
        thread_cnt = len(account_ids) - 2
    else:
        thread_cnt = MAX_THREADS

    with ThreadPoolExecutor(max_workers=thread_cnt) as executor:
        for account_id in account_ids:
            try:
                processes.append(executor.submit(
                    get_account_config,
                    account_id,
                    regions,
                    assume_role_name
                ))
            except Exception as error:
                LOGGER.error(f"{error}")
                continue

    for task in as_completed(processes, timeout=300):
        account_id, region_count, s3logs_count, detector_count = task.result()
        LOGGER.info(f"{account_id} S3 Summary: S3 Enabled in {s3logs_count} out of {region_count} regions")
        total_regions_count += region_count
        total_s3logs_count += s3logs_count
        total_detector_count += detector_count

    LOGGER.info(f"...Time taken to get member account configs: {now() - start}")

    return total_s3logs_count, total_regions_count, total_detector_count


def get_region_config(region, session_client):
    """
    get region config
    :param region:
    :param session_client:
    :return:
    """
    response = session_client.list_detectors()
    is_auto_enabled = False
    is_s3_auto_enabled = False

    if len(response['DetectorIds']) == 0:
        LOGGER.info(f"No detector found for Delegated Admin account in {region}")
    else:
        detector_id = response['DetectorIds'][0]
        org_config = session_client.describe_organization_configuration(DetectorId=detector_id)
        auto_enable = org_config['AutoEnable']
        s3_auto_enable = org_config['DataSources']['S3Logs']['AutoEnable']

        if auto_enable:
            is_auto_enabled = True
        else:
            LOGGER.info(f'AutoEnable not enabled in {region}')

        if s3_auto_enable:
            is_s3_auto_enabled = True
        else:
            LOGGER.info(f'S3 AutoEnable not enabled in {region}')

    return region, is_auto_enabled, is_s3_auto_enabled


def get_security_gd_config(available_regions, delegated_admin_account, assume_role_name):
    """
    Gets and returns GuardDuty org configuration
    :param available_regions:
    :param delegated_admin_account:
    :param assume_role_name:
    :return: s3_autoenabled, s3_not_autoenabled, autoenabled, not_autoenabled
    """
    try:
        session = assume_role(delegated_admin_account, ASSUME_ROLE_NAME, "guardduty_check")
    except Exception as error:
        session = None
        LOGGER.error(f"Unable to assume {assume_role_name} in {delegated_admin_account}")
        exit(0)

    start = now()
    processes = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for region in available_regions:
            try:
                session_client = get_service_client("guardduty", region, session)
                processes.append(executor.submit(
                    get_region_config,
                    region,
                    session_client
                ))
            except Exception as error:
                LOGGER.info(f"{error}")
                raise

    s3_auto_enabled_cnt = 0
    auto_enabled_cnt = 0
    region_cnt = len(available_regions)

    for task in as_completed(processes, timeout=60):
        region, is_auto_enabled, is_s3_auto_enabled = task.result()
        if is_auto_enabled:
            auto_enabled_cnt += 1

        if is_s3_auto_enabled:
            s3_auto_enabled_cnt += 1

    not_s3_auto_enabled_cnt = region_cnt - s3_auto_enabled_cnt
    not_auto_enabled_cnt = region_cnt - auto_enabled_cnt

    LOGGER.info(f"...Time taken to get security account configs: {now() - start}")

    LOGGER.info("\n## GuardDuty Delegated Admin Configuration Summary ##")
    LOGGER.info(f"AutoEnable: {auto_enabled_cnt} Regions Enabled. {not_auto_enabled_cnt} Regions Not Enabled")
    LOGGER.info(f"S3 AutoEnable: {s3_auto_enabled_cnt} Regions Enabled. {not_s3_auto_enabled_cnt} "
                f"Regions Not Enabled\n")

    return s3_auto_enabled_cnt, not_s3_auto_enabled_cnt, auto_enabled_cnt, not_auto_enabled_cnt


def get_guardduty_org_config_status(args):
    """
    get_guardduty_org_config_status
    :param args:
    :return:
    """
    org_accounts = get_all_organization_accounts(False)
    LOGGER.info(f"Account IDS: {org_accounts}")
    user_regions = args.regions
    assume_role_name = args.assume_role_name

    if not assume_role_name:
        assume_role_name = ASSUME_ROLE_NAME

    available_regions = get_available_service_regions(user_regions, "guardduty", False)

    delegated_admin_account = get_guardduty_delegated_admin()

    auto_enabled_cnt = 0
    not_auto_enabled_cnt = 0
    not_s3_auto_enabled_cnt = 0
    s3_auto_enabled_cnt = 0

    if delegated_admin_account:
        s3_auto_enabled_cnt, not_s3_auto_enabled_cnt, auto_enabled_cnt, not_auto_enabled_cnt = get_security_gd_config(
            available_regions, delegated_admin_account, assume_role_name)

    LOGGER.info("\n-Iterating Through member Accounts and Regions to check individual detector configurations-")

    total_s3logs_count, total_regions_count, total_detector_count = get_member_configs(available_regions, org_accounts,
                                                                                       assume_role_name)

    LOGGER.info('\n########## Summary ##########\n')
    LOGGER.info(f'GuardDuty Delegated Admin Account: {delegated_admin_account}\n')
    LOGGER.info("### Delegated Admin Account Guard Duty Configuration ###")

    if delegated_admin_account:
        LOGGER.info(f"AutoEnable: {auto_enabled_cnt} Regions Enabled. {not_auto_enabled_cnt} Regions Not Enabled")
        LOGGER.info(f"S3 AutoEnable: {s3_auto_enabled_cnt} Regions Enabled. {not_s3_auto_enabled_cnt} "
                    f"Regions Not Enabled")
    else:
        LOGGER.info("...NO DELEGATED ADMIN FOUND FOR GUARDDUTY")

    LOGGER.info("\n### Member Account Summary ###")
    LOGGER.info(f"{total_detector_count} detectors found out of expected {len(available_regions) * len(org_accounts)}")
    LOGGER.info(f"{total_s3logs_count} out of {total_detector_count} found detectors have S3 protection enabled\n")


if __name__ == "__main__":
    # Set Log Level
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Provides the current GuardDuty configuration status for all accounts '
                                                 'in an AWS Organization')
    parser.add_argument('--regions', dest="regions", type=str, required=False, default="",
                        help="Comma delimited list of regions to check configurations. "
                             "Leave blank for all available regions.")
    parser.add_argument('--assume_role_name', dest="assume_role_name", type=str, required=False,
                        default="AWSControlTowerExecution",
                        help="Role to assume in each account to get the GuardDuty configurations")
    args = parser.parse_args()

    get_guardduty_org_config_status(args)

