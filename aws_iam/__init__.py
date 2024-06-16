import boto3
from botocore.config import Config
import urllib3
from requests.exceptions import HTTPError, Timeout, ConnectionError

import orenctl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AwsIAM(object):
    def __init__(self, region: str, access_key: str, secret_key: str, proxy: str = None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.proxy_dict = {}
        if proxy:
            self.proxy_dict = {
                "http": proxy,
                "https": proxy
            }

    def create_client(self):
        try:
            boto_config = None
            if self.proxy_dict:
                boto_config = Config(proxies=self.proxy_dict)
            client = boto3.client('iam', region_name=self.region, aws_access_key_id=self.access_key,
                                  aws_secret_access_key=self.secret_key, config=boto_config)
            return client
        except (HTTPError, Timeout, ConnectionError) as e:
            raise e
        except Exception as e:
            raise Exception('Could not create boto3 client: {0}'.format(e))


def delete_access_key():
    kwargs = {
        'AccessKeyId': orenctl.getArg('access_key_id'),
        'UserName': orenctl.getArg('username')
    }
    try:
        iam = AwsIAM(orenctl.getParam("region"), orenctl.getParam("access_key"),
                     orenctl.getParam("secret_key"), orenctl.getParam("proxy"))
        client = iam.create_client()
        response = client.delete_access_key(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            orenctl.results({
                "status": "Success",
                "result":"The Access Key was deleted"
            })
        else:
            orenctl.results({
                "status": "Fail",
                "result": f"status_code: {response['ResponseMetadata']['HTTPStatusCode']}, error: {response['ResponseMetadata']}"
            })
    except HTTPError as http_err:
        orenctl.results(orenctl.error("HTTPError: {}".format(http_err)))
    except Timeout as timeout_err:
        orenctl.results(orenctl.error("TimeoutError: {}".format(timeout_err)))
    except ConnectionError as conn_err:
        orenctl.results(orenctl.error("ConnectionError: {}".format(conn_err)))
    except Exception as ex:
        orenctl.results(orenctl.error(ex.__str__()))


if orenctl.command() == "delete_access_key":
    delete_access_key()

