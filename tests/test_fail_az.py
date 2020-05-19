import unittest
from unittest.mock import patch
import sys

import boto3
from botocore.stub import Stubber

from scripts.fail_az import *

class TestFailAz(unittest.TestCase):

    def setUp(self):
        self.ec2_client = boto3.client('ec2', region_name='us-east-1')
        self.ec2_stub = Stubber(self.ec2_client)

    def test_get_arguments_defaults(self):
        test_args = ["script-fail-az", "--region", "region-1", "--vpc-id", "vpc-xxx", "--az-name", "region-1a"]
        with patch.object(sys, 'argv', test_args):
            args = get_arguments()
            assert args.region == "region-1"
            assert args.vpc_id == "vpc-xxx"
            assert args.az_name == "region-1a"
            assert args.duration == 60
            assert args.limit_asg == False
            assert args.failover_rds == False
            assert args.failover_elasticache == False
            assert args.log_level == "INFO"

    def test_get_subnets_to_chaos(self):
        expected_params = {
            'Filters': [
                {'Name': 'availability-zone', 'Values': ['us-east-0a']},
                {'Name': 'vpc-id', 'Values': ['vpc-xxx']}
            ] 
        }
        sample_response = {
            'Subnets': [
                {'SubnetId': 'subnet-yyy'}
            ]
        }
        self.ec2_stub.add_response('describe_subnets', sample_response, expected_params)
        self.ec2_stub.activate()

        subnet_ids = get_subnets_to_chaos(self.ec2_client, vpc_id='vpc-xxx', az_name='us-east-0a')
        assert subnet_ids[0] == 'subnet-yyy'
    
    def test_create_chaos_nacl(self):
        create_nacl_expected_params = dict(VpcId="vpc-xxx")
        create_nacl_response = {
            'NetworkAcl': {
                'NetworkAclId': 'nacl-yyy'
            }
        }
        self.ec2_stub.add_response('create_network_acl', create_nacl_response, create_nacl_expected_params)
        create_tags_expected_params = dict(Resources=['nacl-yyy'], Tags=[{'Key':'Name','Value':'chaos-kong'}])
        create_tags_response = {}
        self.ec2_stub.add_response('create_tags', create_tags_response, create_tags_expected_params)
        egress_block_expected_params = dict(CidrBlock="0.0.0.0/0", Egress=True, PortRange={'From': 0, 'To': 65535}, NetworkAclId='nacl-yyy', Protocol="-1", RuleAction='deny', RuleNumber=100)
        egress_block_response = {}
        self.ec2_stub.add_response('create_network_acl_entry', egress_block_response, egress_block_expected_params)
        ingress_block_expected_params = dict(CidrBlock="0.0.0.0/0", Egress=False, PortRange={'From': 0, 'To': 65535}, NetworkAclId='nacl-yyy', Protocol="-1", RuleAction='deny', RuleNumber=101)
        ingress_block_response = {}
        self.ec2_stub.add_response('create_network_acl_entry', ingress_block_response, ingress_block_expected_params)
        
        self.ec2_stub.activate()
        nacl_id = create_chaos_nacl(self.ec2_client, "vpc-xxx")