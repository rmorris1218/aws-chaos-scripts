import unittest
from unittest.mock import patch
import sys

from scripts.fail_az import *

class TestFailAz(unittest.TestCase):

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