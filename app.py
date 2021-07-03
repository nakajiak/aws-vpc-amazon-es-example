#!/usr/bin/env python3

import os

from aws_cdk import core as cdk

from aws_vpc_amazon_es_example.aws_vpc_amazon_es_example_stack import (
    VpcMultiAz, VpcMultiAzWithFw, VpcSingleAz, VpcSingleAzWithFw)

app = cdk.App()
VpcSingleAz(app, 'vpc-single-az',
            description=('SIEM on Amazon ES: VPC, Single AZ, ALB, '
                         'to access from internet'))
VpcMultiAz(app, 'vpc-multi-az',
           description=('SIEM on Amazon ES: VPC, Multi AZ, ALB, '
                        'to access from internet'))
VpcSingleAzWithFw(app, 'vpc-single-az-with-fw',
                  description=('SIEM on Amazon ES: VPC, Single AZ, ALB, '
                               'Network Firewall to access from internet'))
VpcMultiAzWithFw(app, 'vpc-multi-az-with-fw',
                 description=('SIEM on Amazon ES: VPC, Mult AZ, ALB, '
                              'Network Firewall to access from internet'))

app.synth()
