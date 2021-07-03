from aws_cdk import (aws_iam, aws_ec2, aws_elasticloadbalancingv2, aws_events,
                     aws_events_targets, aws_lambda, aws_networkfirewall,
                     core as cdk)

LAMBDA_UPDATE_TG = '''
import os
import boto3

aes_domain = os.environ['aes_domain']
tg_arn = os.environ['tg_arn']
ec2 = boto3.client('ec2')
alb = boto3.client('elbv2')


def get_aes_ips():
    res = ec2.describe_network_interfaces(
        Filters=[{'Name': 'description', 'Values': [f'ES {aes_domain}']}])
    if res['NetworkInterfaces']:
        ips = [ojb['PrivateIpAddress'] for ojb in res['NetworkInterfaces']]
        print(f'ENI IP address for Amazon ES instances: {ips}')
        return set(ips)
    return set([])

def modify_target_ips(aes_ips):
    res = alb.describe_target_health(TargetGroupArn=tg_arn)
    registered_ips = set([])
    if res['TargetHealthDescriptions']:
        registered_ips = set(
            [ojb['Target']['Id'] for ojb in res['TargetHealthDescriptions']])
        print(f'Registered IPs: {registered_ips}')
    for ip in (aes_ips - registered_ips):
        response = alb.register_targets(
            TargetGroupArn=tg_arn, Targets=[{'Id': ip, 'Port': 443}])
        print(f'add {ip}, response: {response}')
    for ip in (registered_ips - aes_ips):
        response = alb.deregister_targets(
            TargetGroupArn=tg_arn, Targets=[{'Id': ip, 'Port': 443}])
        print(f'delete {ip}, response: {response}')


def lambda_handler(event, context):
    aes_ips = get_aes_ips()
    modify_target_ips(aes_ips)
'''


class ConfigurALB(cdk.Construct):
    def __init__(self, scope: cdk.Construct, id: str, alb_name: str,
                 subnets: list, security_groups: list, tg_name: str, vpc_id,
                 name_prefix: str, ssl_cert, **kwargs):
        super().__init__(scope, id, **kwargs)

        alb = aws_elasticloadbalancingv2.CfnLoadBalancer(
            self, 'alb', name=f'{name_prefix}{alb_name.value_as_string}',
            scheme='internet-facing', type="application",
            subnets=subnets, security_groups=security_groups
        )
        self.tg = aws_elasticloadbalancingv2.CfnTargetGroup(
            self, 'albTg', name=f'{name_prefix}{tg_name.value_as_string}',
            target_type='ip', protocol='HTTPS', port=443, vpc_id=vpc_id,
            protocol_version='HTTP1',
            health_check_enabled=True, health_check_protocol='HTTPS',
            health_check_path='/_plugin/kibana/', healthy_threshold_count=2,
            unhealthy_threshold_count=2, health_check_timeout_seconds=5,
            health_check_interval_seconds=30, matcher={"httpCode": '302'}
        )
        alb_listener = aws_elasticloadbalancingv2.CfnListener(
            self, "albListener",
            load_balancer_arn=alb.ref, port=443, protocol="HTTPS",
            default_actions=[
                aws_elasticloadbalancingv2.CfnListener.ActionProperty(
                    type='fixed-response',
                    fixed_response_config=aws_elasticloadbalancingv2.CfnListener.FixedResponseConfigProperty(
                        status_code='404',
                        message_body='Not found.'
                    )
                )
            ],
            certificates=[
                aws_elasticloadbalancingv2.CfnListener.CertificateProperty(
                    certificate_arn=ssl_cert.value_as_string)],
        )
        aws_elasticloadbalancingv2.CfnListenerRule(
            self, 'albListenerRule',
            actions=[
                aws_elasticloadbalancingv2.CfnListenerRule.ActionProperty(
                    type='forward', target_group_arn=self.tg.ref)],
            conditions=[
                aws_elasticloadbalancingv2.CfnListenerRule.RuleConditionProperty(
                    field='path-pattern',
                    path_pattern_config=aws_elasticloadbalancingv2.CfnListenerRule.PathPatternConfigProperty(
                        values=['/_plugin/kibana*']
                    )
                ),
            ],
            listener_arn=alb_listener.ref,
            priority=10
        )


class ChangeTgIPsForALB(cdk.Construct):
    def __init__(self, scope: cdk.Construct, id: str, name_prefix: str,
                 aes_name: str, tg: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        # Lambda Functions to change ip addresses of target group
        lambda_func = aws_lambda.Function(
            self, 'lambdaUpdateTg', runtime=aws_lambda.Runtime.PYTHON_3_8,
            code=aws_lambda.InlineCode(LAMBDA_UPDATE_TG),
            function_name=f'{name_prefix}update-tg-ips-for-alb',
            description='Amazon ES: update ip address of target group for ALB',
            handler='index.lambda_handler', timeout=cdk.Duration.seconds(10),
            environment={'aes_domain': aes_name, 'tg_arn': tg.ref}
        )
        lambda_func.add_to_role_policy(aws_iam.PolicyStatement(
            actions=['ec2:DescribeInternetGateways',
                     'ec2:DescribeNetworkInterfaces',
                     'ec2:DescribeSubnets',
                     'ec2:DescribeVpcs',
                     'elasticloadbalancing:DescribeTargetHealth'],
            resources=['*'],
        ))
        lambda_func.add_to_role_policy(aws_iam.PolicyStatement(
            actions=['elasticloadbalancing:DeregisterTargets',
                     'elasticloadbalancing:DescribeTargetHealth',
                     'elasticloadbalancing:RegisterTargets'],
            resources=[tg.ref],
        ))

        # EventBridge
        event_pattern = aws_events.EventPattern(
            source=["aws.ec2"],
            detail_type=["AWS API Call via CloudTrail"],
            detail={"eventSource": ["ec2.amazonaws.com"],
                    "eventName": ["CreateNetworkInterface",
                                  "DeleteNetworkInterface"],
                    "sourceIPAddress": ["es.amazonaws.com"]}
        )
        aws_events.Rule(
            self, 'eventBridgeRule', event_pattern=event_pattern,
            rule_name=f'{name_prefix}trigger-update-tg-ips-for-alb',
            description='Amazon ES: trigger lambda of update-tg-ips-for-alb',
            targets=[aws_events_targets.LambdaFunction(lambda_func)]
        )


class coreVpc(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        def name_tag(name):
            return cdk.CfnTag(key='Name', value=f'{self.name_prefix}{name}')

        # General Configuration
        self.name_aes_domain = cdk.CfnParameter(
            self, 'aesDomanName', type='String', default='aes-siem',
            description='Amazon ES Doamin Name')
        self.aes_name = self.name_aes_domain.value_as_string
        self.name_tag_prefix = cdk.CfnParameter(
            self, 'tagNamePrefix', type='String', default='amazon-es-',
            description="Tag name prefix")
        self.name_prefix = self.name_tag_prefix.value_as_string
        self.trusted_nw_1 = cdk.CfnParameter(
            self, 'trustedNw1', type='String',
            default='192.0.2.0/24',
            description='Trusted Network Address 1')
        self.trusted_nw_2 = cdk.CfnParameter(
            self, "trustedNw2", type='String',
            default='198.51.100.0/24',
            description='Trusted Network Address 2')

        # VPC
        self.vpc_name = cdk.CfnParameter(
            self, 'vpcName', type='String', default='vpc',
            description='VPC tag name')
        self.vpc_cidr = cdk.CfnParameter(
            self, 'vpcCidr', type='String', default='192.168.0.0/16',
            description='VPC CIDR Block')

        # Public Subnet 1 for ALB
        self.subnet_public_1_name = cdk.CfnParameter(
            self, 'subnetPublic1Name', type='String',
            default='subnet-public-1',
            description='Public Subnet 1 for ALB/NAT GW')
        self.subnet_public_1_cidr = cdk.CfnParameter(
            self, 'subnetPublic1Cidr', type='String',
            default='192.168.1.0/24',
            description='Public Subnet 1 CIDR Block')
        self.subnet_public_1_az = cdk.CfnParameter(
            self, "subnetPublic1Az", type="AWS::EC2::AvailabilityZone::Name",
            default='ap-northeast-1a',
            description="Public Subnet 1 Availability Zone")

        # Public Subnet 2 for ALB in another Region
        self.subnet_public_2_name = cdk.CfnParameter(
            self, 'subnetPublic2Name', type='String',
            default='subnet-public-2',
            description='Public Subnet 2 for ALB/NAT GW')
        self.subnet_public_2_cidr = cdk.CfnParameter(
            self, 'subnetPublic2Cidr', type='String',
            default='192.168.11.0/24',
            description="Public Subnet 2 CIDR Block")
        self.subnet_public_2_az = cdk.CfnParameter(
            self, "subnetPublic2Az", type="AWS::EC2::AvailabilityZone::Name",
            default='ap-northeast-1c',
            description="Public Subnet 2 Availability Zone")

        # Private Subnet for Amazon ES
        self.subnet_privte_1_name = cdk.CfnParameter(
            self, "subnetPrivate1Name", type='String',
            default='subnet-private-1',
            description='Private Subnet 1 for Amazon ES')
        self.subnet_privte_1_cidr = cdk.CfnParameter(
            self, "subnetPrivate1Cidr", type='String',
            default='192.168.2.0/24',
            description="Private Subnet 1 CIDR Block")
        self.subnet_privte_1_az = cdk.CfnParameter(
            self, "subnetPrivate1Az", type="AWS::EC2::AvailabilityZone::Name",
            default='ap-northeast-1a',
            description="Private Subnet 1 Availability Zone")

        # Gateway
        self.igw_name = cdk.CfnParameter(
            self, "igwName", type='String', default='igw',
            description="Internet Gateway Name")

        # Application Load Balancer
        self.alb_name = cdk.CfnParameter(
            self, "albName", type='String', default='alb',
            description="ALB Name")
        self.sg_alb_name = cdk.CfnParameter(
            self, "sgAlbName", type='String', default='sg-alb',
            description="Security Group Name For ALB")
        fakecert = ('arn:aws:acm:ap-northeast-1:123456789012:certificate/'
                    'uuid1234-5678-aaaa-bbbb-ddddeeeeffff')
        self.tg_name = cdk.CfnParameter(
            self, 'tgName', type='String', default='tg-aes',
            description='Target Grup Name for Amazon ES')
        self.ssl_cert = cdk.CfnParameter(
            self, 'sslCert', type='String', min_length=50,
            allowed_pattern='^arn:aws:acm:.*',
            description=(f'Default SSL certificate from ACM for ALB. '
                         f'This must be ARN format. eg) {fakecert}'))

        # Route Table
        self.rtb_public_1_name = cdk.CfnParameter(
            self, "rtbPublic1Name", type='String', default='rtb-public-1',
            description="Public Route Table Name")
        self.rtb_public_2_name = cdk.CfnParameter(
            self, "rtbPublic2Name", type='String', default='rtb-public-2',
            description="Public Route Table Name")
        self.rtb_private_name = cdk.CfnParameter(
            self, "rtbPrivateName", type='String',
            default='rtb-private',
            description="Private Route Table Name")

        # configure VPC
        self.vpc = aws_ec2.CfnVPC(
            self, 'vpc', cidr_block=self.vpc_cidr.value_as_string,
            enable_dns_hostnames=True, enable_dns_support=True,
            tags=[name_tag(self.vpc_name.value_as_string)]
        )

        # configure InternetGateway
        self.igw = aws_ec2.CfnInternetGateway(
            self, 'igw', tags=[name_tag(self.igw_name.value_as_string)])
        self.igw_attachment = aws_ec2.CfnVPCGatewayAttachment(
            self, 'igwAttachment', vpc_id=self.vpc.ref, internet_gateway_id=self.igw.ref)

        # configure Subnet
        self.subnet_public_1 = aws_ec2.CfnSubnet(
            self, 'subnetPublic1', vpc_id=self.vpc.ref,
            cidr_block=self.subnet_public_1_cidr.value_as_string,
            availability_zone=self.subnet_public_1_az.value_as_string,
            tags=[name_tag(self.subnet_public_1_name.value_as_string)]
        )
        self.subnet_public_2 = aws_ec2.CfnSubnet(
            self, "subnetPublic2", vpc_id=self.vpc.ref,
            cidr_block=self.subnet_public_2_cidr.value_as_string,
            availability_zone=self.subnet_public_2_az.value_as_string,
            tags=[name_tag(self.subnet_public_2_name.value_as_string)]
        )
        self.subnet_privte_1 = aws_ec2.CfnSubnet(
            self, "subnetPrivate1", vpc_id=self.vpc.ref,
            cidr_block=self.subnet_privte_1_cidr.value_as_string,
            availability_zone=self.subnet_privte_1_az.value_as_string,
            tags=[name_tag(self.subnet_privte_1_name.value_as_string)]
        )

        # Configure Route Table
        self.rtb_public_1 = aws_ec2.CfnRouteTable(
            self, "rtbPublic1", vpc_id=self.vpc.ref,
            tags=[name_tag(self.rtb_public_1_name.value_as_string)]
        )
        aws_ec2.CfnSubnetRouteTableAssociation(
            self, "rtbPublic1Association", route_table_id=self.rtb_public_1.ref,
            subnet_id=self.subnet_public_1.ref
        )
        self.rtb_public_2 = aws_ec2.CfnRouteTable(
            self, "rtbPublic2", vpc_id=self.vpc.ref,
            tags=[name_tag(self.rtb_public_2_name.value_as_string)]
        )
        aws_ec2.CfnSubnetRouteTableAssociation(
            self, "rtbPublic2Association", route_table_id=self.rtb_public_2.ref,
            subnet_id=self.subnet_public_2.ref
        )

        rtb_private = aws_ec2.CfnRouteTable(
            self, "rtbPriv", vpc_id=self.vpc.ref,
            tags=[name_tag(self.rtb_private_name.value_as_string)]
        )
        aws_ec2.CfnSubnetRouteTableAssociation(
            self, "rtbPrivAssociation", route_table_id=rtb_private.ref,
            subnet_id=self.subnet_privte_1.ref
        )

        # Configure Security Group
        sg_trusted_nw = aws_ec2.CfnSecurityGroup(
            self, "sgForALB", vpc_id=self.vpc.ref,
            group_description="SG For application load balancer",
            group_name=f'{self.name_prefix}{self.sg_alb_name.value_as_string}',
            security_group_ingress=[
                aws_ec2.CfnSecurityGroup.IngressProperty(
                    ip_protocol='tcp', from_port=443, to_port=443,
                    cidr_ip=self.trusted_nw_1.value_as_string),
                aws_ec2.CfnSecurityGroup.IngressProperty(
                    ip_protocol='tcp', from_port=443, to_port=443,
                    cidr_ip=self.trusted_nw_2.value_as_string),
                aws_ec2.CfnSecurityGroup.IngressProperty(
                    ip_protocol='tcp', from_port=443, to_port=443,
                    cidr_ip=self.vpc_cidr.value_as_string)],
            tags=[name_tag('sg-trusted-nw')]
        )

        # ALB
        confalb = ConfigurALB(
            self, 'configureALB', alb_name=self.alb_name, name_prefix=self.name_prefix,
            subnets=[self.subnet_public_1.ref, self.subnet_public_2.ref],
            security_groups=[sg_trusted_nw.ref], vpc_id=self.vpc.ref,
            tg_name=self.tg_name, ssl_cert=self.ssl_cert)
        # Lambda Functions to change ip addresses of target group
        ChangeTgIPsForALB(
            self, 'changeip', name_prefix=self.name_prefix,
            aes_name=self.aes_name, tg=confalb.tg)

        cdk.CfnOutput(self, "VPC-ID", value=self.vpc.ref)
        cdk.CfnOutput(self, "Subnet-Id Private1", value=self.subnet_privte_1.ref)


class VpcSingleAz(coreVpc):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        def name_tag(name):
            return cdk.CfnTag(key='Name', value=f'{self.name_prefix}{name}')

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'General Configuration'},
                     'Parameters': [self.name_aes_domain.logical_id,
                                    self.name_tag_prefix.logical_id,
                                    self.trusted_nw_1.logical_id,
                                    self.trusted_nw_2.logical_id]},
                    {'Label': {'default': 'VPC'},
                     'Parameters': [self.vpc_name.logical_id,
                                    self.vpc_cidr.logical_id]},
                    {'Label': {'default': 'Public Subnet 1 for ALB'},
                     'Parameters': [self.subnet_public_1_name.logical_id,
                                    self.subnet_public_1_cidr.logical_id,
                                    self.subnet_public_1_az.logical_id]},
                    {'Label': {'default': ('Public Subnet 2 for ALB in '
                                           'another Region')},
                     'Parameters': [self.subnet_public_2_name.logical_id,
                                    self.subnet_public_2_cidr.logical_id,
                                    self.subnet_public_2_az.logical_id]},
                    {'Label': {'default': 'Private Subnet 1 for Amazon ES'},
                     'Parameters': [self.subnet_privte_1_name.logical_id,
                                    self.subnet_privte_1_cidr.logical_id,
                                    self.subnet_privte_1_az.logical_id]},
                    {'Label': {'default': 'Gateway'},
                     'Parameters': [self.igw_name.logical_id]},
                    {'Label': {'default': 'Application Load Balancer'},
                     'Parameters': [self.alb_name.logical_id,
                                    self.tg_name.logical_id,
                                    self.sg_alb_name.logical_id,
                                    self.ssl_cert.logical_id]},
                    {'Label': {'default': 'Route Table'},
                     'Parameters': [self.rtb_public_1_name.logical_id,
                                    self.rtb_public_2_name.logical_id,
                                    self.rtb_private_name.logical_id]},
                ]
            }
        }
        aws_ec2.CfnRoute(
            self, "routePublic1", route_table_id=self.rtb_public_1.ref,
            destination_cidr_block="0.0.0.0/0", gateway_id=self.igw.ref
        )
        aws_ec2.CfnRoute(
            self, "routePublic2", route_table_id=self.rtb_public_2.ref,
            destination_cidr_block="0.0.0.0/0", gateway_id=self.igw.ref
        )


class VpcMultiAz(VpcSingleAz):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        def name_tag(name):
            return cdk.CfnTag(key='Name', value=f'{self.name_prefix}{name}')

        # Private Subnet 2 for Amazon ES
        self.subnet_privte_2_name = cdk.CfnParameter(
            self, "subnetPrivate2Name", type='String',
            default='subnet-private-2',
            description='Private Subnet 2 for Amazon ES')
        self.subnet_privte_2_cidr = cdk.CfnParameter(
            self, "subnetPrivate2Cidr", type='String',
            default='192.168.12.0/24',
            description="Private Subnet 2 CIDR Block")
        self.subnet_privte_2_az = cdk.CfnParameter(
            self, "subnetPrivate2Az", type="AWS::EC2::AvailabilityZone::Name",
            default='ap-northeast-1c',
            description="Private Subnet 2 Availability Zone")

        # Private Subnet 3 for Amazon ES
        self.subnet_privte_3_name = cdk.CfnParameter(
            self, "subnetPrivate3Name", type='String',
            default='subnet-private-3',
            description='Private Subnet 3 for Amazon ES')
        self.subnet_privte_3_cidr = cdk.CfnParameter(
            self, "subnetPrivate3Cidr", type='String',
            default='192.168.22.0/24',
            description="Private Subnet 3 CIDR Block")
        self.subnet_privte_3_az = cdk.CfnParameter(
            self, "subnetPrivate3Az", type="AWS::EC2::AvailabilityZone::Name",
            default='ap-northeast-1d',
            description="Private Subnet 3 Availability Zone")

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'General Configuration'},
                     'Parameters': [self.name_aes_domain.logical_id,
                                    self.name_tag_prefix.logical_id,
                                    self.trusted_nw_1.logical_id,
                                    self.trusted_nw_2.logical_id]},
                    {'Label': {'default': 'VPC'},
                     'Parameters': [self.vpc_name.logical_id,
                                    self.vpc_cidr.logical_id]},
                    {'Label': {'default': 'Public Subnet 1 for ALB'},
                     'Parameters': [self.subnet_public_1_name.logical_id,
                                    self.subnet_public_1_cidr.logical_id,
                                    self.subnet_public_1_az.logical_id]},
                    {'Label': {'default': ('Public Subnet 2 for ALB in '
                                           'another Region')},
                     'Parameters': [self.subnet_public_2_name.logical_id,
                                    self.subnet_public_2_cidr.logical_id,
                                    self.subnet_public_2_az.logical_id]},
                    {'Label': {'default': 'Private Subnet 1 for Amazon ES'},
                     'Parameters': [self.subnet_privte_1_name.logical_id,
                                    self.subnet_privte_1_cidr.logical_id,
                                    self.subnet_privte_1_az.logical_id]},
                    {'Label': {'default': 'Private Subnet 2 for Amazon ES'},
                     'Parameters': [self.subnet_privte_2_name.logical_id,
                                    self.subnet_privte_2_cidr.logical_id,
                                    self.subnet_privte_2_az.logical_id]},
                    {'Label': {'default': 'Private Subnet 3 for Amazon ES'},
                     'Parameters': [self.subnet_privte_3_name.logical_id,
                                    self.subnet_privte_3_cidr.logical_id,
                                    self.subnet_privte_3_az.logical_id]},
                    {'Label': {'default': 'Gateway'},
                     'Parameters': [self.igw_name.logical_id]},
                    {'Label': {'default': 'Application Load Balancer'},
                     'Parameters': [self.alb_name.logical_id,
                                    self.tg_name.logical_id,
                                    self.sg_alb_name.logical_id,
                                    self.ssl_cert.logical_id]},
                    {'Label': {'default': 'Route Table'},
                     'Parameters': [self.rtb_public_1_name.logical_id,
                                    self.rtb_public_2_name.logical_id,
                                    self.rtb_private_name.logical_id]},
                ]
            }
        }
        # configure subnet
        self.subnet_privte_2 = aws_ec2.CfnSubnet(
            self, "subnetPrivate2", vpc_id=self.vpc.ref,
            cidr_block=self.subnet_privte_2_cidr.value_as_string,
            availability_zone=self.subnet_privte_2_az.value_as_string,
            tags=[name_tag(self.subnet_privte_2_name.value_as_string)]
        )
        self.subnet_privte_3 = aws_ec2.CfnSubnet(
            self, "subnetPrivate3", vpc_id=self.vpc.ref,
            cidr_block=self.subnet_privte_3_cidr.value_as_string,
            availability_zone=self.subnet_privte_3_az.value_as_string,
            tags=[name_tag(self.subnet_privte_3_name.value_as_string)]
        )

        cdk.CfnOutput(self, "Subnet-Id Private2", value=self.subnet_privte_2.ref)
        cdk.CfnOutput(self, "Subnet-Id Private3", value=self.subnet_privte_3.ref)


class VpcSingleAzWithFw(coreVpc):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        def name_tag(name):
            return cdk.CfnTag(key='Name', value=f'{self.name_prefix}{name}')

        # Firewall Subnet
        self.subnet_fw_1_name = cdk.CfnParameter(
            self, 'subnetFw1Name', type='String',
            default='subnet-fw-1',
            description='Firewall Subnet 1 for Network Firewall endpoint')
        self.subnet_fw_1_cidr = cdk.CfnParameter(
            self, 'subnetFw1Cidr', type='String',
            default='192.168.0.0/24',
            description='Firewall Subnet 1 CIDR Block')
        self.subnet_fw_1_az = cdk.CfnParameter(
            self, "subnetFw1Az", type="AWS::EC2::AvailabilityZone::Name",
            default='ap-northeast-1a',
            description="Firewall Subnet 1 Availability Zone")

        # Network Firewall
        self.fw_name = cdk.CfnParameter(
            self, "fwName", type='String', default='fw',
            description="Network Firewall Name")
        self.fw_policy_name = cdk.CfnParameter(
            self, "fwPolicyName", type='String', default='fw-policy',
            description="Network Firewall Policy Name")
        self.fw_stateless_rule_name = cdk.CfnParameter(
            self, 'fwStateleeRuleGroupName', type='String',
            default='stateless-rule-group',
            description=('Netwok Firewall stateless rule group name to '
                         'access Kibana'))
        self.fw_stateless_rule_capacity = cdk.CfnParameter(
            self, 'fwStateleeRuleGroupCapacity', type='Number', default=1000,
            description=('Netwok Firewall capacity for stateless rule group'))

        # Route Table
        self.rtb_igw_name = cdk.CfnParameter(
            self, "rtbIgwName", type='String', default='rtb-igw',
            description="IGW Ingress Route Table Name")
        self.rtb_fw_1_name = cdk.CfnParameter(
            self, "rtbfw1Name", type='String', default='rtb-fw-1',
            description="Route Table Name For Network Firewall 1")

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'General Configuration'},
                     'Parameters': [self.name_aes_domain.logical_id,
                                    self.name_tag_prefix.logical_id,
                                    self.trusted_nw_1.logical_id,
                                    self.trusted_nw_2.logical_id]},
                    {'Label': {'default': 'VPC'},
                     'Parameters': [self.vpc_name.logical_id,
                                    self.vpc_cidr.logical_id]},
                    {'Label': {'default': 'Firewall Subnet 1'},
                     'Parameters': [self.subnet_fw_1_name.logical_id,
                                    self.subnet_fw_1_cidr.logical_id,
                                    self.subnet_fw_1_az.logical_id]},
                    {'Label': {'default': 'Public Subnet 1 for ALB'},
                     'Parameters': [self.subnet_public_1_name.logical_id,
                                    self.subnet_public_1_cidr.logical_id,
                                    self.subnet_public_1_az.logical_id]},
                    {'Label': {'default': ('Public Subnet 2 for ALB in '
                                           'another Region')},
                     'Parameters': [self.subnet_public_2_name.logical_id,
                                    self.subnet_public_2_cidr.logical_id,
                                    self.subnet_public_2_az.logical_id]},
                    {'Label': {'default': 'Private Subnet 1 for Amazon ES'},
                     'Parameters': [self.subnet_privte_1_name.logical_id,
                                    self.subnet_privte_1_cidr.logical_id,
                                    self.subnet_privte_1_az.logical_id]},
                    {'Label': {'default': 'Gateway'},
                     'Parameters': [self.igw_name.logical_id]},
                    {'Label': {'default': 'Application Load Balancer'},
                     'Parameters': [self.alb_name.logical_id,
                                    self.tg_name.logical_id,
                                    self.sg_alb_name.logical_id,
                                    self.ssl_cert.logical_id]},
                    {'Label': {'default': 'Network Firewall'},
                     'Parameters': [self.fw_name.logical_id,
                                    self.fw_policy_name.logical_id,
                                    self.fw_stateless_rule_name.logical_id,
                                    self.fw_stateless_rule_capacity.logical_id]},
                    {'Label': {'default': 'Route Table'},
                     'Parameters': [self.rtb_igw_name.logical_id,
                                    self.rtb_fw_1_name.logical_id,
                                    self.rtb_public_1_name.logical_id,
                                    self.rtb_public_2_name.logical_id,
                                    self.rtb_private_name.logical_id]},
                ]
            }
        }

        # configure
        # Subnet
        self.subnet_fw_1 = aws_ec2.CfnSubnet(
            self, 'subnetFw1', vpc_id=self.vpc.ref,
            cidr_block=self.subnet_fw_1_cidr.value_as_string,
            availability_zone=self.subnet_fw_1_az.value_as_string,
            tags=[name_tag(self.subnet_fw_1_name.value_as_string)]
        )

        # Network Firewall
        fw_stateless_rule = aws_networkfirewall.CfnRuleGroup.RuleGroupProperty(
            rule_variables=None,
            rules_source=aws_networkfirewall.CfnRuleGroup.RulesSourceProperty(
                stateless_rules_and_custom_actions=aws_networkfirewall.CfnRuleGroup.StatelessRulesAndCustomActionsProperty(
                    stateless_rules=[
                        aws_networkfirewall.CfnRuleGroup.StatelessRuleProperty(
                            priority=100,
                            rule_definition=aws_networkfirewall.CfnRuleGroup.RuleDefinitionProperty(
                                actions=['aws:pass'],
                                match_attributes=aws_networkfirewall.CfnRuleGroup.MatchAttributesProperty(
                                    protocols=[6],
                                    sources=[aws_networkfirewall.CfnRuleGroup.AddressProperty(address_definition=self.trusted_nw_1.value_as_string),
                                             aws_networkfirewall.CfnRuleGroup.AddressProperty(address_definition=self.trusted_nw_2.value_as_string)],
                                    source_ports=[aws_networkfirewall.CfnRuleGroup.PortRangeProperty(from_port=0, to_port=65535)],
                                    destinations=[aws_networkfirewall.CfnRuleGroup.AddressProperty(address_definition="0.0.0.0/0")],
                                    destination_ports=[aws_networkfirewall.CfnRuleGroup.PortRangeProperty(from_port=443, to_port=443)]
                                ))),
                        aws_networkfirewall.CfnRuleGroup.StatelessRuleProperty(
                            priority=101,
                            rule_definition=aws_networkfirewall.CfnRuleGroup.RuleDefinitionProperty(
                                actions=['aws:pass'],
                                match_attributes=aws_networkfirewall.CfnRuleGroup.MatchAttributesProperty(
                                    protocols=[6],
                                    sources=[aws_networkfirewall.CfnRuleGroup.AddressProperty(address_definition="0.0.0.0/0")],
                                    source_ports=[aws_networkfirewall.CfnRuleGroup.PortRangeProperty(from_port=443, to_port=443)],
                                    destinations=[aws_networkfirewall.CfnRuleGroup.AddressProperty(address_definition=self.trusted_nw_1.value_as_string),
                                                  aws_networkfirewall.CfnRuleGroup.AddressProperty(address_definition=self.trusted_nw_2.value_as_string)],
                                    destination_ports=[aws_networkfirewall.CfnRuleGroup.PortRangeProperty(from_port=0, to_port=65535)],
                                )))
                    ],
                    custom_actions=None
                )
            )
        )

        fw_stateless_roule_group = aws_networkfirewall.CfnRuleGroup(
            self, "fwRuleGroupToAesFromInternet",
            capacity=self.fw_stateless_rule_capacity.value_as_number,
            rule_group_name=(f'{self.name_prefix}'
                             f'{self.fw_stateless_rule_name.value_as_string}'),
            type='STATELESS',
            description='hoge',
            rule_group=fw_stateless_rule,
        )

        fw_policy = aws_networkfirewall.CfnFirewallPolicy(
            self, 'fwPolicy',
            firewall_policy_name=(f'{self.name_prefix}'
                                  f'{self.fw_policy_name.value_as_string}'),
            firewall_policy=aws_networkfirewall.CfnFirewallPolicy.FirewallPolicyProperty(
                stateless_default_actions=['aws:drop'],
                stateless_fragment_default_actions=['aws:drop'],
                stateless_rule_group_references=[
                    aws_networkfirewall.CfnFirewallPolicy.StatelessRuleGroupReferenceProperty(
                        priority=1,
                        resource_arn=fw_stateless_roule_group.attr_rule_group_arn
                    )
                ],
            )
        )
        self.fw = aws_networkfirewall.CfnFirewall(
            self, 'fw',
            firewall_name=f'{self.name_prefix}{self.fw_name.value_as_string}',
            vpc_id=self.vpc.ref,
            subnet_mappings=[
                aws_networkfirewall.CfnFirewall.SubnetMappingProperty(
                    subnet_id=self.subnet_fw_1.ref)],
            firewall_policy_arn=fw_policy.attr_firewall_policy_arn,
            description='Amazon ES: Network Firewall',
            delete_protection=False,
            firewall_policy_change_protection=False,
            subnet_change_protection=False,
        )
        self.fw_1_endpoint = f"{cdk.Fn.select(1, cdk.Fn.split(':', cdk.Fn.select(0, self.fw.attr_endpoint_ids)))}"

        # Route Table
        # for IGW
        self.rtb_igw = aws_ec2.CfnRouteTable(
            self, 'rtbIgw', vpc_id=self.vpc.ref,
            tags=[name_tag(self.rtb_igw_name.value_as_string)]
        )
        aws_ec2.CfnGatewayRouteTableAssociation(
            self, 'IgwRouteTableAssociation', gateway_id=self.igw.ref,
            route_table_id=self.rtb_igw.ref
        )
        self.route_igw_1 = aws_ec2.CfnRoute(
            self, 'routeIgw1', route_table_id=self.rtb_igw.ref,
            vpc_endpoint_id=self.fw_1_endpoint,
            destination_cidr_block=self.subnet_public_1.cidr_block,
        )
        self.route_igw_2 = aws_ec2.CfnRoute(
            self, 'routeIgw2', route_table_id=self.rtb_igw.ref,
            vpc_endpoint_id=self.fw_1_endpoint,
            destination_cidr_block=self.subnet_public_2.cidr_block,
        )

        # For FW Subnet
        self.rtb_fw_1 = aws_ec2.CfnRouteTable(
            self, "rtbFw1", vpc_id=self.vpc.ref,
            tags=[name_tag(self.rtb_fw_1_name.value_as_string)]
        )
        aws_ec2.CfnSubnetRouteTableAssociation(
            self, 'fwRouteTable1Association', route_table_id=self.rtb_fw_1.ref,
            subnet_id=self.subnet_fw_1.ref
        )
        aws_ec2.CfnRoute(
            self, "routeFw1", route_table_id=self.rtb_fw_1.ref,
            destination_cidr_block="0.0.0.0/0", gateway_id=self.igw.ref
        )

        # For Public
        self.route_public_1 = aws_ec2.CfnRoute(
            self, "routePublic1", route_table_id=self.rtb_public_1.ref,
            vpc_endpoint_id=self.fw_1_endpoint,
            destination_cidr_block="0.0.0.0/0"
        )
        self.route_public_2 = aws_ec2.CfnRoute(
            self, "routePublic2", route_table_id=self.rtb_public_2.ref,
            vpc_endpoint_id=self.fw_1_endpoint,
            destination_cidr_block="0.0.0.0/0"
        )


class VpcMultiAzWithFw(VpcSingleAzWithFw):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        def name_tag(name):
            return cdk.CfnTag(key='Name', value=f'{self.name_prefix}{name}')

        # Route Table
        self.rtb_fw_2_name = cdk.CfnParameter(
            self, "rtbfw2Name", type='String', default='rtb-fw-2',
            description="Route Table Name For Network Firewall")

        # Firewall Subnet 2
        self.subnet_fw_2_name = cdk.CfnParameter(
            self, 'subnetFw2Name', type='String',
            default='subnet-fw-2',
            description='Firewall Subnet 2 for Network Firewall endpoint')
        self.subnet_fw_2_cidr = cdk.CfnParameter(
            self, 'subnetFw2Cidr', type='String',
            default='192.168.10.0/24',
            description='Firewall Subnet 2 CIDR Block')
        self.subnet_fw_2_az = cdk.CfnParameter(
            self, "subnetFw2Az", type="AWS::EC2::AvailabilityZone::Name",
            default='ap-northeast-1c',
            description="Firewall Subnet 2 Availability Zone. "
                        "Select another region")

        # Private Subnet 2 for Amazon ES
        self.subnet_privte_2_name = cdk.CfnParameter(
            self, "subnetPrivate2Name", type='String',
            default='subnet-private-2',
            description='Private Subnet 2 for Amazon ES')
        self.subnet_privte_2_cidr = cdk.CfnParameter(
            self, "subnetPrivate2Cidr", type='String',
            default='192.168.12.0/24',
            description="Private Subnet 2 CIDR Block")
        self.subnet_privte_2_az = cdk.CfnParameter(
            self, "subnetPrivate2Az", type="AWS::EC2::AvailabilityZone::Name",
            default='ap-northeast-1c',
            description="Private Subnet 2 Availability Zone")

        # Private Subnet 3 for Amazon ES
        self.subnet_privte_3_name = cdk.CfnParameter(
            self, "subnetPrivate3Name", type='String',
            default='subnet-private-3',
            description='Private Subnet 3 for Amazon ES')
        self.subnet_privte_3_cidr = cdk.CfnParameter(
            self, "subnetPrivate3Cidr", type='String',
            default='192.168.22.0/24',
            description="Private Subnet 3 CIDR Block")
        self.subnet_privte_3_az = cdk.CfnParameter(
            self, "subnetPrivate3Az", type="AWS::EC2::AvailabilityZone::Name",
            default='ap-northeast-1d',
            description="Private Subnet 3 Availability Zone")

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'General Configuration'},
                     'Parameters': [self.name_aes_domain.logical_id,
                                    self.name_tag_prefix.logical_id,
                                    self.trusted_nw_1.logical_id,
                                    self.trusted_nw_2.logical_id]},
                    {'Label': {'default': 'VPC'},
                     'Parameters': [self.vpc_name.logical_id,
                                    self.vpc_cidr.logical_id]},
                    {'Label': {'default': 'Firewall Subnet 1'},
                     'Parameters': [self.subnet_fw_1_name.logical_id,
                                    self.subnet_fw_1_cidr.logical_id,
                                    self.subnet_fw_1_az.logical_id]},
                    {'Label': {'default': ('Firewall Subnet 2 in '
                                           'another region')},
                     'Parameters': [self.subnet_fw_2_name.logical_id,
                                    self.subnet_fw_2_cidr.logical_id,
                                    self.subnet_fw_2_az.logical_id]},
                    {'Label': {'default': 'Public Subnet 1 for ALB'},
                     'Parameters': [self.subnet_public_1_name.logical_id,
                                    self.subnet_public_1_cidr.logical_id,
                                    self.subnet_public_1_az.logical_id]},
                    {'Label': {'default': ('Public Subnet 2 for ALB in '
                                           'another Region')},
                     'Parameters': [self.subnet_public_2_name.logical_id,
                                    self.subnet_public_2_cidr.logical_id,
                                    self.subnet_public_2_az.logical_id]},
                    {'Label': {'default': 'Private Subnet 1 for Amazon ES'},
                     'Parameters': [self.subnet_privte_1_name.logical_id,
                                    self.subnet_privte_1_cidr.logical_id,
                                    self.subnet_privte_1_az.logical_id]},
                    {'Label': {'default': 'Private Subnet 2 for Amazon ES'},
                     'Parameters': [self.subnet_privte_2_name.logical_id,
                                    self.subnet_privte_2_cidr.logical_id,
                                    self.subnet_privte_2_az.logical_id]},
                    {'Label': {'default': 'Private Subnet 3 for Amazon ES'},
                     'Parameters': [self.subnet_privte_3_name.logical_id,
                                    self.subnet_privte_3_cidr.logical_id,
                                    self.subnet_privte_3_az.logical_id]},
                    {'Label': {'default': 'Gateway'},
                     'Parameters': [self.igw_name.logical_id]},
                    {'Label': {'default': 'Application Load Balancer'},
                     'Parameters': [self.alb_name.logical_id,
                                    self.tg_name.logical_id,
                                    self.sg_alb_name.logical_id,
                                    self.ssl_cert.logical_id]},
                    {'Label': {'default': 'Network Firewall'},
                     'Parameters': [self.fw_name.logical_id,
                                    self.fw_policy_name.logical_id,
                                    self.fw_stateless_rule_name.logical_id,
                                    self.fw_stateless_rule_capacity.logical_id]},
                    {'Label': {'default': 'Route Table'},
                     'Parameters': [self.rtb_igw_name.logical_id,
                                    self.rtb_fw_1_name.logical_id,
                                    self.rtb_fw_2_name.logical_id,
                                    self.rtb_public_1_name.logical_id,
                                    self.rtb_public_2_name.logical_id,
                                    self.rtb_private_name.logical_id]},
                ]
            }
        }

        # configure
        # Subnet
        self.subnet_fw_2 = aws_ec2.CfnSubnet(
            self, 'subnetFw2', vpc_id=self.vpc.ref,
            cidr_block=self.subnet_fw_2_cidr.value_as_string,
            availability_zone=self.subnet_fw_2_az.value_as_string,
            tags=[name_tag(self.subnet_fw_2_name.value_as_string)]
        )
        self.subnet_privte_2 = aws_ec2.CfnSubnet(
            self, "subnetPrivate2", vpc_id=self.vpc.ref,
            cidr_block=self.subnet_privte_2_cidr.value_as_string,
            availability_zone=self.subnet_privte_2_az.value_as_string,
            tags=[name_tag(self.subnet_privte_2_name.value_as_string)]
        )
        self.subnet_privte_3 = aws_ec2.CfnSubnet(
            self, "subnetPrivate3", vpc_id=self.vpc.ref,
            cidr_block=self.subnet_privte_3_cidr.value_as_string,
            availability_zone=self.subnet_privte_3_az.value_as_string,
            tags=[name_tag(self.subnet_privte_3_name.value_as_string)]
        )

        # firewall
        self.fw.subnet_mappings = [aws_networkfirewall.CfnFirewall.SubnetMappingProperty(subnet_id=self.subnet_fw_1.ref),
                                   aws_networkfirewall.CfnFirewall.SubnetMappingProperty(subnet_id=self.subnet_fw_2.ref)]
        self.fw_2_endpoint = f"{cdk.Fn.select(1, cdk.Fn.split(':', cdk.Fn.select(1, self.fw.attr_endpoint_ids)))}"

        # Route Table
        # For IGW
        self.route_igw_2.vpc_endpoint_id = self.fw_2_endpoint

        # For FW Subnet
        self.rtb_fw_2 = aws_ec2.CfnRouteTable(
            self, "rtbFw2", vpc_id=self.vpc.ref,
            tags=[name_tag(self.rtb_fw_2_name.value_as_string)]
        )
        aws_ec2.CfnSubnetRouteTableAssociation(
            self, 'fwRouteTable2Association', route_table_id=self.rtb_fw_2.ref,
            subnet_id=self.subnet_fw_2.ref
        )
        aws_ec2.CfnRoute(
            self, "routeFw2", route_table_id=self.rtb_fw_2.ref,
            destination_cidr_block="0.0.0.0/0", gateway_id=self.igw.ref
        )

        # For Public
        self.route_public_2.vpc_endpoint_id = self.fw_2_endpoint

        cdk.CfnOutput(
            self, "Subnet-Id Private2", value=self.subnet_privte_2.ref)
        cdk.CfnOutput(
            self, "Subnet-Id Private3", value=self.subnet_privte_3.ref)
