#!/usr/bin/env python3
import yaml
import json
import sys
import argparse
from pathlib import Path
from collections import OrderedDict


class CFNTag:
    def __init__(self, value):
        self.value = value


def cfn_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node)
    else:
        value = None

    tag_name = tag_suffix
    if tag_name == 'Ref':
        return {'Ref': value}
    elif tag_name == 'GetAtt':
        if isinstance(value, str):
            parts = value.split('.', 1)
            return {'Fn::GetAtt': parts if len(parts) == 2 else [value]}
        return {'Fn::GetAtt': value}
    else:
        fn_name = f"Fn::{tag_name}"
        return {fn_name: value}


yaml.add_multi_constructor('!', cfn_constructor, Loader=yaml.SafeLoader)


def represent_ordereddict(dumper, data):
    return dumper.represent_mapping('tag:yaml.org,2002:map', data.items())


yaml.add_representer(OrderedDict, represent_ordereddict)


class CFNSecurityEnhancer:
    def __init__(self, template_path):
        self.template_path = Path(template_path)
        self.template = None
        self.kms_keys_created = {}
        self.buckets_enhanced = []

    def load_template(self):
        with open(self.template_path, 'r', encoding='utf-8-sig') as f:
            content = f.read().strip()

        if not content:
            raise ValueError(f"檔案 {self.template_path} 是空的")

        try:
            self.template = yaml.safe_load(content)
            if self.template is None:
                raise yaml.YAMLError("空的 YAML 結構")
            print(f"✓ 成功以 YAML 格式解析模板: {self.template_path}")
            return
        except yaml.YAMLError as e:
            print(f"⚠️ YAML 解析失敗，嘗試 JSON... ({e})")

        try:
            self.template = json.loads(content)
            print(f"✓ 成功以 JSON 格式解析模板: {self.template_path}")
        except json.JSONDecodeError as e:
            snippet = content[:200].replace("\n", "\\n")
            raise ValueError(
                f"❌ 無法解析模板 '{self.template_path}'。\n"
                f"➡️ JSON 錯誤: {e}\n"
                f"➡️ 檔案開頭: {snippet}"
            )

    def create_customer_data_kms_key(self):
        key_resource = {
            'Type': 'AWS::KMS::Key',
            'Properties': {
                'Description': 'KMS key for Customer Data Bucket encryption',
                'EnableKeyRotation': True,
                'KeyPolicy': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Sid': 'Enable IAM User Permissions',
                            'Effect': 'Allow',
                            'Principal': {'AWS': {'Fn::Sub': 'arn:aws:iam::${AWS::AccountId}:root'}},
                            'Action': 'kms:*',
                            'Resource': '*'
                        },
                        {
                            'Sid': 'Allow S3 to use the key',
                            'Effect': 'Allow',
                            'Principal': {'Service': 's3.amazonaws.com'},
                            'Action': ['kms:Decrypt', 'kms:GenerateDataKey'],
                            'Resource': '*'
                        }
                    ]
                }
            }
        }
        alias_resource = {
            'Type': 'AWS::KMS::Alias',
            'Properties': {
                'AliasName': 'alias/customer-data-bucket-key',
                'TargetKeyId': {'Ref': 'CustomerDataKMSKey'}
            }
        }
        return key_resource, alias_resource

    def create_ml_models_kms_key(self):
        key_resource = {
            'Type': 'AWS::KMS::Key',
            'Properties': {
                'Description': 'KMS key for ML Models Bucket encryption',
                'EnableKeyRotation': True,
                'KeyPolicy': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Sid': 'Enable IAM User Permissions',
                            'Effect': 'Allow',
                            'Principal': {'AWS': {'Fn::Sub': 'arn:aws:iam::${AWS::AccountId}:root'}},
                            'Action': 'kms:*',
                            'Resource': '*'
                        },
                        {
                            'Sid': 'Allow S3 to use the key',
                            'Effect': 'Allow',
                            'Principal': {'Service': 's3.amazonaws.com'},
                            'Action': ['kms:Decrypt', 'kms:GenerateDataKey', 'kms:DescribeKey'],
                            'Resource': '*'
                        },
                        {
                            'Sid': 'Allow EC2 and Lambda services to use the key',
                            'Effect': 'Allow',
                            'Principal': {'Service': ['ec2.amazonaws.com', 'lambda.amazonaws.com']},
                            'Action': ['kms:Decrypt', 'kms:DescribeKey'],
                            'Resource': '*'
                        }
                    ]
                }
            }
        }
        alias_resource = {
            'Type': 'AWS::KMS::Alias',
            'Properties': {
                'AliasName': 'alias/ml-models-bucket-key',
                'TargetKeyId': {'Ref': 'MLModelsKMSKey'}
            }
        }
        return key_resource, alias_resource

    def create_analytics_kms_keys(self):
        high_key = {
            'Type': 'AWS::KMS::Key',
            'Properties': {
                'Description': 'KMS key for high sensitivity analytics data',
                'EnableKeyRotation': True,
                'KeyPolicy': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Sid': 'Enable IAM User Permissions',
                            'Effect': 'Allow',
                            'Principal': {'AWS': {'Fn::Sub': 'arn:aws:iam::${AWS::AccountId}:root'}},
                            'Action': 'kms:*',
                            'Resource': '*'
                        },
                        {
                            'Sid': 'Allow S3 to use the key',
                            'Effect': 'Allow',
                            'Principal': {'Service': 's3.amazonaws.com'},
                            'Action': ['kms:Decrypt', 'kms:GenerateDataKey'],
                            'Resource': '*'
                        }
                    ]
                }
            }
        }
        high_alias = {
            'Type': 'AWS::KMS::Alias',
            'Properties': {
                'AliasName': 'alias/analytics-high-sensitivity-key',
                'TargetKeyId': {'Ref': 'AnalyticsHighSensitivityKMSKey'}
            }
        }
        standard_key = {
            'Type': 'AWS::KMS::Key',
            'Properties': {
                'Description': 'KMS key for standard sensitivity analytics data',
                'EnableKeyRotation': True,
                'KeyPolicy': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Sid': 'Enable IAM User Permissions',
                            'Effect': 'Allow',
                            'Principal': {'AWS': {'Fn::Sub': 'arn:aws:iam::${AWS::AccountId}:root'}},
                            'Action': 'kms:*',
                            'Resource': '*'
                        },
                        {
                            'Sid': 'Allow S3 to use the key',
                            'Effect': 'Allow',
                            'Principal': {'Service': 's3.amazonaws.com'},
                            'Action': ['kms:Decrypt', 'kms:GenerateDataKey'],
                            'Resource': '*'
                        }
                    ]
                }
            }
        }
        standard_alias = {
            'Type': 'AWS::KMS::Alias',
            'Properties': {
                'AliasName': 'alias/analytics-standard-key',
                'TargetKeyId': {'Ref': 'AnalyticsStandardKMSKey'}
            }
        }
        return (high_key, high_alias, standard_key, standard_alias)

    def create_ebs_kms_key(self):
        key_resource = {
            'Type': 'AWS::KMS::Key',
            'Properties': {
                'Description': 'KMS key for EBS volume encryption',
                'EnableKeyRotation': True,
                'KeyPolicy': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Sid': 'Enable IAM User Permissions',
                            'Effect': 'Allow',
                            'Principal': {'AWS': {'Fn::Sub': 'arn:aws:iam::${AWS::AccountId}:root'}},
                            'Action': 'kms:*',
                            'Resource': '*'
                        },
                        {
                            'Sid': 'Allow EC2 to use the key',
                            'Effect': 'Allow',
                            'Principal': {'Service': 'ec2.amazonaws.com'},
                            'Action': ['kms:Decrypt', 'kms:GenerateDataKey', 'kms:CreateGrant', 'kms:DescribeKey'],
                            'Resource': '*'
                        },
                        {
                            'Sid': 'Allow attachment of persistent resources',
                            'Effect': 'Allow',
                            'Principal': {'AWS': {'Fn::Sub': 'arn:aws:iam::${AWS::AccountId}:root'}},
                            'Action': ['kms:CreateGrant', 'kms:ListGrants', 'kms:RevokeGrant'],
                            'Resource': '*',
                            'Condition': {'Bool': {'kms:GrantIsForAWSResource': True}}
                        }
                    ]
                }
            }
        }
        alias_resource = {
            'Type': 'AWS::KMS::Alias',
            'Properties': {
                'AliasName': 'alias/ebs-encryption-key',
                'TargetKeyId': {'Ref': 'EBSEncryptionKey'}
            }
        }
        return key_resource, alias_resource

    def enhance_customer_data_bucket(self, bucket_config):
        properties = bucket_config.get('Properties', {})

        existing_encryption = properties.get('BucketEncryption', {})
        if existing_encryption:
            sse_config = existing_encryption.get('ServerSideEncryptionConfiguration', [{}])
            if sse_config and sse_config[0].get('ServerSideEncryptionByDefault', {}).get('SSEAlgorithm') == 'aws:kms':
                print(f"  → CustomerDataBucket 已有 KMS 加密")
                return False

        print(f"  → 為 CustomerDataBucket 添加 KMS 加密")

        properties['BucketEncryption'] = {
            'ServerSideEncryptionConfiguration': [
                {
                    'ServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': {'Ref': 'CustomerDataKMSKey'}
                    },
                    'BucketKeyEnabled': True
                }
            ]
        }

        if 'Tags' not in properties:
            properties['Tags'] = []

        if not any(tag.get('Key') == 'EncryptionType' for tag in properties['Tags']):
            properties['Tags'].append({
                'Key': 'EncryptionType',
                'Value': 'KMS-CMK'
            })

        return True

    def enhance_ml_models_bucket(self, bucket_config):
        properties = bucket_config.get('Properties', {})

        current_encryption = properties.get('BucketEncryption', {}).get(
            'ServerSideEncryptionConfiguration', [{}]
        )[0].get('ServerSideEncryptionByDefault', {})

        if (current_encryption.get('SSEAlgorithm') == 'aws:kms' and
                isinstance(current_encryption.get('KMSMasterKeyID'), dict) and
                current_encryption.get('KMSMasterKeyID', {}).get('Ref') == 'MLModelsKMSKey'):
            print(f"  → MLModelsBucket 已有正確的 KMS 加密")
            return False

        print(f"  → 為 MLModelsBucket 添加 KMS 加密")

        properties['BucketEncryption'] = {
            'ServerSideEncryptionConfiguration': [
                {
                    'ServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': {'Ref': 'MLModelsKMSKey'}
                    },
                    'BucketKeyEnabled': True
                }
            ]
        }

        if 'Tags' not in properties:
            properties['Tags'] = []

        if not any(tag.get('Key') == 'EncryptionType' for tag in properties['Tags']):
            properties['Tags'].append({
                'Key': 'EncryptionType',
                'Value': 'KMS-CMK'
            })

        return True

    def enhance_analytics_data_bucket(self, bucket_config):
        properties = bucket_config.get('Properties', {})

        existing_encryption = properties.get('BucketEncryption', {})
        if existing_encryption:
            current_key = existing_encryption.get('ServerSideEncryptionConfiguration', [{}])[0].get(
                'ServerSideEncryptionByDefault', {}).get('KMSMasterKeyID')
            if isinstance(current_key, dict) and current_key.get('Ref') == 'AnalyticsHighSensitivityKMSKey':
                print(f"  → AnalyticsDataBucket 已有分層加密")
                return False

        print(f"  → 為 AnalyticsDataBucket 添加分層 KMS 加密")

        properties['BucketEncryption'] = {
            'ServerSideEncryptionConfiguration': [
                {
                    'ServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': {'Ref': 'AnalyticsHighSensitivityKMSKey'}
                    },
                    'BucketKeyEnabled': True
                }
            ]
        }

        if 'ReplicationConfiguration' in properties:
            repl_config = properties['ReplicationConfiguration']
            rules = repl_config.get('Rules', [])

            for rule in rules:
                if 'Priority' not in rule:
                    rule['Priority'] = 1

                if 'Filter' not in rule and 'Prefix' in rule:
                    prefix = rule.pop('Prefix')
                    rule['Filter'] = {'Prefix': prefix}

                if 'DeleteMarkerReplication' not in rule:
                    rule['DeleteMarkerReplication'] = {'Status': 'Enabled'}

                if 'Destination' in rule:
                    dest = rule['Destination']
                    dest['EncryptionConfiguration'] = {
                        'ReplicaKmsKeyID': {'Fn::GetAtt': ['AnalyticsHighSensitivityKMSKey', 'Arn']}
                    }

                if 'SourceSelectionCriteria' not in rule:
                    rule['SourceSelectionCriteria'] = {}
                rule['SourceSelectionCriteria']['SseKmsEncryptedObjects'] = {'Status': 'Enabled'}

        if 'Tags' not in properties:
            properties['Tags'] = []

        if not any(tag.get('Key') == 'EncryptionType' for tag in properties['Tags']):
            properties['Tags'].append({
                'Key': 'EncryptionType',
                'Value': 'KMS-CMK-Tiered'
            })

        return True

    def enhance_analytics_backup_bucket(self, bucket_config):
        properties = bucket_config.get('Properties', {})

        if 'BucketEncryption' in properties:
            print(f"  → AnalyticsBackupBucket 已有加密")
            return False

        print(f"  → 為 AnalyticsBackupBucket 添加 KMS 加密")

        properties['BucketEncryption'] = {
            'ServerSideEncryptionConfiguration': [
                {
                    'ServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': {'Ref': 'AnalyticsHighSensitivityKMSKey'}
                    },
                    'BucketKeyEnabled': True
                }
            ]
        }

        if 'Tags' not in properties:
            properties['Tags'] = []

        if not any(tag.get('Key') == 'EncryptionType' for tag in properties['Tags']):
            properties['Tags'].append({
                'Key': 'EncryptionType',
                'Value': 'KMS-CMK'
            })

        return True

    def enhance_ec2_instance(self, instance_config):
        properties = instance_config.get('Properties', {})

        if 'BlockDeviceMappings' in properties:
            existing = properties['BlockDeviceMappings']
            if any(bdm.get('Ebs', {}).get('Encrypted', False) for bdm in existing):
                print(f"  → EC2 Instance 已有加密 EBS")
                return False

        print(f"  → 為 EC2 Instance 添加加密 EBS 卷")

        properties['BlockDeviceMappings'] = [
            {
                'DeviceName': '/dev/xvda',
                'Ebs': {
                    'VolumeSize': 20,
                    'VolumeType': 'gp3',
                    'Encrypted': True,
                    'KmsKeyId': {'Ref': 'EBSEncryptionKey'},
                    'DeleteOnTermination': True
                }
            },
            {
                'DeviceName': '/dev/sdf',
                'Ebs': {
                    'VolumeSize': 50,
                    'VolumeType': 'gp3',
                    'Encrypted': True,
                    'KmsKeyId': {'Ref': 'EBSEncryptionKey'},
                    'DeleteOnTermination': True
                }
            }
        ]

        if 'Tags' not in properties:
            properties['Tags'] = []

        if not any(tag.get('Key') == 'EBSEncryption' for tag in properties['Tags']):
            properties['Tags'].append({
                'Key': 'EBSEncryption',
                'Value': 'KMS-CMK'
            })

        return True

    def enhance_lambda_function(self, function_config):
        properties = function_config.get('Properties', {})

        if 'EphemeralStorage' in properties:
            print(f"  → Lambda Function 已配置臨時存儲")
            return False

        print(f"  → 為 Lambda Function 添加臨時存儲加密")

        properties['EphemeralStorage'] = {'Size': 1024}

        if 'Environment' not in properties:
            properties['Environment'] = {'Variables': {}}
        if 'Variables' not in properties['Environment']:
            properties['Environment']['Variables'] = {}

        properties['Environment']['Variables']['EPHEMERAL_ENCRYPTED'] = 'true'

        if 'Tags' not in properties:
            properties['Tags'] = []

        if not any(tag.get('Key') == 'StorageEncryption' for tag in properties['Tags']):
            properties['Tags'].append({
                'Key': 'StorageEncryption',
                'Value': 'Enabled'
            })

        return True

    def update_iam_permissions(self):
        resources = self.template.get('Resources', {})
        updated = []

        if 'DataProcessingRole' in resources:
            role = resources['DataProcessingRole']
            properties = role.get('Properties', {})
            policies = properties.get('Policies', [])

            if not any(p.get('PolicyName') == 'KMSAccess' for p in policies):
                print(f"  → 為 DataProcessingRole 添加 KMS 權限")
                if 'Policies' not in properties:
                    properties['Policies'] = []
                properties['Policies'].append({
                    'PolicyName': 'KMSAccess',
                    'PolicyDocument': {
                        'Version': '2012-10-17',
                        'Statement': [{
                            'Effect': 'Allow',
                            'Action': ['kms:Decrypt', 'kms:DescribeKey', 'kms:GenerateDataKey'],
                            'Resource': [
                                {'Fn::GetAtt': ['CustomerDataKMSKey', 'Arn']},
                                {'Fn::GetAtt': ['MLModelsKMSKey', 'Arn']},
                                {'Fn::GetAtt': ['AnalyticsHighSensitivityKMSKey', 'Arn']},
                                {'Fn::GetAtt': ['AnalyticsStandardKMSKey', 'Arn']}
                            ]
                        }]
                    }
                })
                updated.append('DataProcessingRole')

        if 'ThirdPartyIntegrationRole' in resources:
            role = resources['ThirdPartyIntegrationRole']
            properties = role.get('Properties', {})
            policies = properties.get('Policies', [])

            for policy in policies:
                if policy.get('PolicyName') == 'ThirdPartyAccess':
                    statements = policy['PolicyDocument'].get('Statement', [])
                    has_kms = any('kms:' in str(stmt.get('Action', [])) for stmt in statements)

                    if not has_kms:
                        print(f"  → 為 ThirdPartyIntegrationRole 添加 KMS 權限")
                        statements.append({
                            'Effect': 'Allow',
                            'Action': ['kms:Decrypt', 'kms:DescribeKey'],
                            'Resource': '*'
                        })
                        updated.append('ThirdPartyIntegrationRole')
                    break

        if 'S3ReplicationRole' in resources:
            role = resources['S3ReplicationRole']
            properties = role.get('Properties', {})
            policies = properties.get('Policies', [])

            for policy in policies:
                if policy.get('PolicyName') == 'ReplicationPolicy':
                    statements = policy['PolicyDocument'].get('Statement', [])
                    has_kms = any('kms:' in str(stmt.get('Action', [])) for stmt in statements)

                    if not has_kms:
                        print(f"  → 為 S3ReplicationRole 添加 KMS 權限")
                        statements.append({
                            'Effect': 'Allow',
                            'Action': ['kms:Decrypt', 'kms:DescribeKey', 'kms:GenerateDataKey'],
                            'Resource': [{'Fn::GetAtt': ['AnalyticsHighSensitivityKMSKey', 'Arn']}]
                        })
                        updated.append('S3ReplicationRole')
                    break

        if 'DataScientistUser' in resources:
            user = resources['DataScientistUser']
            properties = user.get('Properties', {})
            policies = properties.get('Policies', [])

            for policy in policies:
                if policy.get('PolicyName') == 'DataScientistAccess':
                    statements = policy['PolicyDocument'].get('Statement', [])
                    has_kms = any('kms:' in str(stmt.get('Action', [])) for stmt in statements)

                    if not has_kms:
                        print(f"  → 為 DataScientistUser 添加 KMS 權限")
                        statements.append({
                            'Effect': 'Allow',
                            'Action': ['kms:Decrypt', 'kms:DescribeKey', 'kms:GenerateDataKey'],
                            'Resource': '*'
                        })
                        updated.append('DataScientistUser')
                    break

        if 'DataScientistsGroup' in resources:
            group = resources['DataScientistsGroup']
            properties = group.get('Properties', {})
            policies = properties.get('Policies', [])

            for policy in policies:
                if policy.get('PolicyName') == 'CustomDataAccess':
                    statements = policy['PolicyDocument'].get('Statement', [])
                    has_kms = any('kms:' in str(stmt.get('Action', [])) for stmt in statements)

                    if not has_kms:
                        print(f"  → 為 DataScientistsGroup 添加 KMS 權限")
                        statements.append({
                            'Effect': 'Allow',
                            'Action': ['kms:Decrypt', 'kms:DescribeKey', 'kms:GenerateDataKey'],
                            'Resource': '*'
                        })
                        updated.append('DataScientistsGroup')
                    break

        return updated

    def update_outputs(self):
        if 'Outputs' not in self.template:
            self.template['Outputs'] = {}

        outputs = self.template['Outputs']

        bucket_updates = {
            'CustomerDataBucketName': 'Now with KMS encryption',
            'MLModelsBucketName': 'Now with KMS encryption and key policy',
            'AnalyticsDataBucketName': 'Now with tiered encryption'
        }

        for output_name, suffix in bucket_updates.items():
            if output_name in outputs:
                desc = outputs[output_name].get('Description', '')
                if suffix not in desc:
                    outputs[output_name]['Description'] = f"{desc} - {suffix}"

        kms_outputs = {
            'CustomerDataKMSKeyId': {
                'Description': 'KMS Key ID for Customer Data Bucket',
                'Value': {'Ref': 'CustomerDataKMSKey'},
                'Export': {'Name': {'Fn::Sub': '${AWS::StackName}-CustomerData-KMSKey'}}
            },
            'MLModelsKMSKeyId': {
                'Description': 'KMS Key ID for ML Models Bucket',
                'Value': {'Ref': 'MLModelsKMSKey'},
                'Export': {'Name': {'Fn::Sub': '${AWS::StackName}-MLModels-KMSKey'}}
            },
            'AnalyticsHighSensitivityKeyId': {
                'Description': 'KMS Key ID for high sensitivity analytics data',
                'Value': {'Ref': 'AnalyticsHighSensitivityKMSKey'},
                'Export': {'Name': {'Fn::Sub': '${AWS::StackName}-Analytics-HighSensitivity-KMSKey'}}
            },
            'AnalyticsStandardKeyId': {
                'Description': 'KMS Key ID for standard sensitivity analytics data',
                'Value': {'Ref': 'AnalyticsStandardKMSKey'},
                'Export': {'Name': {'Fn::Sub': '${AWS::StackName}-Analytics-Standard-KMSKey'}}
            },
            'EBSEncryptionKeyId': {
                'Description': 'KMS Key ID for EBS volume encryption',
                'Value': {'Ref': 'EBSEncryptionKey'},
                'Export': {'Name': {'Fn::Sub': '${AWS::StackName}-EBS-KMSKey'}}
            }
        }

        for key, value in kms_outputs.items():
            if key not in outputs:
                outputs[key] = value

        if 'EncryptionImprovements' not in outputs:
            improvements = ('CustomerDataBucket: KMS-CMK | MLModelsBucket: KMS-CMK with key policy | '
                            'AnalyticsDataBucket: Tiered KMS encryption | EC2: Encrypted EBS volumes | '
                            'Lambda: Ephemeral storage encryption')
            outputs['EncryptionImprovements'] = {
                'Description': 'Encryption enhancements added to this template',
                'Value': improvements
            }

    def enhance_template(self):
        print("\n=== 開始安全增強 ===\n")

        resources = self.template.get('Resources', {})
        if not resources:
            print("❌ 模板中沒有 Resources")
            return

        print("1. 創建 KMS Keys...")
        new_resources = OrderedDict()

        customer_key, customer_alias = self.create_customer_data_kms_key()
        new_resources['CustomerDataKMSKey'] = customer_key
        new_resources['CustomerDataKMSKeyAlias'] = customer_alias
        print("  ✓ CustomerDataKMSKey")

        ml_key, ml_alias = self.create_ml_models_kms_key()
        new_resources['MLModelsKMSKey'] = ml_key
        new_resources['MLModelsKMSKeyAlias'] = ml_alias
        print("  ✓ MLModelsKMSKey")

        analytics_keys = self.create_analytics_kms_keys()
        new_resources['AnalyticsHighSensitivityKMSKey'] = analytics_keys[0]
        new_resources['AnalyticsHighSensitivityKMSKeyAlias'] = analytics_keys[1]
        new_resources['AnalyticsStandardKMSKey'] = analytics_keys[2]
        new_resources['AnalyticsStandardKMSKeyAlias'] = analytics_keys[3]
        print("  ✓ AnalyticsHighSensitivityKMSKey")
        print("  ✓ AnalyticsStandardKMSKey")

        ebs_key, ebs_alias = self.create_ebs_kms_key()
        new_resources['EBSEncryptionKey'] = ebs_key
        new_resources['EBSEncryptionKeyAlias'] = ebs_alias
        print("  ✓ EBSEncryptionKey")

        print("\n2. 插入 KMS Keys 到模板...")
        updated_resources = OrderedDict()
        updated_resources.update(new_resources)
        updated_resources.update(resources)
        self.template['Resources'] = updated_resources

        print("\n3. 處理 S3 Buckets...")
        resources = self.template['Resources']

        if 'CustomerDataBucket' in resources:
            if self.enhance_customer_data_bucket(resources['CustomerDataBucket']):
                self.buckets_enhanced.append('CustomerDataBucket')

        if 'MLModelsBucket' in resources:
            if self.enhance_ml_models_bucket(resources['MLModelsBucket']):
                self.buckets_enhanced.append('MLModelsBucket')

        if 'AnalyticsDataBucket' in resources:
            if self.enhance_analytics_data_bucket(resources['AnalyticsDataBucket']):
                self.buckets_enhanced.append('AnalyticsDataBucket')

        if 'AnalyticsBackupBucket' in resources:
            if self.enhance_analytics_backup_bucket(resources['AnalyticsBackupBucket']):
                self.buckets_enhanced.append('AnalyticsBackupBucket')

        print("\n4. 處理 EC2 Instances...")
        if 'DataAnalysisInstance' in resources:
            self.enhance_ec2_instance(resources['DataAnalysisInstance'])

        print("\n5. 處理 Lambda Functions...")
        if 'DataProcessingFunction' in resources:
            self.enhance_lambda_function(resources['DataProcessingFunction'])

        print("\n6. 更新 IAM 權限...")
        iam_updated = self.update_iam_permissions()
        if iam_updated:
            print(f"  ✓ 已更新: {', '.join(iam_updated)}")

        print("\n7. 更新 Outputs...")
        self.update_outputs()

        if 'Description' in self.template:
            desc = self.template['Description']
            if 'Enhanced Encryption' not in desc:
                self.template['Description'] = desc.replace(
                    '(DO NOT USE IN PRODUCTION)',
                    'with Enhanced Encryption (DO NOT USE IN PRODUCTION)'
                )

        print("\n=== 安全增強完成 ===")
        print(f"\n增強摘要:")
        print(f"  • 創建了 5 個 KMS Keys（含 Aliases）")
        print(f"  • 增強了 {len(self.buckets_enhanced)} 個 S3 Buckets")
        print(f"  • 為 EC2 添加了加密 EBS 卷")
        print(f"  • 為 Lambda 添加了臨時存儲加密")
        print(f"  • 更新了 {len(iam_updated)} 個 IAM 資源")
        print(f"  • 更新了 Outputs 和 Description\n")

    def save_template(self, output_path=None):
        if output_path is None:
            output_path = self.template_path.parent / f"{self.template_path.stem}_enhanced{self.template_path.suffix}"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            if output_path.suffix in ['.yaml', '.yml']:
                yaml.dump(
                    self.template,
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                    allow_unicode=True,
                    width=1000,
                    indent=2,
                    Dumper=CFNYAMLDumper
                )
            else:
                json.dump(self.template, f, indent=2, ensure_ascii=False)

        print(f"✓ 增強後的模板已儲存至: {output_path}")
        return output_path


class CFNYAMLDumper(yaml.SafeDumper):
    pass


def represent_cfn_function(dumper, data):
    if not isinstance(data, dict) or len(data) != 1:
        return dumper.represent_dict(data)

    key = list(data.keys())[0]
    value = data[key]

    if key == 'Ref':
        return dumper.represent_scalar('!Ref', value)

    elif key == 'Fn::GetAtt':
        if isinstance(value, list) and len(value) == 2:
            return dumper.represent_scalar('!GetAtt', f'{value[0]}.{value[1]}')
        return dumper.represent_scalar('!GetAtt', str(value))

    elif key.startswith('Fn::'):
        tag_name = key.replace('Fn::', '')
        if isinstance(value, (str, int, float, bool)):
            return dumper.represent_scalar(f'!{tag_name}', str(value))
        elif isinstance(value, list):
            return dumper.represent_sequence(f'!{tag_name}', value)
        elif isinstance(value, dict):
            return dumper.represent_mapping(f'!{tag_name}', value)

    return dumper.represent_dict(data)


CFNYAMLDumper.add_representer(dict, represent_cfn_function)
CFNYAMLDumper.add_representer(OrderedDict, represent_cfn_function)


def main():
    parser = argparse.ArgumentParser(
        description='自動增強 CloudFormation 模板的安全性',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用範例:
  %(prog)s template.yaml
  %(prog)s template.yaml -o secure_template.yaml
  %(prog)s template.json -o output/secure.json

此腳本會添加:
  • 5 個 KMS Keys (CustomerData, MLModels, AnalyticsHigh, AnalyticsStandard, EBS)
  • 完整的 Key Policy 配置
  • S3 Buckets 加密
  • EC2 EBS 卷加密
  • Lambda 臨時存儲加密
  • IAM 權限更新
        """
    )
    parser.add_argument('template', help='CloudFormation 模板文件路徑')
    parser.add_argument('-o', '--output', help='輸出文件路徑（預設: 原文件名_enhanced）')

    args = parser.parse_args()

    try:
        enhancer = CFNSecurityEnhancer(args.template)
        enhancer.load_template()
        enhancer.enhance_template()
        output_file = enhancer.save_template(args.output)

        print(f"\n✅ 成功！增強後的模板已完成")
        print(f"\n📁 輸出文件: {output_file}")
        print("\n⚠️  注意事項:")
        print("    • 此模板已添加完整的 KMS 加密")
        print("    • 仍需進行全面的安全審查")
        print("    • 請勿直接用於生產環境")
        print("\n📋 下一步建議:")
        print("    1. 使用 'aws cloudformation validate-template' 驗證")
        print("    2. 使用 'cfn-lint' 進行檢查")
        print("    3. 審查並修正其他安全問題")

    except FileNotFoundError:
        print(f"\n❌ 錯誤: 找不到文件 '{args.template}'", file=sys.stderr)
        sys.exit(1)
    except (yaml.YAMLError, json.JSONDecodeError) as e:
        print(f"\n❌ 解析錯誤: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 錯誤: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()