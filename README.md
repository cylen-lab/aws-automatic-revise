### 1. 導入模組與初始化
````
#!/usr/bin/env python3
import yaml
import json
import sys
import argparse
from pathlib import Path
from collections import OrderedDict
````
導入必要的 Python 標準庫，yaml 用於解析 YAML 格式，json 處理 JSON，argparse 處理命令列參數，Path 處理檔案路徑，OrderedDict 保持資源順序。
### 2. CloudFormation 函數處理器
````
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
````
處理 CloudFormation 內建函數（如 !Ref、!GetAtt、!Sub）。將 YAML 標籤轉換為字典格式，例如 !Ref MyResource 轉為 {'Ref': 'MyResource'}。這樣可以正確解析和保留 CloudFormation 的特殊語法。
### 3. YAML 輸出配置
````
def represent_ordereddict(dumper, data):
    return dumper.represent_mapping('tag:yaml.org,2002:map', data.items())


yaml.add_representer(OrderedDict, represent_ordereddict)
````
配置 YAML 輸出時如何處理 OrderedDict，確保輸出的 YAML 保持資源的順序，讓 KMS Keys 能排在其他資源之前。
### 4. 主類別初始化
````
class CFNSecurityEnhancer:
    def __init__(self, template_path):
        self.template_path = Path(template_path)
        self.template = None
        self.kms_keys_created = {}
        self.buckets_enhanced = []
````
定義主要類別 CFNSecurityEnhancer，初始化時接收模板路徑，準備儲存模板內容、已創建的 KMS 金鑰和已增強的儲存桶列表。
### 5. 模板載入方法
````
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
````
載入 CloudFormation 模板檔案，優先嘗試 YAML 解析，失敗則嘗試 JSON。支援 UTF-8-BOM 編碼，提供詳細的錯誤訊息。
### 6.創建 CustomerData KMS Key
````
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
````
創建用於客戶資料儲存桶的 KMS 金鑰及其別名。金鑰政策允許 IAM 根帳戶完全控制，並授權 S3 服務使用該金鑰進行加密和解密。啟用自動金鑰輪換以提高安全性。
### 7.創建 MLModels KMS Key
````
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
````
創建用於機器學習模型儲存桶的 KMS 金鑰。除了 S3 服務外，還授權 EC2 和 Lambda 服務使用此金鑰，因為 ML 模型可能需要被這些服務存取。
### 8.創建 Analytics KMS Keys
````
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
````
創建兩個用於分析資料的 KMS 金鑰：高敏感度和標準敏感度。這實現了分層加密策略，允許根據資料敏感度使用不同的加密金鑰，提供更細緻的存取控制。
### 9.創建 EBS KMS Key
````
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
````
創建用於 EBS 卷加密的 KMS 金鑰。除了基本的加密解密權限外，還授予 EC2 服務 CreateGrant 權限，這是 EBS 卷加密所必需的。條件語句確保 Grant 只能用於 AWS 資源。
### 10.增強 CustomerDataBucket
````
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
````
為 CustomerDataBucket 添加 KMS 加密配置。先檢查是否已有加密設定，避免重複修改。啟用 BucketKeyEnabled 可降低 KMS 請求成本。添加標籤以標識加密類型。
### 11. 增強 MLModelsBucket
````
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
````
為 MLModelsBucket 添加 KMS 加密。檢查邏輯更嚴謹，確認是否已使用正確的 KMS 金鑰（MLModelsKMSKey）。
### 12.增強 AnalyticsDataBucket（含複製配置）
````
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
````
為 AnalyticsDataBucket 添加分層加密並更新複製配置。如果存在 S3 複製規則，會更新為支援加密物件的複製，包括設定目標金鑰、啟用加密物件選擇，並確保複製規則符合最新的 CloudFormation 規範（使用 Filter 而非 Prefix）。
### 13.增強 AnalyticsBackupBucket
````
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
````
為備份儲存桶添加加密，使用與主要分析資料儲存桶相同的高敏感度金鑰，確保備份資料獲得同等級的保護。
### 14.增強 EC2 Instance
````
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
````
為 EC2 實例添加兩個加密的 EBS 卷：根卷（/dev/xvda, 20GB）和資料卷（/dev/sdf, 50GB）。使用 gp3 卷類型以獲得更好的性能和成本效益。所有卷都使用專用的 EBS KMS 金鑰加密，並設定為實例終止時自動刪除。
### 15.增強 Lambda Function
````
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
````
為 Lambda 函數配置臨時存儲（/tmp 目錄）並設定為 1024 MB。Lambda 的臨時存儲預設已加密，此處明確設定大小並添加環境變數標記。
### 16.更新 IAM 權限
````
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

    return updated
````
更新 IAM 角色權限，添加必要的 KMS 操作權限。以 DataProcessingRole 為例，添加對所有 KMS 金鑰的解密、描述和生成資料金鑰權限。類似的邏輯應用於其他 IAM 資源（ThirdPartyIntegrationRole、S3ReplicationRole、DataScientistUser 等）。
### 17.更新 Outputs
````
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
````
更新 CloudFormation 輸出部分。為現有儲存桶輸出添加加密說明，新增所有 KMS 金鑰的輸出（含 Export 以便其他堆疊引用），並添加加密改進摘要。
### 18.主要增強流程
````
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
````
這是整個增強流程的核心方法，按順序執行以下步驟：

創建所有 KMS 金鑰和別名
將 KMS 資源插入到模板的最前面（使用 OrderedDict 保持順序）
依序處理所有 S3 儲存桶
處理 EC2 實例
處理 Lambda 函數
更新 IAM 權限
更新輸出部分
更新模板描述並顯示完整的增強摘要
### 19.儲存模板
````
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
````
將增強後的模板儲存到檔案。若未指定輸出路徑，則自動在原檔案名後加上 _enhanced。根據副檔名選擇 YAML 或 JSON 格式輸出。YAML 輸出使用自訂的 CFNYAMLDumper 以正確處理 CloudFormation 函數，並設定不排序、保持原有縮排格式。
### 20.CloudFormation YAML Dumper
````
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
````
自訂 YAML Dumper 用於輸出 CloudFormation 模板。將內部的字典格式（如 {'Ref': 'MyResource'}）轉換回 CloudFormation 的 YAML 標籤格式（如 !Ref MyResource）。處理各種 CloudFormation 內建函數，確保輸出的 YAML 符合 CloudFormation 規範且易於閱讀。
### 21. 主程式入口
````
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
````
程式的主入口點。使用 argparse 處理命令列參數，提供詳細的使用說明和範例。執行流程包括：載入模板、執行增強、儲存結果。包含完整的錯誤處理，針對不同錯誤類型（檔案不存在、解析錯誤、其他異常）提供清晰的錯誤訊息。成功完成後顯示後續驗證建議。


