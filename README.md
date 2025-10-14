# CloudFormation Security Enhancer

自動增強 AWS CloudFormation 模板的加密安全性的工具。

## 主要用途

此工具能夠自動化地為 CloudFormation 模板添加企業級加密配置，包括：

- **KMS 金鑰管理**：自動創建多個 AWS Key Management Service (KMS) 金鑰，用於不同的數據存儲場景
- **S3 加密**：為 S3 儲存桶配置伺服器端加密 (SSE-KMS)
- **EBS 加密**：為 EC2 實例配置加密的 EBS 卷
- **Lambda 保護**：為 Lambda 函數添加臨時存儲加密
- **IAM 權限更新**：自動授予相關 IAM 角色和使用者必要的 KMS 權限

## 功能特性

### 創建的 KMS 金鑰

1. **CustomerDataKMSKey** - 客戶數據儲存桶專用加密金鑰
2. **MLModelsKMSKey** - ML 模型儲存桶專用加密金鑰
3. **AnalyticsHighSensitivityKMSKey** - 高敏感度分析數據加密金鑰
4. **AnalyticsStandardKMSKey** - 標準敏感度分析數據加密金鑰
5. **EBSEncryptionKey** - EBS 卷加密金鑰

每個金鑰均配有適當的 Key Policy，限制只有授權的 AWS 服務和角色能夠使用。

### 增強的資源

- **S3 Buckets**：CustomerDataBucket、MLModelsBucket、AnalyticsDataBucket、AnalyticsBackupBucket
- **EC2 Instances**：DataAnalysisInstance（添加加密 EBS 卷）
- **Lambda Functions**：DataProcessingFunction（添加臨時存儲加密）
- **IAM 角色**：DataProcessingRole、ThirdPartyIntegrationRole、S3ReplicationRole、DataScientistUser、DataScientistsGroup

## 安裝與使用

### 前置需求

- Python 3.7+
- PyYAML
- 有效的 CloudFormation 模板（YAML 或 JSON 格式）

### 安裝依賴

```bash
pip install pyyaml
```

### 基本用法

```bash
python cfn_security_enhancer.py template.yaml
```

### 指定輸出文件

```bash
python cfn_security_enhancer.py template.yaml -o secure_template.yaml
```

### 處理 JSON 模板

```bash
python cfn_security_enhancer.py template.json -o output/secure.json
```

## 使用範例

```bash
# 增強 YAML 模板（自動生成輸出文件）
python cfn_security_enhancer.py my-infrastructure.yaml

# 增強模板並指定輸出位置
python cfn_security_enhancer.py my-infrastructure.yaml -o ./enhanced/my-infrastructure-secure.yaml

# 增強 JSON 模板
python cfn_security_enhancer.py template.json -o secure-template.json
```

## 輸出結果

工具執行後會：

1. 解析輸入的 CloudFormation 模板（支援 YAML 和 JSON 格式）
2. 創建 5 個 KMS 金鑰和對應的別名
3. 為現有 S3 儲存桶配置 KMS 加密
4. 為 EC2 實例添加加密的 EBS 卷
5. 為 Lambda 函數添加臨時存儲加密
6. 更新 IAM 角色和使用者的權限
7. 在模板中添加新的 Output 部分，展示 KMS 金鑰 ID
8. 生成增強後的模板文件

## 重要注意事項

⚠️ **此工具生成的模板仍需進行以下步驟：**

1. **驗證模板**
   ```bash
   aws cloudformation validate-template --template-body file://template.yaml
   ```

2. **進行靜態分析**
   ```bash
   cfn-lint template.yaml
   ```

3. **全面安全審查**
   - 檢查 Key Policy 是否符合最小權限原則
   - 驗證所有 IAM 權限配置
   - 評估是否需要額外的安全控制

4. **測試與驗證**
   - 在開發/測試環境先行部署
   - 驗證加密功能是否正常運作
   - 測試所有相關服務的權限

## 支援的輸入/輸出格式

- **輸入**：YAML (.yaml, .yml) 或 JSON (.json) 格式的 CloudFormation 模板
- **輸出**：與輸入格式相同的增強型模板

## 許可

MIT License

## 貢獻

歡迎提交 Issue 和 Pull Request！

## 免責聲明

此工具生成的模板僅供參考。使用者應在部署至生產環境前進行完整的安全審查和測試。作者對使用本工具造成的任何損失或損害不承擔責任。
