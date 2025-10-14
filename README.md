這是一個能自動化修正，使cloudformation能夠修正並加入:
1. CloudFormation 函數處理

正確解析和保留 !Ref、!GetAtt、!Sub 等內建函數
雙向轉換：讀取時轉為字典，輸出時轉回標籤格式

2. 資源順序管理

使用 OrderedDict 確保 KMS Keys 在依賴資源之前
CloudFormation 會自動處理依賴關係，但保持良好順序有助閱讀

3. 冪等性設計

每個增強方法都檢查現有配置
避免重複修改，可安全多次執行

4. 分層加密策略

不同敏感度資料使用不同 KMS 金鑰
提供細緻的存取控制和審計能力

5. 完整的權限管理

金鑰政策授權服務使用金鑰
IAM 角色政策授權實體存取金鑰
雙重授權確保安全性


### 使用方式
下載cfn_security_enhancer.py
安裝相關套件
````
pip install pyyaml
````
執行
````
python cfn_security_enhancer.py template.yaml
````
