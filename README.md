# office-document-threat-auditor
Python Office 文档威胁审计库，处理宏关系、外部引用、嵌入对象和 OOXML 路径边界

## 概述

面向邮件网关等 inbound 场景的 OOXML（docx / docm / xlsx / pptx 等）静态威胁审计器。
把 Office 文档当作 ZIP 容器解析，覆盖扩展名与 `vbaProject` 存在性之外的攻击面：

- `[Content_Types].xml`：部件内容类型，识别 macroEnabled 主文档与 VBA 项目
- 关系文件（`_rels/*.rels`）：解析每条关系，校验关系类型必须落在允许的 OOXML
  关系命名空间内，并输出具体关系文件、source part 与 target part
- VBA 项目：`vbaProject.bin` 部件与 `vbaProject` 关系（HIGH）
- 外部 target：`TargetMode="External"` 的远程模板（`attachedTemplate`，HIGH）、
  普通外链（hyperlink，INFO）、外部图片等
- 嵌入 OLE 对象：`oleObject` 关系与 `word/embeddings/` 部件（MEDIUM）
- 可疑字段指令：`DDEAUTO` / `DDE`、带远程 URL 的 `INCLUDETEXT` / `INCLUDEPICTURE`
  等 `w:instrText` / `w:fldSimple` 字段
- 对象引用图：以 source part 为节点、关系为边的完整引用图

## 安全边界

- 所有 ZIP 成员名与关系 target 都经过规范化并限制在包根内：`..` 回退、绝对路径、
  盘符路径、NUL 字节一律拒绝并记为 `PATH_TRAVERSAL` 发现，不会发生越界读取
- 异常大小防护：成员数量、单部件解压大小、总解压大小与压缩比均有上限，
  超限即拒绝（防 ZIP 炸弹）
- 仅做静态威胁分析：**不执行宏或任何 Office 内容，不访问任何外部 target，
  不渲染文档**。远程模板与外链只被记录和定级，从不被拉取

## 用法

```bash
python -m ooxml_auditor suspicious.docm
```

```python
from ooxml_auditor import OoxmlAuditor

report = OoxmlAuditor().audit(open("suspicious.docm", "rb"), path="suspicious.docm")
for rel in report.relationships:
    print(rel.rels_file, rel.source_part, "->", rel.resolved_target or rel.target)
for finding in report.findings:
    print(finding)
```

## 测试

```bash
python -m unittest
```

测试在内存中构造样本：宏文档、远程模板、普通外链、嵌入 OLE 对象、正常图片文档、
损坏 ZIP、路径穿越 target、可疑字段指令与越界关系命名空间。
