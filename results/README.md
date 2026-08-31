# Curated experimental results / 精简实验结果

This directory contains compact, machine-readable outputs that help reviewers
trace the implementation to its experiments. Bulk request/resource JSONL,
QEMU logs, generated reports and compiled binaries are deliberately excluded.

本目录仅保留便于审阅者核对实现与实验的精简机器可读结果。大体积的请求与
资源 JSONL、QEMU 日志、自动生成报告及编译二进制均未纳入仓库。

| Directory | Contents / 内容 |
|---|---|
| `stage2/` | End-to-end acceptance and Audit TA verification summaries / 端到端验收与 Audit TA 验证摘要 |
| `stage3/` | AI pipeline smoke-test features, metrics, models and parity vectors / AI 流水线冒烟实验的特征、指标、模型与一致性向量 |
| `stage4/` | Formal detection outputs plus the 40-run performance summary / 正式检测结果与 40 次性能实验摘要 |
| `stage5/` | Feature-ablation models, paired comparison outputs and 70 per-run result summaries / 特征消融模型、配对比较结果及 70 个单次运行摘要 |

The original collection timestamps are retained in directory names for
provenance. These files are evidence snapshots, not live production data.

目录名保留原始采集时间用于追溯；这些文件是实验快照，并非生产环境数据。
