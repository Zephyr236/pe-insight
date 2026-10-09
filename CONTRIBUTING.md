# 贡献指南

感谢你愿意参与。这个项目有几个**必须遵守的硬约束**，先读完再动手。

---

## 一、不可动摇的设计约束

### 1. 样本永不离开本机

这是整个项目的存在理由，任何改动都不能破坏它。

- **不允许**引入任何会把样本内容、哈希或元数据发往网络的引擎或功能
- 新增引擎必须声明 `network_level()`，说明其真实的外传行为
- 不确定是否外传的，**按最坏情况声明**——宁可引擎被策略拦下，也不要撒谎
- 引擎的 `offline` / `network_level()` 是**安全契约**，不是描述性标签。
  声明 `local` 意味着"我能证明它不走网络"，而不是"我希望它不走网络"

### 2. 不真正执行样本

当前所有动态分析都走 Speakeasy 模拟执行，样本从未作为真实进程运行。
如果你要引入真实沙箱，必须同时提供完整的隔离方案（专用 VM、快照回滚、
Host-Only 网络），并在 PR 里说明为什么模拟执行不足以覆盖该场景。

### 3. 诚实优先于好看

这个项目在"报错"和"看起来正常"之间永远选前者：

- 模拟执行没跑起来就明确说"未覆盖完整逻辑"，**绝不能让它看起来像"干净"**
- 引擎读不到文件就报 `error`，不要静默跳过
- 被测出的真实行为不要隐藏

反例（这类 PR 会被拒）：把超时的引擎结果当 `clean` 返回。

---

## 二、开发环境

```powershell
git clone <your-fork>
cd pe-insight
.\setup.ps1 -SkipTools     # 装依赖和前端，不下载 2.5 GB 引擎
```

改完代码后：

```powershell
# 后端热重载
cd backend
.\.venv\Scripts\python.exe -m app.cli serve --reload

# 前端热重载（另开一个终端，后端保持运行）
cd frontend
npm run dev
```

## 三、代码风格

- **Python**：`ruff` 检查，行宽 100。提交前跑一次：

  ```powershell
  cd backend
  uv run ruff check .
  uv run ruff format .
  ```

- **注释写"为什么"，不写"是什么"**。
  `# 递增计数器` 是废话；`# 这里必须用独立进程，因为 run_module 没有超时参数`
  才有价值。

- **中文注释是允许的**（项目主要面向中文用户），但变量名、函数名一律用英文。

- **不要为了"以后可能需要"提前抽象**。这个项目已经因为过早抽象吃过亏。

---

## 四、新增一个引擎

引擎适配器在 `backend/app/engines/`。加一个引擎需要：

1. 继承 `EngineAdapter`，实现三个抽象方法：

   ```python
   class MyEngine(EngineAdapter):
       name = "MyEngine"
       kind = EngineKind.SIGNATURE
       resource_class = "light"   # "heavy" 会串行执行

       def available(self) -> bool: ...
       def scan(self, ctx: ScanContext) -> EngineResult: ...
       def unavailable_reason(self) -> str: ...
   ```

2. **如果它可能走网络**，重写 `network_level()` 和 `network_note()`
   如实说明，不要写死 `offline = True`。

3. **如果它单次占用超过 ~200 MB 内存**，把 `resource_class` 设成 `"heavy"`。
   分级依据是**内存**不是耗时——把弱机器拖垮的是内存压力。

   > 实测参考（单核 6 GB 机器，`cmd.exe`）：
   > ClamAV 无 clamd 1126 MB / CAPA 404 MB / Emsisoft 120 MB /
   > DIE 37 MB / Manalyze 8 MB / Defender 与 YARA 约 0 MB

4. 在 `registry.py` 的 `all_engines()` 里登记。

5. **不要不加参数就扫**。特别注意：
   - 会给样本做隔离/删除的引擎，必须关掉该行为（否则后续引擎拿不到文件）
   - 有云端查询的引擎，必须显式关闭
   - 参考 `clamav.py`（无删除行为）、`emsisoft.py`（`/cloud=0` +
     刻意不加 `/d` 和 `/q=`）、`defender.py`（`-DisableRemediation`）

---

## 五、测试

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest
```

测试目录 `backend/tests/`。有用的测试类型：

- **引擎适配器**：mock 掉子进程调用，验证输出解析（尤其是畸形/多余输出）
- **聚合逻辑**：`orchestrator.aggregate()` 的判定矩阵
- **YARA 规则**：`tests/test_yara_rules.py` 会用规则自身的字符串构造合成
  样本验证真阳性，再用系统自带的 exe/dll/sys 验证真阴性
  （**规则绝不能在这上面误报**）

> 历史教训：反调试规则曾经在 `notepad.exe` 上误报，因为把
> `IsDebuggerPresent`、`OutputDebugString` 这类正常程序普遍导入的 API
> 计入了阈值。**加检测规则时一定要拿系统文件跑一遍验证零误报。**

---

## 六、提交

- 一个 PR 只做一件事
- commit message 说清楚**为什么**改，不只是改了什么
- 涉及行为变更（尤其是让某些结果变得更"宽松"的）必须说明理由
- 修改 `rules/` 下的 YARA 规则时，附上在系统文件上的误报测试结果

---

## 七、绝对不要提交的东西

`.gitignore` 已经处理了大部分，但请确认：

- `data/` —— 里面存着**真实恶意样本**
- `tools/` —— 2.5 GB 的引擎二进制
- `.venv/`、`node_modules/`、`frontend/dist/`

**特别提醒**：调试时不要把真实恶意样本拖进项目目录再 `git add -A`。
一旦样本进了 git 历史，清理起来非常麻烦。

---

## 八、报告问题

提交 issue 时请附上：

- `python -m app.cli engines` 的输出
- `python -m app.cli verify-offline` 的输出（如果涉及隐私问题）
- 完整的错误堆栈

**不要**在 issue 里附上真实恶意样本。如果必须说明样本特征，
提供 SHA256 和静态分析结果即可。
