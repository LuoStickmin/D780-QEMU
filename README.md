# D780-QEMU

Nikon D780（EXPEED 6 / E6）固件研究用 QEMU 原型机器。

本仓库是从 [D750-QEMU](https://github.com/LuoStickmin/D750-QEMU) 的验证机方法中
拆出的 D780 专用工作区：一个 QEMU 11.1.0 的 overlay 机器 `nikon-d780`，
加上运行工具和已经确认的 E6 启动链结论。

- **不包含任何 Nikon 固件**；需要你自行提供已解密的 `eg1510_*.bi`。
- 机器默认值面向 E6：`payload-base=0x10020000`、`flash-size=0x2400000`、
  `e6-prep=on`、CPU `cortex-a15`。

## 当前状态（2026-11-10）

`eg1510_012100.bi`（35.6 MB）装到 `0x10020000` 后，用 **`-smp 2`** 运行：

- header 的 `EA002F20` 分支进入 `0x1002BC88`，完成寄存器清零、SP、MMU
  （SCTLR/TTBR0/DACR/VBAR）和各级栈设置；
- 页表在 `payload+0x10000`（即 `0x10030000`），镜像里只存 1 MiB 物理地址，
  `e6-prep` 会补成 identity section（实测 1478 条）；
- `0x0420_0000` 外设块已建模为寄存器堆：`[page+4]` 视为完成位、
  `0x04266008` 为自增计数器（延时循环）；
- `0x20022300`、`0x20070008`、`0x20010038` 三个 ready word 置 1 后，
  **0 undefined、238 次 SVC**，PC 已跑到 `0x1011D8F4` 附近
  （调度/空闲路径）；
- 两个 CPU 都需要启动（firmware 在 `0x1011C014` 等待第二个核）。

下一步：确认 `0x1011D8F4` 是 idle 还是等待定时器中断；必要时给
`0x04266000` 定时器加 IRQ。

细节见 [docs/status.md](docs/status.md)。

## 构建

```sh
# QEMU 11.1.0 源码树
python3 qemu/prepare_source.py /path/to/qemu-11.1.0
cd /path/to/qemu-11.1.0 && ninja -C build qemu-system-arm
```

## 运行

```sh
python3 tools/run.py \
  --payload /path/to/eg1510_012100.bi \
  --qemu /path/to/qemu-system-arm \
  --out runs/e6 \
  --timeout 5
```

机器默认已经带 `payload-base=0x10020000`、`flash-size=0x2400000`、
`e6-prep=on`，一般不需要再传。

## 许可

机器 overlay 与工具为 GPLv2；Nikon 固件版权归 Nikon Corporation，仓库不附带。
