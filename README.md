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

`0x1011D8F4` 经 RSP 采样确认**不是 idle/WFI**：它在自旋等待
`[r4+4] = 0x00020002` 的高 16 位清零（r4 指向
`{id=0x0E, pending, fn=0x101058C8, ctx}` 工作项）。采样时 GIC
（`0xE0001100`/`0xE0001000`/`0xE0002000`）全为 0，固件还没有使能任何
GIC 中断，所以给 `0x04266000` 加 IRQ 暂时不会被接收。

`secondary-pc=0` 实验（CPU1 从 0 执行）会让 SVC 归零，说明 CPU1 必须走
固件自己的 secondary 路径。

下一步：找 CPU1 的 secondary entry，或找谁负责完成 `0x101058C8` 工作项。

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

## GUI（boot monitor）

仿 z6-qemu 的浏览器控制器，纯标准库、无第三方依赖：

```sh
# WSL / Linux
python3 tools/gui.py \
  --payload /path/to/eg1510_012100.bi \
  --qemu /path/to/qemu-system-arm
# 浏览器打开 http://127.0.0.1:8787/
```

- 实时显示 stage、last PC、SVC、undef/prefetch/data、probe（含最后地址）、
  translated blocks；
- PC trail 与 QEMU 日志尾部；
- Start / Stop / Restart；
- 不渲染 framebuffer（D780 还没有 LCD 模型），是启动监视器；
- 日志默认写 `/tmp/d780-gui/`（WSL 下避免 `/mnt/c` 慢 I/O），可用
  `D780_GUI_RUNS` 覆盖；`--cpu/--ram/--smp/--port/--bind` 可调。

## 原机 GUI 模拟（/camera）

`tools/camera.html` 是 D780 **菜单界面**的模拟（UI mock，不是固件渲染）：

- 4:3 显示屏 + 状态栏（M / 快门 / 光圈 / ISO / WB / 画质 / 电量 / 剩余张数）；
- 7 个菜单标签：播放、照片拍摄、动画拍摄、自定义设定、设定、润饰、我的菜单；
- 方向键 / Enter / Esc / MENU 导航，选项可循环切换；
- **Lv 按钮显示“暂未实现”**（按要求先不做实时取景）；
- 启动 `tools/gui.py` 后打开 <http://127.0.0.1:8787/camera>。

这是纯前端模拟，用于先确定原机 GUI 的布局与交互；等 QEMU 的显示模型/固件
渲染接通后，可以把它替换成真实 framebuffer 输出。

## 还需要什么（输入需求）

D780（E6）与 D750（E4）、D850/D5（E5）一样，缺的都是**第一级 boot**。
按优先级：

1. **整片 SPI flash dump**（D780 或任一 E6/E5/E4 机型）——最直接，可能包含
   boot 分区或第一级 loader；CH341A/测试夹读取，或从维修渠道获取。
2. **Nikon 服务软件/维修固件里的 recovery/boot 镜像**（如 Tornado NKN 等）。
3. **其他机型整片 dump**（D5100/D7000/D800）——理解 Nikon boot 分区结构。
4. **硬件 UART 启动日志**——确认 boot ROM 之后第一段代码的加载地址与大小。
5. **Z6/Z7 QEMU 社区关于 `0x40000000` 区域填充者的信息**（可选）。

已经具备、无需再提供：`eg1510_012100.bi` 解密镜像、`nikon-d780` 机器、
`e6-prep`/`early_control` 模型、E6 启动链与 `0x1011D8F4` 分析。

没有新输入时仍可做：在 `eg1510` 里反查写 `0x40000000` 的 relocation 循环，
判断 boot 是否其实在镜像内；继续 `0x101058C8` 工作项与调度器路径。

## 许可

机器 overlay 与工具为 GPLv2；Nikon 固件版权归 Nikon Corporation，仓库不附带。
