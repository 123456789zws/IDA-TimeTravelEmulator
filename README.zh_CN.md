# Time Travel Emulator

`TimeTravelEmulator` 是一款功能强大的 IDA Pro 插件，通过集成 Unicorn 仿真框架，实现时间回溯调试的功能。通过记录和回放程序执行，可以实现对运行时行为的详细分析。

## 语言

[English](README.md) | 中文


## 功能特性

* **基于Unicorn的仿真引擎**：集成 Unicorn 仿真框架，用于在 IDA Pro 中执行代码片段或整个函数。
* **全面的状态捕获**：记录执行每条指令时CPU寄存器和内存变化的详细快照。
* **时间回溯调试**：
    * **前进和后退导航**：无缝地前进（F3）和后退（F2）执行历史记录。
    * **状态切换**：跳转到任何已捕获的程序状态（Q），分析特定时间点的确切条件。
    * **基于状态ID的切换**：通过唯一的 `state_id` 跳转（I）到任何已捕获的程序状态(`state_id` 格式为 `$<指令地址>#<执行次数>`)，以实现精确导航。
* **差异可视化** ：在状态之间切换时，插件会高亮显示插件界面中的内存和寄存器差异，
* **内存和寄存器跟踪**：提供对程序执行过程中内存和寄存器值变化的可见性。
* **可配置的仿真**：
    * 设置自定义仿真范围（起始地址和结束地址）。
    * 从当前调试器状态加载初始寄存器值（在调试模式下生效）。
    * 配置仿真步数限制和时间限制。
    * 设置自定义的预处理代码，以设置 Unicorn 环境。


## 运行要求

- IDA Pro 版本 >= 7.7
- Python 版本 >= 3.8


## 安装

1.  在你的IDAPython中使用指令 `pip install bsdiff4 capstone sortedcontainers unicorn` 安装必要的依赖包。
2.  将 `TimeTravelEmulator.py` 文件放入 IDA Pro 的 `plugins` 目录。
3.  重启 IDA Pro。


## 快速入门

<img width="483" height="585" alt="image" src="https://github.com/user-attachments/assets/315d56fe-7599-49b0-a9c1-b2285d43b8a8" />

按下快捷键 `Shift+T` 打开 `EmuTrace: Emulator Settings` (模拟器设置) 对话框。

设置完成后，点击 "Emulate" 开始时间回溯仿真。


<img width="2300" height="1020" alt="image" src="https://github.com/user-attachments/assets/053cee98-c4a0-4146-b3ab-c28bfcef4ad3" />

仿真完成后，插件将创建一个独立的视图，您可以使用以下快捷键浏览该视图中记录的状态：
* `F3`: 移动到下一个录制的状态。
* `F2`: 移动到上一个录制的状态。
* `Q`: 通过光标所在的位置跳转到对应指令处的状态。

## 更多信息
```cpp
#include <iostream>

int main() {
    volatile int a = 5;
    volatile int b = 3;
    volatile int result = 0;

    int i = 0;
    while (i < 32) {
        result = result + i;
        b += a;
        i+= 1;
    }

     printf("Result: %d\n", result);

    return 0;
}
```

用于仿真的示例程序源代码。

### 模拟器设置对话框
<img width="2312" height="1281" alt="image" src="https://github.com/user-attachments/assets/f30f80ac-c19a-4dc0-9fd0-a61201993bf1" />

选择要仿真的代码并使用快捷键 `Shift+T` 打开仿真设置对话框。

在设置对话框中，配置仿真参数：
* **Start address & End address**: 模拟运行的起始地址和终止地址
* **Select funtion range**: 选择某一函数作为模拟执行的运行范围

* **Emulate step limit**:  模拟运行的运行步数限制
* **Emulate time out**: 模拟运行的运行时间限制

* **load registers**: 是否加载当前的寄存器值(在调试模式下生效)
* **Set Stack value**: 是否设置特殊的栈帧寄存器值

* **Skip interrupts**：在模拟过程中跳过`int`指令
* **Skip unloaded calls**：跳过目标地址未被加载的`call`指令
* **Skip thunk functions**：在模拟过程中跳过thunk函数

* **Log level & Log file path**: 日志记录等级和保存位置

<img width="1652" height="971" alt="image" src="https://github.com/user-attachments/assets/a57468de-f946-448c-8bcd-8300ef4d79e9" />

* **Set custom preprocessing code**: 设置自定义的预处理代码，这些代码将会在模拟运行前执行。你可以使用此功能提前设置内存、寄存器值或添加Hook


### 时间旅行仿真器视图

![Opening Time Travel Emulator View](https://github.com/user-attachments/assets/51ed9758-250c-44a7-a5b5-a98a99dfd250)


点击 "Emulate" 开始仿真。仿真完成后，将打开一个新窗口，显示从第一个模拟状态开始的反汇编、寄存器和内存视图。

#### 反汇编视图
<img width="2325" height="1054" alt="image" src="https://github.com/user-attachments/assets/125d0e5f-747a-4ea1-a6e0-2e6943731aa0" />

这是插件的核心视图，标注了当前执行的汇编指令行，最左侧的数字指示当前汇编指令行在整个模拟执行过程中的执行次数。

使用以下快捷键进行导航：

  * `F3`: 移动到下一个录制的状态。
  * `F2`: 移动到上一个录制的状态。
  * `Q`:  跳转到光标所在指令处的状态。
  * `I`:  提示输入 state_id（例如，$0x401000#5）以跳转到特定状态。

#### 寄存器视图和内存视图

![Register View and Memory View examples](https://github.com/user-attachments/assets/fbcfc301-c639-4f85-a4cf-891909189011)


当切换状态时，寄存器视图和内存视图分别高亮改变的寄存器值和内存字节变化。


<img width="2559" height="799" alt="image" src="https://github.com/user-attachments/assets/ab080307-4298-4438-8280-c506974520c2" />

在内存视图中可以选择字节范围，按 `E` 将内容打印到控制台。


#### 辅助视图

插件还提供了以下辅助视图：


##### 状态选择器


<img width="2547" height="1253" alt="image" src="https://github.com/user-attachments/assets/e60b7573-3259-4f23-8216-f725ffc984b1" />

使用 `C` 快捷键打开状态选择器视图。此视图显示了模拟执行期间保存的所有状态。双击条目可跳转到相应状态。


##### 内存页选择器

<img width="2242" height="1194" alt="image" src="https://github.com/user-attachments/assets/14a158b3-6249-4cf5-956e-67e69061085b" />

该插件在仿真期间对内存页面采用延迟加载机制，这意味着只有在被指令访问时才会映射和加载这些页面。

使用快捷键 `M` 打开此视图并快速确定当前状态下加载的内存页。


##### 差异选择器

![Difference chooser use examples](https://github.com/user-attachments/assets/ad40cd4b-c82a-49ca-a07d-ff22705394dd)

使用快捷键 `D` 打开差异选择器视图，该视图将会在每次切换状态时同步更新，直观显示这两个状态之间的内存和寄存器变化



#### 调试模式

<img width="2552" height="921" alt="image" src="https://github.com/user-attachments/assets/e0d2697b-3260-4e67-8aeb-8ddcaec43a80" />

该插件支持在 IDA 的调试模式下进行仿真，并可以自动加载当前寄存器值。


#### 动态反汇编

<img width="2454" height="976" alt="image" src="https://github.com/user-attachments/assets/97a2dc00-077c-4a1b-bffa-9a9221b9ee9a" />

当模拟执行流进入 IDA 未识别为可执行代码的数据段时，插件将使用 Capstone 引擎对这些数据进行反汇编。


## 支持的架构

该插件目前支持 x86 (32-bit) 和 x64 (64-bit) 架构。
未来将提供更多架构支持


## 贡献

欢迎贡献！请随时提交问题或拉取请求。
