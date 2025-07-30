# Time Travel Emulator

The `TimeTravelEmulator` is a powerful IDA Pro plugin that brings the concept of time-travel debugging to your reverse engineering workflow. By integrating with the Unicorn emulation framework, it provides a unique capability to record and replay program execution, allowing for detailed analysis of runtime behavior.

## Language

English | [中文](README.zh_CN.md)


## Features

* **Emulation powered by Unicorn**: Utilizes the Unicorn CPU emulator to execute code snippets or entire functions within IDA Pro.
* **Comprehensive State Capture**: Records detailed snapshots of the CPU registers and memory changes at each instruction executed.
* **Time Travel Debugging**:
    * **Forward and Backward Navigation**: Seamlessly step forward (F3) and backward (F2) through the execution history.
    * **State Switching**: Jump to any captured program state (Q) to analyze the exact conditions at a specific point in time.
    * **State Switching by ID**: Jump to any captured program state by entering its unique `state_id` (I). The `state_id` is formatted as `$<instruction address>#<execution count>`, allowing precise navigation.
* **Visualizing Differences**: When switching between states, the plugin highlights the memory and register differences in the plugin interface,
* **Memory and Register Tracking**: Provides visibility into how memory and register values evolve during execution.
* **Configurable Emulation**:
    * Set custom emulation ranges (start and end addresses).
    * Load initial register values from the current debugger state (if a debugger is attached).
    * Configure emulation step limits and timeouts.
    * Option to set custom preprocessing code to set up the Unicorn environment before emulation.


## Requirements

- IDA Pro version >= 7.7
- Python version >= 3.8


## Installation

1.  Use `pip install bsdiff4 capstone sortedcontainers unicorn` to install nessesary dependencies for this plugin in your IDAPython.
2.  Place the `TimeTravelEmulator.py` file into your IDA Pro `plugins` directory.
3.  Restart IDA Pro.


## Quick Start

<img width="483" height="585" alt="image" src="https://github.com/user-attachments/assets/315d56fe-7599-49b0-a9c1-b2285d43b8a8" />

Press the hotkey `Shift+T` to open the `TimeTravel Emulator: Emulator Settings` dialog.

After the setting is completed, You can click "Emulate" to start the time-travel emulation.

<img width="2300" height="1020" alt="image" src="https://github.com/user-attachments/assets/053cee98-c4a0-4146-b3ab-c28bfcef4ad3" />

Once emulation is completed, the plugin will create a independent view, you can use the following hotkeys to navigate through the recorded states in this view:
* `F3`: Move to the next recorded state.
* `F2`: Move to the previous recorded state.
* `Q`: Switch to a specific state by the instruction position where the cursor is located.

## More Details
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

Source code of a simple program for emulation.

### Emulator Settings dialog
<img width="2312" height="1281" alt="image" src="https://github.com/user-attachments/assets/f30f80ac-c19a-4dc0-9fd0-a61201993bf1" />

Opening the emulation settings dialog by selecting code and using `Shift+T`.

In the settings dialog, configure the emulation parameters:

* **Emulation Execute Range**: Specify a start and end address, or select a function as the emulation range.
* **Emulate step limit**: Set a limit on the number of instructions to emulate.
* **Emulate time out**: Set a time limit for the emulation run.
* **load registers**: Choose whether to load current register values (effective in debug mode).
* **Set Stack value**: Configure special stack frame register values.

* **Skip interrupts**: Skip `int` instructions during simulation
* **Skip unloaded calls**: Skip the call instructions whose target address not loaded
* **Skip thunk functions**: Skip thunk functions during simulation

* **Log level & Log file path**: Set logging level and save location for logs.

<img width="1652" height="971" alt="image" src="https://github.com/user-attachments/assets/a57468de-f946-448c-8bcd-8300ef4d79e9" />

* **Set custom preprocessing code**: Add custom Python code to execute before emulation. This can be used to set up memory, register values, or add hooks.


### Time Travel Emulator View
![recording 4](https://github.com/user-attachments/assets/51ed9758-250c-44a7-a5b5-a98a99dfd250)

Click "Emulate" to start the emulation. When the emulation is completed, a new window will open displaying the disassembly, register, and memory views, starting from the first emulated state.

#### Disassembly View
<img width="2325" height="1054" alt="image" src="https://github.com/user-attachments/assets/125d0e5f-747a-4ea1-a6e0-2e6943731aa0" />

This is the core view, highlighting the currently executed assembly instruction line. The number on the far left indicates how many times the current instruction has been executed throughout the emulation.

Use the following hotkeys for navigation:
  * `F3`: Move to the next recorded state.
  * `F2`: Move to the previous recorded state.
  * `Q`:  Jump to the state corresponding to the instruction at the cursor.
  * `I`:  Prompt to enter a `state_id` (e.g., `$0x401000#5`) to jump to a specific state.

#### Register View and Memory View

![Register View and Memory View examples](https://github.com/user-attachments/assets/fbcfc301-c639-4f85-a4cf-891909189011)


When switching between states, these views will highlight the changed register values and memory bytes respectively, making it easy to identify differences.

<img width="2559" height="799" alt="image" src="https://github.com/user-attachments/assets/ab080307-4298-4438-8280-c506974520c2" />

In the memory view, you can select a range of bytes and press `E` to print the content to the console.

#### Auxiliary Views

The plugin also provides the following auxiliary views:

##### State Chooser

<img width="2547" height="1253" alt="image" src="https://github.com/user-attachments/assets/e60b7573-3259-4f23-8216-f725ffc984b1" />

Use the hotkey `C` to open the state chooser view. This view displays all saved states during the emulation. Double-click an entry to jump to the corresponding state.

##### Memory Page Chooser

<img width="2242" height="1194" alt="image" src="https://github.com/user-attachments/assets/14a158b3-6249-4cf5-956e-67e69061085b" />

The plugin employs a lazy-loading mechanism for memory pages during emulation, meaning pages are mapped and loaded only when accessed by an instruction.

Use hotkey `M` to open this view and quickly ascertain the memory pages loaded in the current state.


##### Difference Chooser

![Difference chooser use examples](https://github.com/user-attachments/assets/ad40cd4b-c82a-49ca-a07d-ff22705394dd)

Use hotkey `D` to open the difference chooser view. This view automatically updates when switching states, providing a clear visual representation of memory and register changes between the two states.


#### Debugging Mode

<img width="2552" height="921" alt="image" src="https://github.com/user-attachments/assets/e0d2697b-3260-4e67-8aeb-8ddcaec43a80" />

The plugin supports emulation in IDA's debugging mode and can automatically load the current register values.

#### Dynamic Disassembly

<img width="2454" height="976" alt="image" src="https://github.com/user-attachments/assets/97a2dc00-077c-4a1b-bffa-9a9221b9ee9a" />


When the simulation execution flow enters a segment of data that the IDA does not recognize as executable code, the plugin disassembles the data using the Capstone engine.


## Supported Architectures

The plugin currently supports x86 (32-bit) and x64 (64-bit) architectures.
More architectures will be added in the future.


## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.
