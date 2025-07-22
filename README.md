# TimeTravelEmulator IDA Plugin

The `TimeTravelEmulator` is a powerful IDA Pro plugin that brings the concept of time-travel debugging to your reverse engineering workflow. By integrating with the Unicorn emulation framework, it provides a unique capability to record and replay program execution, allowing for detailed analysis of runtime behavior.


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


## Installation

1.  Use `pip install bsdiff4 capstone sortedcontainers unicorn` to install nessesary dependencies for this plugin in your IDAPython.
2.  Place the `TimeTravelEmulator.py` file into your IDA Pro `plugins` directory.
3.  Use hotkey `Shift+T` to open the `TimeTravel Emulator: Emulator Settings` dialog.


## Usage

Press the hotkey `Shift+T` to open the `TimeTravel Emulator: Emulator Settings` dialog.

In the settings dialog, you can:
    * Define the **Emulation Execute Range** by specifying a start and end address, or by selecting a function.
    * Adjust **Configs** such as the emulation step limit and timeout.
    * Choose whether to **load registers** from the current debugger state.
    * Configure **logging** levels and output file paths.
    * Add **custom preprocessing code** to initialize the Unicorn emulator (e.g., set up specific memory regions or registers).

Click "Emulate" to start the time-travel emulation.

Once emulation begins, you can use the following hotkeys to navigate through the recorded states:
    * `F3`: Move to the next recorded state.
    * `F2`: Move to the previous recorded state.
    * `Q`: Switch to a specific state by instruction address.


## Supported Architectures

The plugin currently supports x86 (32-bit) and x64 (64-bit) architectures.
More architectures will be added in the future.


## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.