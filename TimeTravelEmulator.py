import idaapi
import ida_ida
import ida_kernwin
import ida_dbg
import idc
import ida_name
import ida_bytes
import ida_lines
import ida_segment

import logging
import bisect
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Callable, Dict, Iterator, List, Literal, Optional, Set, Tuple, Union
from copy import deepcopy
from dataclasses import dataclass
from re import split

import bsdiff4
from sortedcontainers import SortedDict, SortedList
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from PyQt5 import QtCore, QtWidgets



VERSION = '1.1.1'

PLUGIN_NAME = 'TimeTravelEmulator'
PLUGIN_HOTKEY = 'Shift+T'

NEXT_STATE_ACTION_SHORTCUT = "F3"
PREV_STATE_ACTION_SHORTCUT = "F2"
CURSOR_STATE_ACTION_SHORTCUT = "Q"


EXECUTE_INSN_HILIGHT_COLOR = 0xFFD073
CHANGE_HIGHLIGHT_COLOR   = 0xFFD073
BYTE_CHANGE_HIGHTLIGHT = ida_kernwin.CK_EXTRA11



# Define page size and page mask, usually 4 kb
PAGE_SIZE = 0x1000
PAGE_MASK = ~(PAGE_SIZE - 1)

# Define default page permission
DEFAULT_PAGE_PERMISSION = UC_PROT_WRITE | UC_PROT_READ

# Define default stack and frame values
DEFAULT_STACK_POINT_VALUE = 0x70000000
DEFAULT_BASE_POINT_VALUE = DEFAULT_STACK_POINT_VALUE


UNICORN_ARCH_MAP =      {
            "x64": [UC_ARCH_X86, UC_MODE_64],
            "x86": [UC_ARCH_X86, UC_MODE_32],
}

CAPSTONE_ARCH_MAP = {
    "x64": [CS_ARCH_X86, CS_MODE_64],
    "x86": [CS_ARCH_X86, CS_MODE_32]
}

IDA_PROC_TO_ARCH_MAP = {
    ("metapc", 64) : "x64",
    ("metapc", 32) : "x86",
}

ARCH_TO_INSN_POINTER_MAP = {
    "x64" : UC_X86_REG_RIP,
    "x86" : UC_X86_REG_EIP,
}


UNICORN_REGISTERS_MAP = {
    "x64" : {
        # General Purpose Registers (GPRs)
        "RAX": UC_X86_REG_RAX,
        "RBX": UC_X86_REG_RBX,
        "RCX": UC_X86_REG_RCX,
        "RDX": UC_X86_REG_RDX,
        "RSI": UC_X86_REG_RSI,
        "RDI": UC_X86_REG_RDI,
        "RBP": UC_X86_REG_RBP,
        "RSP": UC_X86_REG_RSP,
        "RIP": UC_X86_REG_RIP,
        "R8": UC_X86_REG_R8,
        "R9": UC_X86_REG_R9,
        "R10": UC_X86_REG_R10,
        "R11": UC_X86_REG_R11,
        "R12": UC_X86_REG_R12,
        "R13": UC_X86_REG_R13,
        "R14": UC_X86_REG_R14,
        "R15": UC_X86_REG_R15,
        # Instruction Pointer
        # Flags Register
        "Rflags": UC_X86_REG_EFLAGS, # In 64-bit, EFLAGS is extended to RFLAGS, but the constant remains EFLAGS
        # Segment Registers
        "CS": UC_X86_REG_CS,
        "SS": UC_X86_REG_SS,
        "DS": UC_X86_REG_DS,
        "ES": UC_X86_REG_ES,
        "FS": UC_X86_REG_FS,
        "GS": UC_X86_REG_GS,
    },
    "x86": {
        # General Purpose Registers (GPRs)
        "EAX": UC_X86_REG_EAX,
        "EBX": UC_X86_REG_EBX,
        "ECX": UC_X86_REG_ECX,
        "EDX": UC_X86_REG_EDX,
        "ESI": UC_X86_REG_ESI,
        "EDI": UC_X86_REG_EDI,
        "EBP": UC_X86_REG_EBP,
        "ESP": UC_X86_REG_ESP,
        # Instruction Pointer
        "EIP": UC_X86_REG_EIP,
        # Flags Register
        "Eflags": UC_X86_REG_EFLAGS,
        # Segment Registers
        "CS": UC_X86_REG_CS,
        "SS": UC_X86_REG_SS,
        "DS": UC_X86_REG_DS,
        "ES": UC_X86_REG_ES,
        "FS": UC_X86_REG_FS,
        "GS": UC_X86_REG_GS,
    }
}

IP_REG_NAME_MAP = {
    "x64": "RIP",
    "x86": "EIP"
}

IDA_PERM_TO_UC_PERM_MAP = {
    ida_segment.SEGPERM_EXEC : UC_PROT_EXEC,
    ida_segment.SEGPERM_WRITE : UC_PROT_WRITE,
    ida_segment.SEGPERM_READ : UC_PROT_READ
}


def get_bitness() -> Union[None, Literal[64], Literal[32]]:
    if ida_ida.inf_is_64bit():
        return 64
    elif ida_ida.inf_is_32bit_exactly():
        return 32

def get_is_be() -> bool:
        return ida_ida.inf_is_be()

def get_arch() -> str:
    proc_name = idaapi.inf_get_procname()
    proc_bitness = get_bitness()

    if proc_bitness == None:
        return ""
    if (proc_name, proc_bitness) not in IDA_PROC_TO_ARCH_MAP:
        return ""
    return IDA_PROC_TO_ARCH_MAP[(proc_name, proc_bitness)]


def get_arch_x64_regs_value() -> Dict[int, int]:
    if not idaapi.is_debugger_on():
        return {}
    arch = get_arch()
    if arch not in UNICORN_REGISTERS_MAP:
        return {}

    result: Dict[int, int] = {}
    regs_map =  UNICORN_REGISTERS_MAP[arch]
    for reg_name, uc_reg_const in regs_map.items():
        if reg_name == "Rflags":
            flag_positions = {
                "CF": 0,    # Carry Flag
                "PF": 2,    # Parity Flag
                "AF": 4,    # Auxiliary Carry Flag
                "ZF": 6,    # Zero Flag
                "SF": 7,    # Sign Flag
                "TF": 8,    # Trap Flag
                "IF": 9,    # Interrupt Enable Flag
                "DF": 10,   # Direction Flag
                "OF": 11,   # Overflow Flag
                "IOPL": 12, # I/O Privilege Level (Usually two bit)
                "NT": 14,   # Nested Task Flag
                "RF": 16,   # Resume Flag
                "VM": 17,   # Virtual-8086 Mode Flag
                "AC": 18,   # Alignment Check / Access Control Flag
                "VIF": 19,  # Virtual Interrupt Flag
                "VIP": 20,  # Virtual Interrupt Pending
                "ID": 21    # ID Flag
            }
            rflags_value = 0
            for flag_name, bit_pos in flag_positions.items():
                try:
                    flag_val = ida_dbg.get_reg_val(flag_name)

                    if flag_val is not None:
                        if flag_name == "IOPL":
                            rflags_value |= ((flag_val & 0x3) << bit_pos)
                        else:
                            if flag_val == 1:
                                rflags_value |= (1 << bit_pos)
                except Exception as e:
                    continue
            result[uc_reg_const] = rflags_value
        elif reg_name in ["FS", "GS"]:
            continue
        else:
            try:
                reg_value = ida_dbg.get_reg_val(reg_name)
                result[uc_reg_const] = reg_value
            except Exception as e:
                tte_log_err(f"Error getting register value for {reg_name}: {e}")
                pass
    return result


def get_arch_x86_regs_value() -> Dict[int, int]:
    if not idaapi.is_debugger_on():
        return {}
    arch = get_arch()
    if arch not in UNICORN_REGISTERS_MAP:
        return {}

    result: Dict[int, int] = {}
    regs_map =  UNICORN_REGISTERS_MAP[arch]
    for reg_name, uc_reg_const in regs_map.items():
        if reg_name == "Eflags":
            flag_positions = {
                "CF": 0,    # Carry Flag
                "PF": 2,    # Parity Flag
                "AF": 4,    # Auxiliary Carry Flag
                "ZF": 6,    # Zero Flag
                "SF": 7,    # Sign Flag
                "TF": 8,    # Trap Flag
                "IF": 9,    # Interrupt Enable Flag
                "DF": 10,   # Direction Flag
                "OF": 11,   # Overflow Flag
                "IOPL": 12, # I/O Privilege Level (Usually two bit)
                "NT": 14,   # Nested Task Flag
                "RF": 16,   # Resume Flag
                "VM": 17,   # Virtual-8086 Mode Flag
                "AC": 18,   # Alignment Check / Access Control Flag
                "VIF": 19,  # Virtual Interrupt Flag
                "VIP": 20,  # Virtual Interrupt Pending
                "ID": 21    # ID Flag
            }
            rflags_value = 0
            for flag_name, bit_pos in flag_positions.items():
                try:
                    flag_val = ida_dbg.get_reg_val(flag_name)

                    if flag_val is not None:
                        if flag_name == "IOPL":
                            rflags_value |= ((flag_val & 0x3) << bit_pos)
                        else:
                            if flag_val == 1:
                                rflags_value |= (1 << bit_pos)
                except Exception as e:
                    continue
            result[uc_reg_const] = rflags_value
        elif reg_name in ["CS", "SS", "DS", "ES", "FS", "GS"]:
            continue
        else:
            try:
                reg_value = ida_dbg.get_reg_val(reg_name)
                result[uc_reg_const] = reg_value
            except Exception as e:
                tte_log_err(f"Error getting register value for {reg_name}: {e}")
                pass
    return result


def get_page_slice(page_start: int, page_size: int) -> List[Tuple[int, int]]:
    """
    Get a slice of segments address of a memory page

    :param page_start: Start address of the memory page. Must be page aligned.
    :param page_size: Size of the memory page
    :return: A list, where the value is a list of tuples (start_ea, end_ea) of the segments slice in the page.
    """
    result: List[Tuple[int, int]] = []
    seg = ida_segment.get_first_seg()
    page_end = page_start + page_size
    while seg:
        if seg.start_ea >= page_end:
            break
        # Check for overlap:
        # (seg.start_ea <= end_address) and (seg.end_ea >= start_address)
        if seg.start_ea < page_end - 1 and seg.end_ea > page_start:
            max_addr = max(seg.start_ea, page_start)
            min_addr = min(seg.end_ea, page_end - 1)
            result.append((max_addr, min_addr))
        seg = ida_segment.get_next_seg(seg.end_ea -1 ) # -1 to ensure next segment is properly found

    return result


def get_segment_prem(addr: int) -> int: # [ ] TODO: The segments of the program are not always page-aligned, so this situation needs to be considered
    seg = ida_segment.getseg(addr)
    if seg is not None:
        ida_perm = seg.perm
        uc_perm = 0
        for ida_bit, uc_bit in IDA_PERM_TO_UC_PERM_MAP.items():
            if ida_perm & ida_bit:
                uc_perm |= uc_bit
        return uc_perm
    return DEFAULT_PAGE_PERMISSION


def catch_dict_patch(
        base_dict: Dict[str, int],
        target_dict: Dict[str, int]
) -> Dict[str, int]:
    """
    Compare the two dictionaries and return different key-value pairs of target_dict relative to base_dict.
    Prerequisite: Two dictionaries have exactly the same set of keys.
    Returns the key-value pair contains only the changed values.
    """
    return {key: target_dict[key] for key in base_dict if base_dict[key] != target_dict[key]}


def apply_dict_patch(
        base_dict: Dict[str, int],
        patch: Optional[Dict[str, int]]
) -> Dict[str, int]:
    result = base_dict.copy()
    if patch is not None:
        result.update(patch)
    return result


def catch_bytes_patch(
        base_bytes_dict: Dict[int, Tuple[int, bytearray]], #
        target_bytes_dict: Dict[int, Tuple[int, bytearray]]
) -> Tuple[Dict[int, Tuple[int, bytes]], Dict[int, Tuple[int, bytearray]]]:
    """
    Compare the two byte dictionaries and return different key-value pairs of target_bytes relative to base_bytes.

    :param base_bytes_dict: Original dictionary of bytes  {addr: (permission, data)}
    :param target_bytes_dict: Dictionary of bytes to be compared with base_bytes_dict  {addr: (permission, data)}
    :return patches: Dictionary of binary diffs for modified keys  {addr: (permission, patch)}
    :return new_entries: Dictionary of new key-value pairs  {addr: (permission, data)}
    """
    patches: Dict[int, Tuple[int, bytes]] = {}
    new_entries: Dict[int, Tuple[int, bytearray]] = {}


    for addr, (permossion, target_bytes) in target_bytes_dict.items():
        entry = base_bytes_dict.get(addr)
        if entry is None:
            new_entries[addr] = (permossion, target_bytes)
            continue
        _, base_bytes = entry
        if base_bytes != target_bytes:
            patches[addr] = (permossion, bsdiff4.diff(bytes(base_bytes), bytes(target_bytes)))
        else:
            patches[addr] = (permossion, b'')

    return patches, new_entries


def apply_bytes_patch(
        base_bytes_dict: Dict[int, Tuple[int, bytearray]],
        patches: Dict[int, Tuple[int, bytes]],
        new_entries: Dict[int, Tuple[int, bytearray]]
) -> Dict[int, Tuple[int, bytearray]]:
    """
    Apply the generated patches to the base data dictionary and merge new entries.

    :param base_bytes_dict: Original dictionary of bytes  {addr: (permission, data)}
    :param patches: Dictionary of binary diffs for modified keys  {addr: (permission, patch)}
    :param new_entries: Dictionary of new key-value pairs  {addr: (permission, data)}
    :return updated_dict: Updated dictionary with applied diffs and new entries  {addr: (permission, data)}
    """
    updated_dict: Dict[int, Tuple[int, bytearray]] = dict(base_bytes_dict)

    for addr, (permossion, patch) in patches.items():
        if patch == b'':
            continue
        key_data = updated_dict.get(addr)
        assert key_data is not None, f"Error: key {addr} not found in base_bytes_dict"
        _, original_data = key_data
        try:
            patched_data = bsdiff4.patch(bytes(original_data), patch)
            updated_dict[addr] = (permossion, bytearray(patched_data))
        except Exception as e:
            raise RuntimeError(f"Error applying patch to key {addr}: {e}")

    updated_dict.update(new_entries)
    return updated_dict




class TTE_Logger:
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(TTE_Logger, cls).__new__(cls)
        return cls._instance

    def start(self, log_level, log_file=None):
        """
        Start the logger
        :param log_file: Log file path
        :param level: Log Level
        """
        if self._initialized:
            tte_log_info("Logger already started.")
            return

        # Set logging
        self.logger = logging.getLogger('TTE_Logger')
        self.logger.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # Create handler
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        self._initialized = True
        self.log(logging.INFO, "Logger started.")

    def stop(self):
        """
        Stop the logger
        """
        if not self._initialized:
            return

        self.log(logging.INFO, "Logger stopping...")
        handlers = self.logger.handlers[:]
        for handler in handlers:
            handler.close()
            self.logger.removeHandler(handler)
        self._initialized = False

    def log(self, level, message):
        """
        Logging
        :param level: Log Level (logging.INFO, logging.ERROR)
        :param message: Information to be recorded
        """
        if not self._initialized:
            return

        self.logger.log(level, message)

def tte_log_info(message):
    """
    Logging with INFO level
    :param message: Information to be recorded
    """
    TTE_Logger().log(logging.INFO,message)

def tte_log_dbg(message):
    """
    Logging with DEBUG level
    :param message: Information to be recorded
    """
    TTE_Logger().log(logging.DEBUG,message)

def tte_log_warn(message):
    """
    Logging with WARNING level
    :param message: Information to be recorded
    """
    TTE_Logger().log(logging.WARNING,message)

def tte_log_err(message):
    """
    Logging with ERROR level
    :param message: Information to be recorded
    """
    TTE_Logger().log(logging.ERROR,message)


@dataclass
class EmuSettings():
    start: int = -1
    end: int = -1

    is_load_registers: bool = False
    is_skip_interrupts = False
    is_skip_unloaded_calls = True
    is_skip_trunk_funcs: bool = False
    is_set_stack_value: bool = False

    time_out: int = 0
    count: int = 500
    log_level: int = logging.WARNING
    log_file_path: Optional[str] = None

    preprocessing_code: str = ""


class EmuSettingsForm(idaapi.Form):

    def __init__(self, start_ea, end_ea) -> None:
        self.emu_settings = EmuSettings()

        self.i_start_address: Optional[ida_kernwin.Form.NumericInput] =  None
        self.i_end_address: Optional[ida_kernwin.Form.NumericInput] = None

        self.i_emulate_step_limit: Optional[ida_kernwin.Form.NumericInput] =  None
        self.i_time_out: Optional[ida_kernwin.Form.NumericInput] = None

        self.c_configs_group: Optional[ida_kernwin.Form.ChkGroupControl] = None
        self.r_load_register: Optional[ida_kernwin.Form.ChkGroupItemControl] = None


        self.r_skip_interrupts: Optional[ida_kernwin.Form.ChkGroupItemControl] = None
        self.r_skip_unloaded_calls: Optional[ida_kernwin.Form.ChkGroupItemControl] = None
        self.r_skip_thunk_funcs: Optional[ida_kernwin.Form.ChkGroupItemControl] = None
        self.r_set_stack_value: Optional[ida_kernwin.Form.ChkGroupItemControl] = None

        self.i_log_level: Optional[ida_kernwin.Form.DropdownListControl] = None
        self.i_log_file_path: Optional[ida_kernwin.Form.FileInput] = None


        super().__init__(
            r'''STARTITEM {id:i_start_address}
BUTTON YES* Emulate
TimeTravel Emulator: Emulator Settings

            {FormChangeCb}
            Emulation Execute Range:
            <Start address  :{i_start_address}>
            <End address    :{i_end_address}>
            <Select function range    :{b_select_function}>

            Configs:
            <Emulate step limit  :{i_emulate_step_limit}>
            <Emluate time out    :{i_time_out}>

            <load registers:{r_load_register}>
            <Set stack value:{r_set_stack_value}>
            <Skip interrupts:{r_skip_interrupts}>
            <Skip unloaded calls:{r_skip_unloaded_calls}>
            <Skip thunk functions:{r_skip_thunk_funcs}>{c_configs_group}>

            <Log level:{i_log_level}>
            <Log file path:{i_log_file_path}>


            Advanced Configs:
            <Set custom preprocessing code:{b_set_preprocessing_code}>

            ''',
            {
                'FormChangeCb': self.FormChangeCb(self._on_form_change),
                'i_start_address': self.NumericInput(self.FT_ADDR, value=start_ea,  swidth = 30),
                'i_end_address': self.NumericInput(self.FT_ADDR, value=end_ea, swidth = 30),
                'b_select_function': self.ButtonInput(self._open_select_function_dialog),

                'i_emulate_step_limit': self.NumericInput(self.FT_DEC, value=500, swidth = 30),
                "i_time_out": self.NumericInput(self.FT_DEC, value=0, swidth = 30),
                'c_configs_group': self.ChkGroupControl(("r_load_register", "r_set_stack_value", "r_skip_interrupts", "r_skip_unloaded_calls", "r_skip_thunk_funcs")),


                'i_log_level': self.DropdownListControl(
                    items=["DEBUG", "INFO", "WARNING", "ERROR"],
                    readonly=True,
                    selval=2
                ),
                'i_log_file_path': self.FileInput(save=True, swidth=30),

                'b_set_preprocessing_code': self.ButtonInput(self._add_preprocessing_code)
            }
         )
        self.Compile()
        self.set_default_values()


    def _on_form_change(self, fid: int):
        assert self.r_load_register is not None, "r_load_register is not initialized"
        assert self.r_skip_thunk_funcs is not None, "r_skip_thunk_funcs is not initialized"

        # Init
        if fid == -1:
            if not idaapi.is_debugger_on():
                self.EnableField(self.r_load_register, False)
            else:
                self.EnableField(self.r_load_register, True)


        # Click Yes
        elif fid == -2:
            ok = self._set_emu_range()
            if not ok:
                return 0
            self._set_setting_result()
            return 1

        return 1


    def set_default_values(self):
        assert self.r_load_register is not None \
            and self.r_set_stack_value is not None \
            and self.r_skip_interrupts is not None \
            and self.r_skip_unloaded_calls is not None \
            and self.r_skip_thunk_funcs is not None \

        self.preprocessing_code: str = "mu: unicorn.Uc = emu_executor.get_mu()"

        if idaapi.is_debugger_on():
            self.r_load_register.checked = True
            self.r_set_stack_value.checked = False
        else:
            self.r_load_register.checked = False
            self.r_set_stack_value.checked = True
            self.r_skip_thunk_funcs.checked = True

        self.r_skip_interrupts.checked = True
        self.r_skip_unloaded_calls.checked = True


    def _open_select_function_dialog(self, code = 0):
        target_func =  ida_kernwin.choose_func("Select target function range",1)
        if not target_func:
            return

        self._set_emu_range(target_func.start_ea, target_func.end_ea)


    def _add_preprocessing_code(self, code = 0):

        class PreprocessingCodeForm(ida_kernwin.Form):
            def __init__(self, default_multiline_text: str = ""):
                self.i_multiline_text: Optional[ida_kernwin.Form.MultiLineTextControl] = None
                self.i_load_file: Optional[ida_kernwin.Form.ButtonInput] = None
                self.i_save_file: Optional[ida_kernwin.Form.ButtonInput] = None
                super().__init__(
                    r"""STARTITEM {id:i_multiline_text}
BUTTON YES* OK
BUTTON NO Cancel
Preprocessing Code Input

        {FormChangeCb}
        <##Enter your preprocessing code here:{i_multiline_text}>
        <Load from file:{i_load_file}> <Save to file:{i_save_file}>
        """, {
                    'FormChangeCb': self.FormChangeCb(self.OnFormChange),
                    'i_multiline_text': self.MultiLineTextControl(text=default_multiline_text,
                                                                  flags = ida_kernwin.Form.MultiLineTextControl.TXTF_FIXEDFONT | \
                                                                  ida_kernwin.Form.MultiLineTextControl.TXTF_ACCEPTTABS,
                                                                  tabsize = 4,
                                                                  width = 120,
                                                                  swidth = 100),
                    'i_load_file': self.ButtonInput(self.OnLoadFile),
                    'i_save_file': self.ButtonInput(self.OnSaveFile),
                })
                self.Compile()
                self.user_input_text = ""

            def OnLoadFile(self, code=0):
                file_path = ida_kernwin.ask_file(False, "*.*", "Select a file to load")
                if file_path:
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            textctrl = ida_kernwin.textctrl_info_t(content)
                            self.SetControlValue(self.i_multiline_text, textctrl)
                            idaapi.msg(f"Loaded content from {file_path}\n")
                    except Exception as e:
                        ida_kernwin.warning(f"Failed to load file: {e}")
                else:
                    idaapi.msg("No file selected for loading.\n")

            def OnSaveFile(self, code=0):
                file_path = ida_kernwin.ask_file(True, "*.*", "Select a file to save to")
                if file_path:
                    try:
                        textctrl = self.GetControlValue(self.i_multiline_text)
                        with open(file_path, 'w') as f:
                            f.write(textctrl.text)
                        idaapi.msg(f"Saved content to {file_path}\n")
                    except Exception as e:
                        ida_kernwin.warning(f"Failed to save file: {e}")
                else:
                    idaapi.msg("No file selected for saving.\n")

            def OnFormChange(self, fid):
                assert self.i_multiline_text is not None, "i_multiline_text is not initialized"

                if fid == -2: # OnFormChange is called with -2 on form close
                    self.user_input_text = self.GetControlValue(self.i_multiline_text).text
                return 1

            def get_user_text(self):
                """
                Public method to retrieve the user's input after the form is closed.
                """
                return self.user_input_text

        form = PreprocessingCodeForm(self.preprocessing_code)
        ok = form.Execute()
        if ok == 1:
            self.preprocessing_code = form.get_user_text()
        form.Free()


    def _set_emu_range(self, start: int = -1, end: int = -1):
        # set range by parameters
        if start != -1 and end != -1:
            start_t = start
            end_t = end

        # set range by edit input
        else:
            try:
                if self.i_start_address is None or self.i_end_address is None:
                    ida_kernwin.warning("Address input controls are not initialized.")
                    return 0
                start_t: Optional[int] =  self.GetControlValue(self.i_start_address) # type: ignore
                end_t: Optional[int] =  self.GetControlValue(self.i_end_address) # type: ignore
                if not start_t or not end_t:
                    raise ValueError()
            except ValueError:
                ida_kernwin.warning("Invalid Input: Please enter valid hexadecimal addresses.")
                return 0

        if start_t < ida_ida.inf_get_min_ea() or end_t > ida_ida.inf_get_max_ea():
            y = ida_kernwin.ask_yn(2, "Invalid Range: Address out of range, continute?")
            if y == 0:
                return 0

        # set range
        self.sim_range_start = start_t
        self.sim_range_end = end_t

        if start != -1 and end != -1:
            self.SetControlValue(self.i_start_address, start_t)
            self.SetControlValue(self.i_end_address, end_t)
        return 1


    def _set_setting_result(self):
        if self.i_emulate_step_limit is None or \
           self.c_configs_group is None or \
           self.i_time_out is None or \
           self.r_load_register is None or \
           self.r_skip_interrupts is None or \
           self.r_skip_unloaded_calls is None or \
           self.r_skip_thunk_funcs is None or \
           self.r_set_stack_value is None or \
           self.i_log_level is None or \
           self.i_log_file_path is None:
            ida_kernwin.warning("Form controls are not initialized.")
            return None

        self.emu_settings.start = self.sim_range_start
        self.emu_settings.end = self.sim_range_end

        self.emu_settings.count = self.GetControlValue(self.i_emulate_step_limit) # type: ignore
        self.emu_settings.time_out = self.GetControlValue(self.i_time_out) # type: ignore

        self.emu_settings.is_load_registers = self.GetControlValue(self.r_load_register) # type: ignore
        self.emu_settings.is_skip_interrupts = self.GetControlValue(self.r_skip_interrupts) # type: ignore
        self.emu_settings.is_skip_unloaded_calls = self.GetControlValue(self.r_skip_unloaded_calls) # type: ignore
        self.emu_settings.is_skip_trunk_funcs = self.GetControlValue(self.r_skip_thunk_funcs) # type: ignore
        self.emu_settings.is_set_stack_value = self.GetControlValue(self.r_set_stack_value) # type: ignore

        self.emu_settings.preprocessing_code = self.preprocessing_code

        log_level_map = {
            0: logging.DEBUG,
            1: logging.INFO,
            2: logging.WARNING,
            3: logging.ERROR,
        }

        log_level_value: int = self.GetControlValue(self.i_log_level) # type: ignore
        self.emu_settings.log_level = log_level_map.get(log_level_value, logging.WARNING)
        self.emu_settings.log_file_path = self.GetControlValue(self.i_log_file_path) # type: ignore


    def GetSetting(self):
        return self.emu_settings



class EmuExecutor():
    """
    A simulation executor class used to manage the operation of the entire program, including initialization, loading, running, saving, etc.
    """

    def __init__(self, settings: EmuSettings) -> None:
        self._is_initialized = False

        self.arch = get_arch()
        self.unicorn_arch, self.unicorn_mode = UNICORN_ARCH_MAP[self.arch]
        self.is_be = get_is_be()

        self.settings = settings
        tte_log_info("Create EmuExecutor: arch-{}, mode-{}".format(self.unicorn_arch, self.unicorn_mode))

        self.loaded_pages: Set[int] = set() # Set(page_start)

        self.emu_map_mem_callback = []
        self.emu_run_end_callback = []
        self.mu_hook_handlers = []


    def init(self) -> None:
        """
        Initialize Unicorn emulation, the method must be called before calling other methods.
        """
        if self._is_initialized:
            tte_log_info("EmuExecutor already initialized.")
            return

        # Unicorn instance creation
        self.mu = unicorn.Uc(self.unicorn_arch, self.unicorn_mode)

        # Memory mapping and data loading
        self._map_and_load_binary(self.settings.start, self.settings.end)

        # Register initialization
        self._set_regs_init_value()

        # Hooks setting
        if self.settings.is_skip_interrupts:
            self._hook_skip_interrupt()
        if self.settings.is_skip_trunk_funcs:
            self._hook_skip_thunk_funcs()
        if self.settings.is_skip_unloaded_calls:
            self._hook_skip_unloaded_call()
        self._hook_mem_unmapped()

        self._is_initialized = True


    @staticmethod
    def execute_preprocessing_code(preprocessing_code, emu_executor: 'EmuExecutor') -> int:
        """
        Execute the preprocessing code.
        """
        if(len(preprocessing_code) == 0):
            return 1
        # idaapi.msg("Executing preprocessing code...\n")
        try:
            exec(preprocessing_code)
        except Exception as e:
            idaapi.msg(f"Error executing preprocessing code: {e}\n")
            return idaapi.ask_yn(0, f"Error executing preprocessing code: {e}\nDo you want to continue?")

        mem_regions_iter = emu_executor.get_mu().mem_regions()
        for page_start, page_end, perm in mem_regions_iter:
            current_addr = page_start
            while current_addr < page_end:
                emu_executor.loaded_pages.add(current_addr & PAGE_MASK)
                current_addr += PAGE_SIZE

        return 1


    def get_mu(self):
        return self.mu


    def add_mu_hook(self, htype: int, callback, user_data = None, begin: int = 1, end: int = 0) -> None:
        handler = self.mu.hook_add(htype, callback, user_data, begin, end)
        self.mu_hook_handlers.append(handler)


    def _is_memory_mapped(self, address) -> bool:
        # return any(map_start <= address < map_end for map_start, map_end, _ in self.mu.mem_regions())
        return (address & PAGE_MASK) in self.loaded_pages


    def _map_memory(self, map_start, map_size) -> None:
        """
        Map memory pages for the given range.

        :param map_start: Start address of the mapping. Must be page aligned.
        :param map_size: Size of the mapping. Must be page aligned.
        """
        for page_start in range(map_start, map_start + map_size, PAGE_SIZE):
            if self._is_memory_mapped(page_start):
                continue
            try:
                perm = get_segment_prem(page_start)
                self.mu.mem_map(page_start, PAGE_SIZE, perm)
                tte_log_info(f"Map memory: 0x{page_start:X}~0x{page_start + PAGE_SIZE - 1 :X} by permission {perm}")
            except UcError as e:
                tte_log_warn(f"Mapping memory failed: {e}")

            for callback in self.emu_map_mem_callback:
                callback(self.mu)


    def _load_binary(self, load_seg_start, load_seg_end) -> None:
        """
        Map memory pages for the given range.

        :param load_seg_start: Start address of the binary data to load.
        :param load_seg_end: End address of the binary data to load.
        """

        seg_data = ida_bytes.get_bytes(load_seg_start, load_seg_end - load_seg_start + 1)
        if seg_data:
            try:
                self.mu.mem_write(load_seg_start, seg_data)
            except UcError as e:
                tte_log_info(f"Writing segment failed 0x{load_seg_start:X}~0x{load_seg_end:X}: {e}")
        else:
            tte_log_warn(f"Warning: Section 0x{load_seg_start:X}~0x{load_seg_end:X} No data")


    def _map_and_load_binary(self, start_ea, end_ea) -> None:
        tte_log_dbg(f"Start map and load binary: 0x{start_ea:X}~0x{end_ea:X}")

        end_ea = min(end_ea, start_ea + PAGE_SIZE * 8)
        map_start = start_ea & PAGE_MASK
        map_size = (end_ea - map_start + PAGE_SIZE - 1) & PAGE_MASK

        self._map_memory(map_start, map_size)
        # if not is_address_range_loaded(start_ea, end_ea):
        #     return

        for page_start in range(map_start, map_start + map_size, PAGE_SIZE):
            if page_start not in self.loaded_pages:
                load_range_list = get_page_slice(page_start, PAGE_SIZE)
                for start_ea, end_ea in load_range_list:
                    self._load_binary(start_ea, end_ea )
                    tte_log_info(f"Load binary segments {ida_segment.get_segm_name(idaapi.getseg(start_ea))}: 0x{start_ea:X}~0x{end_ea:X}")


    def _hook_mem_unmapped(self) -> None:
        def cb_map_mem_unmapped(uc, access, address, size, value, user_data) -> bool:
            if access == UC_MEM_READ_UNMAPPED:
                tte_log_info(f"Hook callback: Try to read the unmapped memory at 0x{address:X}, size {size}")
            elif access == UC_MEM_WRITE_UNMAPPED:
                tte_log_info(f"Hook callback: Try to write the unmapped memory at 0x{address:X}, size {size}, value 0x{value:X}")
            elif access == UC_MEM_FETCH_UNMAPPED:
                tte_log_info(f"Hook callback: Try to fetch the unmapped memory at 0x{address:X}, size {size}")

            try:
                tte_log_info(f"Hook callback: Map memory during running: 0x{address:X}, 0x{size:X}")
                self._map_and_load_binary(address, address + size)
                return True

            except UcError as e:
                tte_log_err(f"Hook callback: Mapping memory failed: {e}")
                return False

        self.add_mu_hook(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, cb_map_mem_unmapped)


    def _hook_skip_interrupt(self) -> None:
        def cb_skip_interrupt(uc, intno, user_data) -> bool:
            tte_log_info(f"Hook callback: Skip interrupt: {intno}")
            return True

        self.add_mu_hook(UC_HOOK_INTR, cb_skip_interrupt)


    def _hook_skip_thunk_funcs(self) -> None:

        def execute_x86_ret(uc):
            if self.unicorn_mode == UC_MODE_64:
                stack_pointer_value = uc.reg_read(UC_X86_REG_RSP)
                return_address_bytearray = uc.mem_read(stack_pointer_value, 8)
                return_address_int = int.from_bytes(return_address_bytearray, byteorder='big' if self.is_be else 'little',  signed=False)

                uc.reg_write(UC_X86_REG_RIP, return_address_int)
                uc.reg_write(UC_X86_REG_RSP, stack_pointer_value + 8)

                tte_log_info(f"Hook callback: Jump to return address: 0x{return_address_int:X}")
                return

            elif self.unicorn_mode == UC_MODE_32:
                stack_pointer_value = uc.reg_read(UC_X86_REG_ESP)
                return_address_bytearray = uc.mem_read(stack_pointer_value, 4)
                return_address_int = int.from_bytes(return_address_bytearray, byteorder='big' if self.is_be else 'little',  signed=False)

                uc.reg_write(UC_X86_REG_EIP, return_address_int)
                uc.reg_write(UC_X86_REG_ESP, stack_pointer_value + 4)

                tte_log_info(f"Hook callback: Jump to return address: 0x{return_address_int:X}")
                return

            else:
                return

        def cb_skip_thunk_func_call(uc, address, size, user_data):

            flags = idc.get_func_attr(address, idc.FUNCATTR_FLAGS)
            if flags == idaapi.BADADDR:
                return False
            is_thunk_function = (flags & idaapi.FUNC_THUNK) != 0

            # If the function is a thunk function, detect the return address on the stack and jump to it.
            if is_thunk_function:
                tte_log_info(f"Hook callback: Skip thunk function at 0x{address:X}")
                if self.unicorn_arch == UC_ARCH_X86:
                    execute_x86_ret(uc)

        self.add_mu_hook(UC_HOOK_CODE, cb_skip_thunk_func_call)


    def _hook_skip_unloaded_call(self) -> None:

        def get_x86_call_target(uc, insn_bytes, address, size):
            target_address = -1
            if insn_bytes[0] == 0xE8: # Direct call
                relative_offset = int.from_bytes(insn_bytes[1:5], byteorder = 'big' if self.is_be else 'little', signed=True)
                target_address = address + size + relative_offset
                tte_log_dbg(f"Direct call to 0x{target_address:X}")

            elif insn_bytes[0] == 0xFF: # Indirect call
                insn = None
                try:
                    insn = next(InstrctionParser().parse_instructions(insn_bytes))
                except StopIteration:
                    return

                op_str = insn.op_str
                if '[' not in op_str: # register indirect calls
                    register_id = UNICORN_REGISTERS_MAP[self.arch].get(op_str.upper(), -1)
                    if register_id != -1:
                        target_address = uc.reg_read(register_id)

                else: # memory indirect call
                    pass # TODO: support memory indirect call calculation
                    # reg_or_mem = op_str.strip('[]')
                    # mem_addr = uc.reg_read(self.get_register_id(reg_or_mem))
                    # target_address = int.from_bytes(uc.mem_read(mem_addr, uc.mode // 8), byteorder='little')

                tte_log_dbg(f"Indirect call to 0x{target_address:X}")
            return target_address

        def cb_check_call_target_loaded_and_skip(uc, address, size, user_data):
            insn_bytes = uc.mem_read(address, size)

            target_address = -1
            if self.unicorn_arch == UC_ARCH_X86:
                if insn_bytes[0] not in [0xE8, 0xFF]: # Not a call instruction
                    return False
                target_address = get_x86_call_target(uc, insn_bytes, address, size)

            if target_address == -1:
                return

            elif not ida_bytes.is_loaded(target_address):
                tte_log_dbg(f"Hook callback: Skip unloaded call target: 0x{target_address:X}")
                current_insn_address = uc.reg_read(ARCH_TO_INSN_POINTER_MAP[self.arch])
                uc.reg_write(ARCH_TO_INSN_POINTER_MAP[self.arch], current_insn_address + size)

        self.add_mu_hook( UC_HOOK_CODE, cb_check_call_target_loaded_and_skip)


    def _set_regs_init_value(self) -> None:
        if not self.settings.is_load_registers and self.settings.is_set_stack_value and self.unicorn_arch == UC_ARCH_X86: # Set default stack value in x86 mode
            offset = 0
            while(self._is_memory_mapped(DEFAULT_STACK_POINT_VALUE + offset)):
                offset += 0x1000000
            if self.unicorn_mode == UC_MODE_64:
                stack_point, frame_point  = UNICORN_REGISTERS_MAP[self.arch]['RSP'], UNICORN_REGISTERS_MAP[self.arch]['RBP']
            elif self.unicorn_mode == UC_MODE_32:
                stack_point, frame_point  = UNICORN_REGISTERS_MAP[self.arch]['ESP'], UNICORN_REGISTERS_MAP[self.arch]['EBP']
            else:
                raise AssertionError("Invalid unicorn mode")

            self.mu.reg_write(stack_point, DEFAULT_STACK_POINT_VALUE + offset)
            self.mu.reg_write(frame_point, DEFAULT_BASE_POINT_VALUE + offset)
            tte_log_info(f"Init regs: Sets registers default stack regs value: sp = {DEFAULT_STACK_POINT_VALUE + offset:X}, bp = {DEFAULT_BASE_POINT_VALUE + offset:X}")

        elif self.settings.is_load_registers and self.unicorn_arch == UC_ARCH_X86 and self.unicorn_mode == UC_MODE_64:
            for reg_id, reg_value in get_arch_x64_regs_value().items():
                if reg_value is not None:
                    self.mu.reg_write(reg_id, reg_value)
                    tte_log_info(f"Init regs: Sets register ID {reg_id} value: 0x{reg_value:X}")
                else:
                    tte_log_info(f"Init regs: Skip register ID {reg_id} value: None")

        elif self.settings.is_load_registers and self.unicorn_arch == UC_ARCH_X86 and self.unicorn_mode == UC_MODE_32:
            for reg_id, reg_value in get_arch_x86_regs_value().items():
                if reg_value is not None:
                    self.mu.reg_write(reg_id, reg_value)
                    tte_log_info(f"Init regs: Sets register ID {reg_id} value: 0x{reg_value:X}")
                else:
                    tte_log_info(f"Init regs: Skip register ID {reg_id} value: None")


    CUSTOM_HOOK_MEM_MAP = 0
    CUSTOM_HOOK_EXECUTE_END = 1
    def add_custom_hook(self, htype: int, callback):
        if htype == EmuExecutor.CUSTOM_HOOK_MEM_MAP:
            self.emu_map_mem_callback.append(callback)
        elif htype == EmuExecutor.CUSTOM_HOOK_EXECUTE_END:
            self.emu_run_end_callback.append(callback)
        else:
            raise AssertionError("Invalid hook type")

    def get_mem_regions(self) -> Iterator[Tuple[int, int, int]]:
        return self.mu.mem_regions()

    def run(self) -> None:
        """
        Run the emulation from the specified address until the specified address.
        """
        tte_log_info(f"Run emulation: 0x{self.settings.start:X}~0x{self.settings.end:X}, count {self.settings.count}")

        try:
            self.mu.emu_start(self.settings.start, self.settings.end, 0, self.settings.count)
        except UcError as e:
            tte_log_err(f"Emulation failed: {e}")

        tte_log_info(f"Emulation ended: 0x{self.mu.reg_read(ARCH_TO_INSN_POINTER_MAP[self.arch]):X}")
        tte_log_dbg("Emulation: Start calling end callback functions.")
        for callback in self.emu_run_end_callback:
            callback(self.mu)

        tte_log_info("Emulation completed successfully.")

    def destroy(self) -> None:
        """
        End the emulate
        """
        if not self._is_initialized:
            tte_log_info("EmuExecutor not initialized.")
            return

        self.mu.emu_stop()
        for handler in self.mu_hook_handlers:
            self.mu.hook_del(handler)

        self.emu_run_end_callback.clear()
        self.emu_map_mem_callback.clear()
        self.loaded_pages.clear()

        self._is_initialized = False


StateList = List[Tuple[str, "EmuState"]]
RegistersDict = Dict[str, int] # {reg_name: reg_value}
RegistersPatchDict = Dict[str, int] # {reg_name: patch_reg_value}
MemoryPatchList= List[Tuple[int, int, bytes]] # [(page_start, page_size, patch_bytes)]
MemoryPagesDict = Dict[int, Tuple[int, bytearray]] # {page_start: (page_permissions, page_data)}
MemoryBsdiffPatchDict = Dict[int, Tuple[int, bytes]] # {page_start: (page_permissions, bsdiff_patch_bytes)}

RegistersDiffsDict = Dict[str, Tuple[int, int]] # {reg_name: (reg_value, patch_value)}



class EmuState(ABC):
    """
    Class that saves Unicorn execution status
    Saved status includes:
    1. Register value(or Register patch)
    2. Memory page(or Memory patch)
    3. Memory page comparison
    4. Command address
    5. Number of executions
    """

    # State type constant, Represents a specific state in Unicorn simulation execution.
    # The full state or difference from the previous state can be stored.
    STATE_TYPE_FULL  = 1  # Full status
    STATE_TYPE_LIGHT_PATCH = 2 # Light Patch Status
    STATE_TYPE_HEAVY_PATCH = 3 # Heavy Patch Status

    def __init__(self,
                 state_id: str,
                 prev_state_id: str = "",
                 instruction: bytes = b"",
                 instruction_address: int = -1,
                 execution_count: int = -1) -> None:
        self.state_id = state_id
        self.prev_state_id = prev_state_id
        self.type = None

        self.instruction_address = instruction_address
        self.instruction = instruction
        self.execution_count = execution_count

        self.memory_patches: Optional[MemoryPatchList] = []

    @abstractmethod
    def generate_full_state(self, states_dict: Dict[str, 'EmuState']) -> Optional['FullEmuState']:
        pass


class FullEmuState(EmuState):
    def __init__(self,
                 state_id: str,
                 prev_state_id: str = "",
                 instruction: bytes = b"",
                 instruction_address: int = -1,
                 execution_count: int = -1) -> None:
        super().__init__(state_id,
                         prev_state_id,
                         instruction,
                         instruction_address,
                         execution_count)
        self.type = EmuState.STATE_TYPE_FULL

        self.registers_map: RegistersDict = {} # {reg_name: reg_value}
        self.memory_patches: Optional[MemoryPatchList] = None # [(page_start, page_size, patch_bytes)]
        self.memory_pages: MemoryPagesDict = {} # {page_start: (page_permissions, page_data)}


    def set_data(self,
                 registers_map: RegistersDict,
                 memory_patches: Optional[MemoryPatchList],
                 memory_pages: MemoryPagesDict) -> None:
        """
        Set the full state of the emulator.
        :param registers: Dictionary of register values.
        :param memory_pages: Dictionary of memory pages.
        """
        self.registers_map = registers_map
        self.memory_patches = memory_patches # As a prompt in viewer only, it will not be used for memory patching
        self.memory_pages = memory_pages

    def generate_full_state(self, states_dict: Dict[str, EmuState]) -> Optional['FullEmuState']:
        return deepcopy(self)


class HeavyPatchEmuState(EmuState):
    def __init__(self,
                 state_id: str,
                 prev_state_id: str = "",
                 instruction: bytes = b"",
                 instruction_address: int = -1,
                 execution_count: int = -1) -> None:
        super().__init__(state_id,
                         prev_state_id,
                         instruction,
                         instruction_address,
                         execution_count)
        self.type = EmuState.STATE_TYPE_HEAVY_PATCH

        self.base_full_state_id: Optional[str] = None

        self.reg_patches: RegistersPatchDict = {} # {reg_name: patch_value}
        self.memory_patches: Optional[MemoryPatchList] = None # [(page_start, page_size, patch_bytes)]

        # Memory patch stores binary differential data generated by bsdiff4
        self.mem_bsdiff_patches: MemoryBsdiffPatchDict = {} # {page_start: (page_permissions, bsdiff_patch_bytes)}
        self.new_pages: MemoryPagesDict = {} # {page_start: (page_permissions, page_data)}

    def set_data(self,
                 base_full_state_id: str,
                 reg_patches: RegistersPatchDict,
                 memory_patches: Optional[MemoryPatchList],
                 mem_bsdiff_patches: MemoryBsdiffPatchDict,
                 new_pages: MemoryPagesDict):
        """
        Sets the patch status of the emulator.

        :param reg_patches: Dictionary of register patches.
        :param mem_bsdiff_patches: Dictionary of memory patches, need to be applied by bsdiff4.
        """
        self.base_full_state_id = base_full_state_id

        self.reg_patches = reg_patches
        self.memory_patches = memory_patches # As a prompt in viewer only, it will not be used for memory patching
        self.mem_bsdiff_patches = mem_bsdiff_patches
        self.new_pages = new_pages

    def generate_full_state(self, states_dict: Dict[str, EmuState]) -> Optional[FullEmuState]:
        tte_log_dbg(f"Generate full state for heavy path state {self.state_id}")
        target_state = FullEmuState(self.state_id, self.prev_state_id,self.instruction, self.instruction_address, self.execution_count)

        assert self.base_full_state_id is not None, "Generate full State: Cannot apply memory patch: base state id not set."
        assert self.base_full_state_id in states_dict, f"Generate full State: Cannot apply memory patch: base state {self.base_full_state_id} not found."
        base_full_state: Optional[EmuState] = states_dict[self.base_full_state_id].generate_full_state(states_dict)

        assert base_full_state is not None, f"Generate full State: Cannot get full state for {self.base_full_state_id}: base state not found."
        assert isinstance(base_full_state, FullEmuState), f"Generate full State: Cannot apply memory patch: base state is not a full state."

        target_registers_map = apply_dict_patch(base_full_state.registers_map, self.reg_patches)
        target_memory_pages = apply_bytes_patch(base_full_state.memory_pages, self.mem_bsdiff_patches, self.new_pages)
        target_state.set_data(target_registers_map, None,  target_memory_pages)

        return deepcopy(target_state)


class LightPatchEmuState(EmuState):
    def __init__(self,
                 state_id: str,
                 prev_state_id: str = "",
                 instruction: bytes = b"",
                 instruction_address: int = -1,
                 execution_count: int = -1) -> None:
        super().__init__(state_id,
                         prev_state_id,
                         instruction,
                         instruction_address,
                         execution_count)
        self.type = EmuState.STATE_TYPE_LIGHT_PATCH

        self.base_full_state_id: Optional[str] = None

        self.reg_patches: RegistersPatchDict = {} # {reg_name: patch_value}
        self.memory_patches: MemoryPatchList = [] # List[[address, size, value]...]


    def set_data(self,
                 base_full_state_id: str,
                 reg_patches: RegistersPatchDict,
                 memory_patches: MemoryPatchList):
        """
        Set the patch state of the emulator.
        :param reg_patches: Dictionary of register patches.
        :param memory_patches: Dictionary of memory patches.
        """
        self.base_full_state_id = base_full_state_id

        self.reg_patches = reg_patches
        self.memory_patches = memory_patches
        tte_log_dbg(message=f"state:{self.state_id}, memory_patches {self.memory_patches}")


    def generate_full_state(self, states_dict: Dict[str, EmuState]) -> Optional[FullEmuState]:
        tte_log_dbg(f"Generate full state for light path state {self.state_id}")
        target_state = FullEmuState(self.state_id,
                                    self.prev_state_id,
                                    self.instruction,
                                    self.instruction_address,
                                    self.execution_count)
        accumulated_memory_patches_to_apply = self.memory_patches.copy()
        assert self.base_full_state_id is not None, "Generate full State: Cannot generate full state: base state id not set."
        base_full_state: Optional[EmuState] = states_dict.get(self.base_full_state_id)
        assert base_full_state is not None, f"Generate full State: Cannot generate full state for {self.base_full_state_id}: base state not found."
        assert isinstance(base_full_state, FullEmuState), f"Generate full State: Cannot generate full state for {self.base_full_state_id}: base state is not a full state."

        prev_full_state: Optional[EmuState] = None
        prev_state_id = self.prev_state_id
        while prev_state_id is not None:
            prev_state = states_dict.get(prev_state_id)
            if prev_state is None:
                tte_log_warn(f"Generate full State: Cannot generate full state for {prev_state_id}: previous state not found.")
                return None

            if prev_state.type in [EmuState.STATE_TYPE_FULL, EmuState.STATE_TYPE_HEAVY_PATCH]:
                prev_full_state = prev_state.generate_full_state(states_dict)
                assert prev_full_state is not None, "Generate full State: Cannot generate full state for previous state."
                assert isinstance(prev_full_state, FullEmuState), "Generate full State: Previous state is not a full state."
                break;

            elif prev_state.type == EmuState.STATE_TYPE_LIGHT_PATCH:
                assert isinstance(prev_state, LightPatchEmuState), "Generate full State: Previous state is not a light patch state."
                accumulated_memory_patches_to_apply.extend(prev_state.memory_patches)
                prev_state_id = prev_state.prev_state_id

        # Apply register patches
        target_state.registers_map = apply_dict_patch(base_full_state.registers_map, self.reg_patches)

        # Apply memory patches
        assert prev_full_state is not None, "Generate full State: Cannot apply memory patch: previous state not found."
        target_state.memory_pages = prev_full_state.memory_pages
        while accumulated_memory_patches_to_apply:
            addr, size, value = accumulated_memory_patches_to_apply.pop()

            align_addr = addr & PAGE_MASK
            offset = addr & ~PAGE_MASK

            assert align_addr in target_state.memory_pages, "Generate full State: Cannot apply memory patch: address not found in memory pages."
            _, page_data = target_state.memory_pages[align_addr]
            page_data[offset : offset + size] = value
        return target_state


class EmuStateManager():
    """
    Class responsible for storing and managing all EmuState objects.
    It handles the creation, extraction, serialization, and deserialization of states.
    """

    MAX_PATCH_CHAIN_LENGTH = 100 # The longest patch chain, if it exceeds the full snapshot
    MAX_HEAVY_PATCH_COUNT = 10
    MAX_CUMULATIVE_DIFF_THRESHOLD = 0x1000 # Accumulated difference threshold, if it exceeds it, create a full snapshot
    STATE_ID_FORMAT = "$0x{address:X}#{count}"

    def __init__(self) -> None:
        self.arch = get_arch()

        self.states_dict: Dict[str, EmuState] = {} # dict: {state_id: EmuState}
        # self.storage_path = storage_path
        # os.makedirs(self.storage_path, exist_ok=True)

        self.instruction_execution_counts: Dict[int, int] = defaultdict(int) # {address: count}
        self.last_state_id: str = "" # Record the status id of the previous created
        self.last_full_state_id: Optional[str] = None # Record the most recent full status id

        self.patch_chain_count: int = 0 # Number of statuses in the current patch chain
        self.heavy_patch_count: int = 0 # Number of heavy patches created
        self.cumulative_diff_size: int = 0 # Cumulative difference size (used to determine whether to create a complete snapshot)

        self.has_map_memory = False # Whether the uc instance has mapped new memory page or not


    def _generate_state_id(self, instruction_address: int) -> str:
        """
        Generate a unique state ID based on the instruction address and the number of executions.
        Format: "<hex_addr><count>"
        """
        self.instruction_execution_counts[instruction_address] +=1
        count = self.instruction_execution_counts[instruction_address]
        return self.STATE_ID_FORMAT.format(address=instruction_address, count=count)


    def _read_memory_pages(self, uc, memory_regions: Iterator[Tuple[int, int, int]]) -> MemoryPagesDict:
        """
        Read paging memory from Unicorn instance.

        :param uc: The Unicorn instance.
        :param memory_regions: A list of memory regions to read.  Iterator(Tuple[start, end, permission])
        :return: A dictionary of memory pages, where the key is the start address of
         the page and the value is the page's permission and data.
        """
        memory_pages: MemoryPagesDict = {}
        for start, end, permission in memory_regions:
            size = end - start + 1
            try:
                # Try to read a memory page
                page_data = uc.mem_read(start, size)
                memory_pages[start] = (permission, page_data)
                tte_log_dbg(f"State Manager: Read memory page at 0x{start:X}, size {size}")
            except Exception as e:
                # If memory area may not be mapped, skipped and log
                tte_log_warn(f"Error: Could not read memory page at 0x{start:X}: {e}")
                pass
        return memory_pages


    def _create_full_state(self,
                           new_state_id: str,
                           instruction: bytes,
                           instruction_address:int,
                           current_registers_map: RegistersDict,
                           memory_patches: MemoryPatchList,
                           current_memory_pages: MemoryPagesDict) -> None:
        new_state = FullEmuState(new_state_id,
                                 self.last_state_id,
                                 instruction,
                                 instruction_address,
                                 self.instruction_execution_counts[instruction_address])
        new_state.set_data(current_registers_map, memory_patches, current_memory_pages)

        self.states_dict[new_state_id] = new_state

        self.last_full_state_id = new_state_id
        self.last_state_id = new_state_id # Update the last status id
        tte_log_dbg(f"State Manager: Created FULL state: {new_state_id}")


    def _create_heavy_patch_state(self,
                                  new_state_id: str,
                                  instruction: bytes,
                                  instruction_address:int,
                                  current_registers_map: RegistersDict,
                                  memory_patches: MemoryPatchList,
                                  current_memory_pages: Dict[int, Tuple[int,bytearray]]) -> None:
        assert self.last_full_state_id is not None, "No full base state available for patch creation."
        assert self.last_state_id is not None, "No previous state available for patch creation."

        base_full_state: Optional[FullEmuState] = self.get_state(self.last_full_state_id) # type: ignore
        assert base_full_state is not None, "No full base state available for patch creation."
        assert isinstance(base_full_state, FullEmuState), "Base state is not a full state."

        reg_patches = catch_dict_patch(base_full_state.registers_map, current_registers_map)
        mem_bsdiff_patches,new_pages = catch_bytes_patch(base_full_state.memory_pages, current_memory_pages) # [ ] TODO support unmap pages in newer state

        new_state = HeavyPatchEmuState(new_state_id,
                                       self.last_state_id,
                                       instruction,
                                       instruction_address,
                                       self.instruction_execution_counts[instruction_address])
        new_state.set_data(self.last_full_state_id, reg_patches, memory_patches, mem_bsdiff_patches, new_pages)

        self.states_dict[new_state_id] = new_state

        self.patch_chain_count += 1
        self.heavy_patch_count += 1
        self.cumulative_diff_size += len(mem_bsdiff_patches)
        self.last_state_id = new_state_id # Update the last status id
        tte_log_dbg(f"State Manager: Created HEAVY PATCH state: {new_state_id}, base: {new_state.base_full_state_id}")



    def _create_light_patch_state(self,
                                  new_state_id: str,
                                  instruction: bytes,
                                  instruction_address:int,
                                  current_registers_map: RegistersDict,
                                  memory_patches: MemoryPatchList) -> None:
        assert self.last_full_state_id is not None, "No full base state available for patch creation."
        assert self.last_state_id is not None, "No previous state available for patch creation."

        base_full_state: Optional[FullEmuState] = self.get_state(self.last_full_state_id) # type: ignore
        assert base_full_state is not None, "No full base state available for patch creation."
        assert isinstance(base_full_state, FullEmuState), "Base state is not a full state."

        reg_patches = catch_dict_patch(base_full_state.registers_map, current_registers_map)

        new_state = LightPatchEmuState(new_state_id,
                                       self.last_state_id,
                                       instruction,
                                       instruction_address,
                                       self.instruction_execution_counts[instruction_address])
        new_state.set_data(self.last_full_state_id, reg_patches, memory_patches)

        self.states_dict[new_state_id] = new_state

        self.patch_chain_count += 1
        self.cumulative_diff_size += len(memory_patches)
        self.last_state_id = new_state_id # Update the last status id
        tte_log_dbg(f"State Manager: Created LIGHT PATCH state: {new_state_id}, base:{new_state.base_full_state_id},  prev: {new_state.prev_state_id}")


    def get_state(self, state_id: Optional[str]) -> Optional[EmuState]:
        """
        Get the EmuState object by its ID.
        :param state_id: The ID of the state to retrieve.
        :return: The EmuState object if found, otherwise None.
        """
        if state_id is None:
            return None
        return self.states_dict.get(state_id, None)


    def get_state_list(self) -> StateList:
        """
        Get a list of all EmuState objects with their ID, instruction address, instruction, and execution count.

        :return: A list of tuples containing the state ID, instruction address, instruction, and execution count.
        """
        result: StateList = []
        for state_id, state in self.states_dict.items():
            result.append((state_id, state))
        return result

    def _determine_next_state_type(self):
        tte_log_dbg(f"Determine next state type: heavy patch count: {self.heavy_patch_count}, cumulative diff size: {self.cumulative_diff_size}, has_map_memory: {self.has_map_memory}")

        if self.last_full_state_id is None or self.heavy_patch_count > self.MAX_HEAVY_PATCH_COUNT or \
            self.patch_chain_count >= self.MAX_PATCH_CHAIN_LENGTH or self.cumulative_diff_size >= self.MAX_CUMULATIVE_DIFF_THRESHOLD :
            self.has_map_memory = False
            self.heavy_patch_count = 0
            self.patch_chain_count = 0
            self.cumulative_diff_size = 0

            tte_log_dbg("Create full state")
            return EmuState.STATE_TYPE_FULL

        elif self.has_map_memory == True:
            self.has_map_memory = False
            tte_log_dbg("Create heavy patch state")
            return EmuState.STATE_TYPE_HEAVY_PATCH

        tte_log_dbg("Create light state")
        return EmuState.STATE_TYPE_LIGHT_PATCH


    def create_state(self,
                     uc,
                     instruction: bytes,
                     instruction_address: int,
                     memory_regions: Iterator[Tuple[int, int, int]],
                     memory_patches: MemoryPatchList) -> None:
        """
        Create a new EmuState object based on the current state of the Unicorn instance.
        Decide whether to create a full state or a patch state based on the difference size or number of steps.

        :param uc: The Unicorn instance.
        :param instruction_address: The address of the current instruction.
        :param memory_regions: A list of memory regions(Iterator[Tuple[start, end, permission]]) to read.
        :param memory_patches: A list of memory patches(List[Tuple[addr, size, value]]) to apply.
        """
        tte_log_dbg(f"State Manager: Create state at 0x{instruction_address:X}")
        new_state_id = self._generate_state_id(instruction_address)

        # Read the registers of unicorn instance
        current_registers_map = {
            reg_name: uc.reg_read(reg_const)
            for reg_name,reg_const in UNICORN_REGISTERS_MAP[self.arch].items()
        }

        next_state_type = self._determine_next_state_type()
        if next_state_type == EmuState.STATE_TYPE_FULL:
            # Create a full status
            current_memory_pages = self._read_memory_pages(uc, memory_regions)
            self._create_full_state(new_state_id,
                                    instruction,
                                    instruction_address,
                                    current_registers_map,
                                    memory_patches,
                                    current_memory_pages)

        elif next_state_type == EmuState.STATE_TYPE_HEAVY_PATCH:
            # Create a heavy patch status
            current_memory_pages = self._read_memory_pages(uc, memory_regions)
            self._create_heavy_patch_state(new_state_id,
                                           instruction,
                                           instruction_address,
                                           current_registers_map,
                                           memory_patches,
                                           current_memory_pages)

        else:
            # Create a light patch status
            self._create_light_patch_state(new_state_id,
                                           instruction,
                                           instruction_address,
                                           current_registers_map,
                                           memory_patches)


    def _get_regs_map(self, state) -> RegistersDict:
        if state.type in [EmuState.STATE_TYPE_LIGHT_PATCH, EmuState.STATE_TYPE_HEAVY_PATCH]:
            base_state = self.get_state(state.base_full_state_id)
            assert base_state, f"Base state not found"
            assert isinstance(base_state, FullEmuState)
            return apply_dict_patch(base_state.registers_map, state.reg_patches)
        else:
            assert isinstance(state, FullEmuState)
            return state.registers_map


    def compare_states(self, state1: EmuState, state2: EmuState):
        """
        Compares any two EmuState objects (full or patch) and returns their differences.
        The first state must be the base state, and the second state is the target state.

        :param EmuStateManager: An instance of EmuStateManager to extract full states if needed.
        :param state1: The first EmuState object.
        :param state2: The second EmuState object.
        :return: A tuple (regs_diff, mem_diff, pages_diff) representing the differences.
                 regs_diff: Dict of changed registers in state2 relative to state1.
                 mem_diff: List of memory different from state1 to state2.
                 pages_diff: List of page different from state1 to state2, and the type of the page (1: added, 2: removed)
        """
        tte_log_dbg(f"\n--- Comparing states Fully: {state1.state_id} vs {state2.state_id} ---")

        tte_log_dbg(f"Comparison between State '{state1.state_id}' (Type: {state1.type}) and State '{state2.state_id}' (Type: {state2.type}):")
        tte_log_dbg(f"Instruction Address: 0x{state1.instruction_address:X} -> 0x{state2.instruction_address:X}")
        tte_log_dbg(f"Execution Count: {state1.execution_count} -> {state2.execution_count}")

        full_state1 = state1.generate_full_state(self.states_dict)
        full_state2 = state2.generate_full_state(self.states_dict)

        if not full_state1:
            tte_log_warn(f"Could not generate full state for '{state1.state_id}'. Comparison aborted.")
            return
        if not full_state2:
            tte_log_warn(f"Could not generate full state for '{state2.state_id}'. Comparison aborted.")
            return

        regs_diff: RegistersDiffsDict = {}
        def catch_regs_diff(regs_map1, regs_map2):
            result: RegistersDiffsDict = {}
            for reg_name in regs_map1:
                if regs_map1[reg_name] != regs_map2[reg_name]:
                    result[reg_name] = (regs_map1[reg_name], regs_map2[reg_name])
                    tte_log_dbg(f"  {reg_name}: 0x{regs_map1[reg_name]:X} -> 0x{regs_map2[reg_name]:X}")
            return result
        regs_diff = catch_regs_diff(full_state1.registers_map, full_state2.registers_map)

        mem_diff = SortedDict()
        def catch_mem_diff(page_start_addr, bytes1: bytearray, bytes2: bytearray):
            assert len(bytes1) == len(bytes2), "Byte arrays must be of equal length."
            for offset_addr, (b1, b2) in enumerate(zip(bytes1, bytes2)):
                if b1 != b2:
                    tte_log_dbg(f"Memory difference found at 0x{page_start_addr + offset_addr:X}: 0x{b1:X} -> 0x{b2:X}")
                    mem_diff[page_start_addr + offset_addr] = (b1, b2)

        for page_start_addr in full_state1.memory_pages.keys() & full_state2.memory_pages.keys():
            catch_mem_diff(
                page_start_addr,
                full_state1.memory_pages[page_start_addr][1],
                full_state2.memory_pages[page_start_addr][1]
            )

        pages_diff = SortedDict()
        diff_keys_in_state1 = set(full_state1.memory_pages.keys()) - set(full_state2.memory_pages.keys())
        diff_keys_in_state2 = set(full_state2.memory_pages.keys()) - set(full_state1.memory_pages.keys())
        for key in diff_keys_in_state1:
            pages_diff[key] = (1, full_state1.memory_pages[key])
        for key in diff_keys_in_state2:
            pages_diff[key] = (2, full_state2.memory_pages[key])

        return regs_diff, mem_diff, pages_diff







class EmuTracer():
    """
    Class for tracking EmuExecutor and creating state snapshots in EmuStateManager when appropriate.
    """
    @dataclass
    class state_buffer_t(object):
        instruction: bytes
        memory_patches: MemoryPatchList

    def __init__(self, executor:EmuExecutor, state_manager:EmuStateManager) -> None:
        self.executor: EmuExecutor = executor
        self.state_manager: EmuStateManager = state_manager

        self.arch = self.executor.arch
        self.capstone_arch, self.capstone_mode= CAPSTONE_ARCH_MAP[self.arch]
        self.md = Cs(self.capstone_arch, self.capstone_mode)

        self.state_buffer = self.state_buffer_t(b"", [])


    def init_hook(self) -> None:
        self._trace_code()
        self._trace_mem_write()

        self._trace_custom_operate()


    def _trace_code(self):
        # self.executor.add_mu_hook(UC_HOOK_MEM_READ, self.trace_mem_read)
        self.executor.add_mu_hook(UC_HOOK_CODE, self.cb_catch_insn_execution)
        self.executor.add_mu_hook(UC_HOOK_CODE, self.cb_create_emu_state)


    def _trace_mem_write(self):
        self.executor.add_mu_hook(UC_HOOK_MEM_WRITE, self.cb_log_mem_write)
        self.executor.add_mu_hook(UC_HOOK_MEM_WRITE, self.cb_catch_mem_write)


    def _trace_custom_operate(self):
        self.executor.add_custom_hook(EmuExecutor.CUSTOM_HOOK_EXECUTE_END, self.cb_create_emu_end_state)
        self.executor.add_custom_hook(EmuExecutor.CUSTOM_HOOK_MEM_MAP, self.cb_mark_mem_map)



    def cb_catch_insn_execution(self, uc, address, size, user_data) -> bool:
        tte_log_dbg(message=f"Tracing instruction at 0x{address:X}, instruction size = {size:X}")
        opcode, operand = InstrctionParser().parse_instruction_to_tuple(uc.mem_read(address, size))
        tte_log_dbg("Executing instruction:    %s\t%s" % (opcode, operand))
        self.state_buffer.instruction = bytes(uc.mem_read(address, size))
        return True


    def cb_create_emu_state(self, uc, address, size, user_data) -> bool:
        """
        @Callback function for hook "UC_HOOK_CODE"
        Note: UC_HOOK_CODE triggers callback before the instruction is actually executed

        This function will perform two operations:
        Create the simulated state saved to the status buffer as a new EmuState and add it to the EmuStateManager
        Create a new simulated state in the state buffer
        """

        # Save the current state to the state buffer
        self.state_manager.create_state(uc,
                                        self.state_buffer.instruction,
                                        address,
                                        self.executor.get_mem_regions(),
                                        self.state_buffer.memory_patches)

        # Create a new state buffer
        self.state_buffer.memory_patches = []

        return True


    def cb_log_mem_write(self, uc, access, address, size, value, user_data):
        tte_log_dbg(f"Memory write: access={access}, address=0x{address:X}, size={size}, value=0x{value:X}, insn={uc.reg_read(ARCH_TO_INSN_POINTER_MAP[self.arch]):X}")
        return True


    def cb_catch_mem_write(self, uc, access, address:int, size:int, value:int, user_data) -> bool:
        """
        @Callback function for hook "UC_HOOK_MEM_WRITE"

        """
        tte_log_dbg(f"Catch memory write: address={hex(address)}, size={size}, value= {hex(value)}")
        if value >= 0:
            value_bytes = value.to_bytes(size, byteorder='big' if get_is_be() else 'little', signed=False)
        else:
            value_bytes = value.to_bytes(size, byteorder='big' if get_is_be() else 'little', signed=True)
        # Save the memory patch to the state buffer
        self.state_buffer.memory_patches.append((address, size, value_bytes))
        return True


    def cb_create_emu_end_state(self, uc):
        insn_pointer = uc.reg_read(ARCH_TO_INSN_POINTER_MAP[self.arch])
        self.state_manager.create_state(uc,
                                        b"",
                                        insn_pointer,
                                        self.executor.get_mem_regions(),
                                        self.state_buffer.memory_patches)

    def cb_mark_mem_map(self, uc):
        """
        Callback function to mark that the binary has been loaded.
        This is used to determine which type of state to create next time.
        """

        self.state_manager.has_map_memory = True
        tte_log_dbg("Binary has been loaded, will create heavy patch state next time.")



class InstrctionParser():
    """
    Class for parsing instructions and extracting relevant information.
    """
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(InstrctionParser, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.arch = get_arch()
        self.capstone_arch, self.capstone_mode = CAPSTONE_ARCH_MAP[self.arch]
        self.md = Cs(self.capstone_arch, self.capstone_mode)

    def parse_instructions(self, insn_bytes: bytes):
        return self.md.disasm(insn_bytes, 0)

    def parse_instruction_to_str(self, insn_bytes: bytes) -> str:
        """
        Parses an instruction and returns a string of the form "opcode operand"
        """
        assert self.md is not None, "InstrctionParser not initialized"
        try:
            _, _, opcode, operand = next(self.md.disasm_lite(insn_bytes, 0))
            return f"{opcode}\t{operand}"
        except StopIteration:
            return ""

    def parse_instruction_to_tuple(self, insn_bytes: bytes) -> Tuple[str, str]:
        """
        Parses an instruction and returns a tuple of (opcode, operand)
        """
        assert self.md is not None, "InstrctionParser not initialized"
        try:
            _, _, opcode, operand = next(self.md.disasm_lite(insn_bytes, 0))
            return opcode,operand
        except StopIteration:
            return "", ""




class MenuActionHandler(ida_kernwin.action_handler_t):
    def __init__(self,
                 parent_title,
                 checkable,
                 action_name,
                 handler,
                 title,
                 shortcut):
        ida_kernwin.action_handler_t.__init__(self)
        self.parent_title = parent_title
        self.checkable: Optional[Callable[[], Optional[bool]]] = checkable
        self.action_name = action_name
        self.handler = handler
        self.title = title
        self.shortcut = shortcut
        self.register()

    def activate(self, ctx):
        return self.handler()

    def update(self, ctx):
        if ctx.widget_title == self.parent_title and self.checkable and self.checkable():
            return idaapi.AST_ENABLE
        return idaapi.AST_DISABLE

    def register(self):
        actname = self.action_name
        if ida_kernwin.unregister_action(actname):
            tte_log_dbg("Unregistered previously-registered action \"%s\"" % actname)

        desc = ida_kernwin.action_desc_t(actname, self.title , self, self.shortcut)
        if ida_kernwin.register_action(desc):
            tte_log_dbg("Registered action \"%s\"" % actname)

    def unregister(self):
        actname = self.action_name
        if ida_kernwin.unregister_action(actname):
            tte_log_dbg("Unregistered action \"%s\"" % actname)

    def get_action_name(self) -> str:
        return self.action_name


# Line types
UNKNOW_LINE = 0
DATA_LINE = 1
CODE_LINE = 2
NAME_LINE = 3
EMPTY_LINE = 4
SINGLE_DATA_LINE = 5
ERROR_LINE = 6

@dataclass
class address_line_info:
    address: int
    address_idx: int = 0
    type: int = UNKNOW_LINE
    value: str = ""
    fgcolor: Optional[int] = 0x0
    bgcolor: Optional[int] = 0xFFFFFF


class AddressAwareCustomViewer(ida_kernwin.simplecustviewer_t):
    """
    This class extends simplecustviewer_t to manage lines of text associated with binary addresses.
    It uses a SortedList to maintain lines sorted by their associated address.
    """

    def __init__(self):
        super().__init__()
        self._lines_data: SortedList = SortedList(key=lambda x: (x.address, x.address_idx)) # SortedList[line_info], using Tuple[address, address_idx] as key
        self._lines_data_buffer: List[address_line_info] = []

        self.need_rebuild = False # Flag to indicate if the viewer needs to be refreshed

        self.keydown_callback_list: List[Tuple[int, bool, Callable]] = [] # List[(ord_key, is_shift, callback_func)], Callback functions list called when corresponding keys is down
        self.dbl_click_callback: Optional[Callable] = None # Callback function called when double-clicking a line
        self.menu_action_handlers = []


    def _get_lineno_left_from_address(self, address):
        """
        Gets the line number for a given address using SortedList's bisect_left.
        Returns -1 if address not found.
        """
        idx = self._lines_data.bisect_left(address_line_info(address = address))
        if idx < len(self._lines_data) and self._lines_data[idx].address == address: # type: ignore
            return idx
        return -1


    def _get_lineno_right_from_address(self, address):
        """
        Gets the line number for a given address using SortedList's bisect_right.
        Returns -1 if address not found.
        """
        idx = self._lines_data.bisect_right(address_line_info(address = address))
        if idx > 0 and self._lines_data[idx - 1].address == address: # type: ignore
            return idx - 1
        return -1


    def _get_address_info_from_lineno(self, lineno) -> Optional[address_line_info]:
        """
        Gets the address for a given line number.
        Returns None if lineno is out of bounds.
        """
        if 0 <= lineno < len(self._lines_data):
            return self._lines_data[lineno] # type: ignore
        return None


    def _rebuild_viewer_content(self):
        """
        Internal helper to clear the underlying simplecustviewer_t (which is self)
        and repopulate it from the sorted _lines_data.
        Notes: It is a performance-consuming function, so call this function as few as possible
        """
        super().ClearLines() # Call base ClearLines
        if self._lines_data_buffer:
            self._lines_data.update(self._lines_data_buffer)
            self._lines_data_buffer.clear()
        for addr_info in self._lines_data:
            super().AddLine(addr_info.value, addr_info.fgcolor, addr_info.bgcolor) # Call base AddLine
        super().Refresh() # Refresh the viewer

    def CheckRebuild(self):
        if self.need_rebuild:
            self._rebuild_viewer_content()
            self.need_rebuild = False

    def Create(self, title):
        return super().Create(title)

    def OnClose(self):
       self.UnregisterAction()

    def UnregisterAction(self):
        for action_handler in self.menu_action_handlers:
            action_handler.unregister()
        self.menu_action_handlers.clear()

    def Show(self):
        self.CheckRebuild()
        return super().Show()

    def Refresh(self):
        self.CheckRebuild()
        return super().Refresh()

    def ClearLines(self):
        self._lines_data.clear() # Use SortedList's clear method
        super().ClearLines() # Call base ClearLines
        super().Refresh() # Refresh the viewer


    def AddLine(self, address, address_type, line, fgcolor=None, bgcolor=None, lazy = False):
        """
        Adds a colored line associated with a binary address to  the last line of viewer.
        Note: The incoming address parameter must be bigger than all existing addresses in the viewer

        :param lazy: If True, the viewer will not be refreshed after the deletion.
        :return: Boolean indicating success.
        """

        is_appending = True
        addr_idx = 0

        if self._lines_data:
            last_line_info: address_line_info = self._lines_data[-1] # type: ignore
            if address < last_line_info.address:
                # The address is out of order and cannot be added directly. Forced to go to lazy mode
                is_appending = False
                tte_log_dbg(
                    f"AddLine: Incoming address {hex(address)} is out of order "
                    f"(less than last address {hex(last_line_info.address)}). "
                    f"Forcing lazy rebuild for correct sorting."
                )
                idx = self._get_lineno_right_from_address(address)
                addr_idx = self._lines_data[idx].address_idx + 1 # type: ignore
                lazy = True

            elif address == last_line_info.address:
                # The address is the same, increment the address_idx
                addr_idx = last_line_info.address_idx + 1

            else: # address > last_line_info.address
                #Strictly append, new address, address_idx starts from 0
                addr_idx = 0
        else:
            # The view is empty, the first element
            addr_idx = 0

        # Add the new or updated entry. SortedList.add() will place it correctly.
        new_line_info = address_line_info(address, addr_idx,address_type, line, fgcolor, bgcolor)
        if lazy:
            self.need_rebuild = True
            self._lines_data_buffer.append(new_line_info)
            return True
        else:
            self._lines_data.add(new_line_info)
            return super().AddLine(line, fgcolor, bgcolor) # Call base InsertLine


    def InsertLine(self, address, address_type, line, fgcolor=None, bgcolor=None):
        """
        Inserts a line at the position determined by the given address.
        This is equivalent to AddLine as lines are always kept sorted by address.

        :return: Boolean indicating success.
        """
        self.CheckRebuild()
        # Find if the address already exists
        idx = self._get_lineno_right_from_address(address)
        addr_idx = 0
        if idx != -1 and idx < len(self._lines_data) and self._lines_data[idx].address == address: # type: ignore
            # Address exists
            addr_idx = self._lines_data[idx].address_idx + 1 # type: ignore

        # Add the new or updated entry. SortedList.add() will place it correctly.
        new_line_info = address_line_info(address, addr_idx,address_type, line, fgcolor, bgcolor)
        self._lines_data.add(new_line_info)

        actual_lineno_inserted = self._lines_data.index(new_line_info)
        if actual_lineno_inserted == len(self._lines_data) - 1:
            return super().AddLine(line, fgcolor, bgcolor) # Call base InsertLine
        else:
            return super().InsertLine(actual_lineno_inserted, line, fgcolor, bgcolor) # Call base InsertLine


    def EditLine(self, address, address_idx, address_type, line, fgcolor=None, bgcolor=None):
        """
        Edits an existing line identified by its binary address.

        :return: Boolean indicating success.
        """
        self.CheckRebuild()
        target_line_info = address_line_info(address=address, address_idx=address_idx)
        lineno_to_edit = self._lines_data.bisect_left(target_line_info)
        if lineno_to_edit < len(self._lines_data):
            line_info: address_line_info = self._lines_data[lineno_to_edit] # type: ignore

            if line_info.address == address and \
            line_info.address_idx == address_idx:
                line_info.value = line
                line_info.type = address_type # Update type as well
                line_info.fgcolor = fgcolor
                line_info.bgcolor = bgcolor

                return super().EditLine(lineno_to_edit, line, fgcolor, bgcolor) # Call base EditLine
            return False
        return False


    def EditLineColor(self, address, address_idx, fgcolor=None, bgcolor=None):
        """
        Edits an existing line's color identified by its binary address.

        :return: Boolean indicating success.
        """
        self.CheckRebuild()
        target_line_info = address_line_info(address=address, address_idx=address_idx)
        lineno_to_edit = self._lines_data.bisect_left(target_line_info)
        if lineno_to_edit < len(self._lines_data):
            line_info: address_line_info = self._lines_data[lineno_to_edit] # type: ignore
            if line_info.address == address and \
            line_info.address_idx == address_idx:
                line_info.fgcolor = fgcolor
                line_info.bgcolor = bgcolor
                return super().EditLine(lineno_to_edit, line_info.value, fgcolor, bgcolor) # Call base EditLine
            return False
        return False


    def UpdateLine(self, address, address_idx, address_type, line, fgcolor=None, bgcolor=None):
        """
        Updates an existing line identified by its binary address.

        :return: Boolean indicating success.
        """
        self.CheckRebuild()
        target_line_info = address_line_info(address=address, address_idx=address_idx)
        lineno_to_edit = self._lines_data.bisect_left(target_line_info)
        if lineno_to_edit < len(self._lines_data):
            line_info: address_line_info = self._lines_data[lineno_to_edit] # type: ignore

            if line_info.address == address and \
                line_info.address_idx == address_idx:
                return self.EditLine(address, address_idx, address_type, line, fgcolor, bgcolor)
            else:
                return False
        return False


    def UpdateLineRange(self, address, length, address_type, line, fgcolor=None, bgcolor=None):
        """
        Deletes an existing line range identified by its binary address range.
        and inserts a new line.

        :return: Boolean indicating success.
        """
        self.CheckRebuild()
        for offset in range(length):
            self.DelLine(address + offset, lazy=False)
        return self.InsertLine(address, address_type, line, fgcolor, bgcolor)


    def PatchLine(self, address, address_idx, offs, value):
        raise AssertionError("PatchLine is Forbidden")


    def DelLine(self, address, lazy = False):
        """
        Deletes an existing line identified by its binary address.

        :param address: The binary address of the line to delete.
        :param lazy: If True, the viewer will not be refreshed after the deletion.
        :return: Boolean indicating success.
        """
        self.CheckRebuild()

        lines_to_delete_indices = []

        start_idx = self._lines_data.bisect_left(address_line_info(address=address))
        current_idx = start_idx
        while current_idx < len(self._lines_data) and self._lines_data[current_idx].address == address: # type: ignore
            lines_to_delete_indices.append(current_idx)
            current_idx += 1

        if not lines_to_delete_indices:
            return False # No lines found for this address

        # Delete from _lines_data in reverse order to avoid index shifts
        for lineno in reversed(lines_to_delete_indices):
            del self._lines_data[lineno]
            if not lazy:
                # If not lazy, we must also update the base viewer immediately
                super().DelLine(lineno)
        if lazy:
            self.need_rebuild = True # If any lines were deleted, a rebuild is needed later
        return True


    def GetLine(self, address, address_idx):
        """
        Returns a line's content and colors identified by its binary address.

        :param address: The binary address (integer) of the line.
        :return: Returns a tuple (colored_line, fgcolor, bgcolor) or None if address not found.
        """
        self.CheckRebuild()
        target_line_info = address_line_info(address=address, address_idx=address_idx)
        lineno_to_get = self._lines_data.bisect_left(target_line_info)
        if lineno_to_get < len(self._lines_data):
            # Retrieve the full tuple, then extract line_str, fgcolor, bgcolor
            addr_info: address_line_info = self._lines_data[lineno_to_get] # type: ignore

            if addr_info.address == address and \
            addr_info.address_idx == address_idx:
                return addr_info
        return None


    def Jump(self, address, x=0, y=0):
        """
        Jumps to the line associated with the given binary address.

        :param address: The binary address to jump to.
        :param x: Horizontal cursor position (optional).
        :param y: Vertical cursor position (optional).
        :return: Boolean indicating success.
        """
        self.CheckRebuild()
        idx = self._lines_data.bisect_left(address_line_info(address = address + 1 ,address_idx = -1))
        if idx > 0:
            lineno = idx - 1
            return super().Jump(lineno, x, y)
        return False


    def GetSelection(self):
        """
        Returns the selected range in terms of addresses or None.

        :return:     - tuple(x1, address1, x2, address2)
                    - None if no selection
        """
        self.CheckRebuild()
        selection = super().GetSelection()
        if selection:
            x1, y1, x2, y2 = selection
            info1 = self._get_address_info_from_lineno(y1)
            info2 = self._get_address_info_from_lineno(y2)
            if info1 is not None and info2 is not None:
                addr1 = info1.address
                addr2 = info2.address
                return (x1, addr1, x2, addr2)
        return None


    def GetLineNo(self, mouse = 0):
        """
        Returns the index of the current line or None if no line is selected.

        :param mouse: return mouse position.
        :return: Returns the line number or None on failure.
        """
        self.CheckRebuild()
        lineno = super().GetLineNo(mouse)
        if lineno != -1:
            return lineno
        return None


    def GetLineNoFromAddress(self, address):
        """
        Returns the line number associated with the given binary address.
        :param address: The binary address to search for.
        :return: Returns the line number or -1 if address not found.
        """
        self.CheckRebuild()
        lineno = self._get_lineno_left_from_address(address)
        if lineno != -1:
            return lineno
        return -1


    def GetAddressFromLineNo(self, lineno):
        """
        Returns the binary address associated with the given line number.
        :param lineno: The line number to search for.
        :return: Returns the binary address or None if lineno is out of bounds.
        """
        self.CheckRebuild()
        info = self._get_address_info_from_lineno(lineno)
        if info is not None:
            return info.address
        return None


    # def _JumpToWord(self, word):
    #     ea = None
    #     if all(c in "x0123456789abcdefABCDEF" for c in word):
    #         try:
    #             ea = int(word,16) # word is a address
    #         except ValueError:
    #             pass
    #     else:
    #         segm = idaapi.get_segm_by_name(word)
    #         if segm:
    #             ea = segm.start_ea # word is a segment name
    #         else:
    #             ea =  idaapi.str2ea(word) # word is a name

    #     if ea == idaapi.BADADDR:
    #         result: List[str] = split(r'\.|:|;|\+|-|\[|\]', word)
    #         if result:
    #             for w in reversed(result):
    #                 ea =  idaapi.str2ea(w)
    #                 if ea != idaapi.BADADDR:
    #                     break

    #     if ea:
    #         return idaapi.jumpto(ea)
    #     return False


    # def OnDblClick(self, shift):
    #     dblclick_word = self.GetCurrentWord()
    #     if not dblclick_word:
    #         return False
    #     return self._JumpToWord(dblclick_word)


    def SetDblClickCallback(self, callback):
        self.dbl_click_callback = callback


    def OnDblClick(self, shift):
        if self.dbl_click_callback:
            return self.dbl_click_callback(self)
        return False


    def OnKeydown(self, vkey, shift):
        for key, need_shift, callback in self.keydown_callback_list:
            if key == vkey and (not need_shift or shift):
                callback(self)


    def AddKeyDownCallback(self, target_vkey: int, need_shift: bool, callback):
        """
        Add keydown callback function for this viewer

        callback function receive parameters: the customviewer itself.
        """
        self.keydown_callback_list.append((target_vkey, need_shift, callback))


    def AddAction(self, action_handler: MenuActionHandler):
        actname = action_handler.get_action_name()
        ida_kernwin.attach_action_to_popup(self.GetWidget(), None, actname)

        self.menu_action_handlers.append(action_handler)






class ColorfulLineGenerator():
    def __init__(self):
        pass

    @staticmethod
    def GenerateRegisterLine(reg_name, reg_value, value_len) -> str:
        colored_reg_name = ida_lines.COLSTR(f" {reg_name:>6}", ida_lines.SCOLOR_DEFAULT)
        colored_reg_value = ida_lines.COLSTR(f"0x{reg_value:0{value_len}X}", ida_lines.SCOLOR_SYMBOL)
        return colored_reg_name + ": " + colored_reg_value

    @staticmethod
    def GenerateDisassemblyDataLine(address, address_len, value, value_len) -> str:
        addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}", ida_lines.SCOLOR_PREFIX)
        if len(value) <= 8:
            data_hex_parts = [f"{byte:02x}" for byte in value]
            full_str = ' '.join(data_hex_parts)
            data_str =  full_str
        else:
            prefix = ' '.join(f"{byte:02x}" for byte in value[:3])
            suffix = ' '.join(f"{byte:02x}" for byte in value[-3:])
            data_str =  f"{prefix} ... {suffix}"
        colored_value = ida_lines.COLSTR(data_str, ida_lines.SCOLOR_BINPREF)
        return f"     {addr_str}  {colored_value}"

    @staticmethod
    def GenerateDisassemblyNameLine(address, address_len) -> str:
        addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}", ida_lines.SCOLOR_PREFIX)
        name_str = ida_name.get_nice_colored_name(address)
        return f"     {addr_str}  {name_str}"

    @staticmethod
    def GenerateDisassemblyCodeLine(address, address_len, value, value_len, execution_counts, generate_by_capstone=False) -> str:

        if execution_counts == 0:
            execution_counts_str = "    "
        elif execution_counts == 1:
            execution_counts_str = ida_lines.COLSTR(f"{execution_counts: 4}", ida_lines.SCOLOR_AUTOCMT)
        else:
            execution_counts_str = ida_lines.COLSTR(f"{execution_counts: 4}", ida_lines.SCOLOR_REGCMT)

        if not generate_by_capstone:
            addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}", ida_lines.SCOLOR_PREFIX)
            insn = ida_lines.generate_disasm_line(address)
        else:
            addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}", ida_lines.SCOLOR_IMPNAME)
            opcode, operand = InstrctionParser().parse_instruction_to_tuple(value)
            insn = ida_lines.COLSTR(opcode, ida_lines.SCOLOR_INSN) + "     " + ida_lines.COLSTR(operand, ida_lines.SCOLOR_DNAME)
        return f"{execution_counts_str} {addr_str}  {insn}"

    @staticmethod
    def GenerateUnknownLine(address, address_len):
        addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}", ida_lines.SCOLOR_DREFTAIL)
        return f"     {addr_str}  ??"

    @staticmethod
    def GenerateEmptyLine(address, address_len):
        addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}", ida_lines.SCOLOR_PREFIX)
        return f"     {addr_str}  "

    @staticmethod
    def GenerateErrorLine(address, address_len, error_msg):
        addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}  {error_msg}", ida_lines.SCOLOR_ERROR)
        return f"     {addr_str}  "

    @staticmethod
    def GenerateMemoryLine(address, address_len, data_bytes, bytes_per_line=16, data_patch_indices: Optional[List[int]] = None) -> Tuple[str, List[Tuple[int, int, int]]]:
        """
        Generates a colored memory dump line.
        Example: 0x00401000  48 83 EC 28 48 8B C4 48 | H. .(.H. .H

        :return: Returns a tuple (colored_line, hightlight_byte_indices)
            colored_line: The colored memory dump line.
            hightlight_byte_indices: A list of tuples (color, start_index, length) indicating the byte ranges to highlight.
        """
        addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}", ida_lines.SCOLOR_PREFIX)

        hex_dump_parts = []
        ascii_dump_parts = []

        hightlight_byte_indices: List[Tuple[int, int, int]] = []
        for i, byte_val in enumerate(data_bytes):
            hex_part = f"{byte_val:02X}"

            # Check if this byte is part of a patch
            if data_patch_indices and i in data_patch_indices:
                hex_dump_parts.append(ida_lines.COLSTR(hex_part, ida_lines.SCOLOR_BINPREF)) # Highlight changed bytes
                hightlight_byte_indices.append((BYTE_CHANGE_HIGHTLIGHT, 2 + address_len + 2 + 3 * i, 2))
            else:
                hex_dump_parts.append(ida_lines.COLSTR(hex_part, ida_lines.SCOLOR_BINPREF)) # Default color

            if 0x20 <= byte_val <= 0x7E:
                ascii_dump_parts.append(chr(byte_val))
            else:
                ascii_dump_parts.append('.')

        hex_str = ' '.join(hex_dump_parts).ljust(bytes_per_line * 3 - 1)
        ascii_str = ''.join(ascii_dump_parts)

        return f"{addr_str}  {hex_str} | {ascii_str}", hightlight_byte_indices

    @staticmethod
    def GenerateEmplyMemoryLine(address, address_len, bytes_per_line=16) -> str:
        """
        Generates a colored empty memory dump line.
        """
        addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}", ida_lines.SCOLOR_DREFTAIL)
        hex_str = " ".join("??" for _ in range(bytes_per_line))
        ascii_str = "".join("." for _ in range(bytes_per_line))

        return f"{addr_str}  {hex_str} | {ascii_str}"


class TTE_DisassemblyViewer():
    """
    a subviewer class of TimeTravelEmuViewer to display disassembly.

    To use it following the steps:
    1. Use self.InitViewer() to initializate the viewer.
    2. Add self.viewer_widget to TimeTravelEmuViewer's layout.
    3. Use self.LoadListFromESM() to statistics execution counts of code lines.
    4. Use self.LoadState() to load state data, including self.memory_pages_list and self.execution_counts
    5. Use self.DisplayMemoryRange() to display memory pages in range.
    6. Call TimeTravelEmuViewer.Show() to show viewer with the subviewer.
    """

    title = "TimeTravelEmuDisassemblyViewer"

    def __init__(self):
        self.viewer = AddressAwareCustomViewer()
        self.bitness = get_bitness()
        if self.bitness:
            self.addr_len = self.bitness // 4
        else:
            tte_log_err("Failed to get bitness")

        self.statusbar_state_id_qlabel: Optional[QtWidgets.QLabel] = None
        self.statusbar_memory_range_qlabel: Optional[QtWidgets.QLabel] = None

        self.execution_counts = None
        self.codelines_dict:Dict[int, int] = {}  # {address : address_idx)}
        self.capstone_lines: Dict[int, Tuple[bytes, int, str]] = {} # {address : (code_size, capstone_insn_str)}


        self.current_state = None
        self.memory_pages_list = None

        self.current_insn_address: int = -1
        self.current_range_display_start: int = -1;
        self.current_range_display_end: int = -1;


        self.hightlighting_lines: List[Tuple[int, int, Optional[int]]] = [] # [(address, lineno, color),...]
        self.code_lines_comments: List[Tuple[int, bool, str]] = [] # [(address, has_show, comment),...]

    def InitViewer(self):
        self.viewer.Create(self.title)
        self.viewer_widget  = ida_kernwin.PluginForm.FormToPyQtWidget(self.viewer.GetWidget())
        self._SetCustomViewerStatusBar()
        self._SetDoubleClickCallback()
        self._SetMenuActions()


    def _SetCustomViewerStatusBar(self):
        # Remove original status bar
        viewer_status_bar = self.viewer_widget.findChild(QtWidgets.QStatusBar)
        for widget in viewer_status_bar.findChildren(QtWidgets.QLabel):
            viewer_status_bar.removeWidget(widget)

        self.statusbar_state_id_qlabel = QtWidgets.QLabel("[Status: N\\A ]")
        viewer_status_bar.addWidget(self.statusbar_state_id_qlabel)
        self.statusbar_memory_range_qlabel = QtWidgets.QLabel("(Memory Range: N\\A )")
        viewer_status_bar.addWidget(self.statusbar_memory_range_qlabel)


    def _SetDoubleClickCallback(self):

        def OnDblClickAction(custom_viewer: AddressAwareCustomViewer):
            """
            Action:
                If user double click a address, jump to it in IDA View
                If user double click a word, jump to it's address in CustomViewer
            """
            dblclick_word = custom_viewer.GetCurrentWord()
            if not dblclick_word:
                return False
            ea = None
            if all(c in "x0123456789abcdefABCDEF" for c in dblclick_word):
                try:
                    ea = int(dblclick_word,16) # word is a address
                    return idaapi.jumpto(ea)
                except ValueError:
                    pass

            if ea is None:
                segm = idaapi.get_segm_by_name(dblclick_word)
                if segm:
                    ea = segm.start_ea # word is a segment name
                else:
                    ea =  idaapi.str2ea(dblclick_word) # word is a name

            if ea == idaapi.BADADDR:
                result: List[str] = split(r'\.|:|;|\+|-|\[|\]', dblclick_word)
                if result:
                    for w in reversed(result):
                        ea =  idaapi.str2ea(w)
                        if ea != idaapi.BADADDR:
                            break
            if ea != idaapi.BADADDR:
                self.JumpTo(ea)
                return True
            return False

        self.viewer.SetDblClickCallback(OnDblClickAction)


    def GetCursorAddress(self):
        lineno =  self.viewer.GetLineNo()
        if lineno is not None:
            return self.viewer.GetAddressFromLineNo(lineno)
        return None


    def _SetMenuActions(self):
        self.viewer.AddAction(MenuActionHandler(self.title, lambda : True,
                              f"{self.title}:RefreshAction",
                              self.RefreshAction, "Refresh", ""))
        self.viewer.AddAction(MenuActionHandler(self.title, lambda : True,
                              f"{self.title}:JumpAction",
                              self.InputJumpAction, "Jump to address", "G"))
        self.viewer.AddAction(MenuActionHandler(self.title, lambda : True,
                              f"{self.title}:SetMemoryRangeAction",
                              self.SetDisplayMemoryRangeAction, "Set memory range", "R"))


    def UnregisterAction(self):
        self.viewer.UnregisterAction()


    def AddMenuActions(self, action_handler: MenuActionHandler):
        action_handler.parent_title = self.title
        self.viewer.AddAction(action_handler)


    def ClearLines(self):
        self.viewer.ClearLines()
        self.current_insn_address = -1
        self.current_range_display_start = -1;
        self.current_range_display_end = -1;


    def JumpTo(self, address):
        assert self.memory_pages_list, "State data not loaded"

        if self.current_range_display_start < address and self.current_range_display_end > address:
            self.viewer.Jump(address, 5, 0)

        else:
            # page undisplay
            starts = [entry[0] for entry in self.memory_pages_list]
            idx = bisect.bisect_right(starts, address) - 1

            if idx >= 0 and 0 <= address - starts[idx] < PAGE_SIZE:
                self.DisplayMemoryRange(starts[idx], starts[idx]+ PAGE_SIZE)
                self.viewer.Jump(address, 5, 0)
            else:
                if idaapi.ask_yn(1, "Target address not loaded, Continue?") == 1:
                    self.DisplayMemoryRange(address, address+ PAGE_SIZE)
                    self.viewer.Jump(address, 5, 0)


    def RefreshAction(self):
        self.ClearHighlightLines()
        self.ClearCodeLinesComments()

        self.DisplayMemoryRange(self.current_range_display_start, self.current_range_display_end)


    def InputJumpAction(self):
        n = self.viewer.GetLineNo()
        if n is not None:
            target_addr = ida_kernwin.ask_addr(self.viewer.GetLineNo(), "Jump to address")
            if target_addr:
                self.JumpTo(target_addr)
        return None


    def SetDisplayMemoryRangeAction(self):
        assert self.memory_pages_list, "State data not loaded"

        class RangeInputForm(idaapi.Form):
            def __init__(self, start_addr, end_addr):
                self.start_addr = start_addr
                self.end_addr = end_addr

                self.RangeStart: Optional[ida_kernwin.Form.NumericInput]  = None
                self.RangeEnd: Optional[ida_kernwin.Form.NumericInput] = None
                super().__init__(
                r'''
                {FormChangeCb}
                <Range Start: {RangeStart}> | <Range End: {RangeEnd}>
                ''',
                {
                "FormChangeCb": self.FormChangeCb(self.OnFormChange),

                "RangeStart": self.NumericInput(value = self.start_addr, swidth = 30),
                "RangeEnd": self.NumericInput(value = self.end_addr, swidth = 30),
                }
                )
                self.Compile()

            def OnFormChange(self,fid):
                assert self.RangeStart and self.RangeEnd
                if fid == self.RangeStart.id or fid == self.RangeEnd.id:
                    self.start_addr = self.GetControlValue(self.RangeStart)
                    self.end_addr = self.GetControlValue(self.RangeEnd)
                return 1

        form = RangeInputForm(self.current_range_display_start,self.current_range_display_end)
        IsSet = form.Execute()
        if IsSet == 1:
            range_start: int = form.start_addr # type: ignore
            range_end: int = form.end_addr # type: ignore

            if range_start > range_end:
                idaapi.warning("Invalid range, start address should be less than end address")
            elif range_end - range_start > 16 * PAGE_SIZE:
                ok = idaapi.ask_yn(0, f"The range is too large, do you want to continue? (Range: {range_start:X} - {range_end:X})")
                if ok == 1:
                    self.DisplayMemoryRange(range_start, range_end)
            else:
                self.DisplayMemoryRange(range_start, range_end)
        form.Free()


    def LoadListFromESM(self, state_list: StateList):
        """
        Load execution counts from StateList.

        Here it is believed that the state list is arranged in the order in which it was created,
        so the execution counts of the later record must be greater than the number of previous records in the same address, and can be directly overwritten.
        """
        self.execution_counts= {state.instruction_address: state.execution_count for _, state in state_list}


    def LoadState(self, state: EmuState, insn_address: int, memory_pages: MemoryPagesDict):
        assert self.statusbar_state_id_qlabel, "Status bar not initialized"
        self.ClearHighlightLines()
        self.ClearCodeLinesComments()

        self.current_state = state
        self.current_insn_address = insn_address
        self.memory_pages_list = sorted(memory_pages.items())
        self.statusbar_state_id_qlabel.setText(f"[State: {self.current_state.state_id} ]")


    def AddHightlightLine(self, address, address_idx, color):
        self.hightlighting_lines.append((address, address_idx, color))


    def HighlightLines(self):
        for address, address_idx, color in self.hightlighting_lines:
            self.viewer.EditLineColor(address, address_idx, 0, color)


    def ClearHighlightLines(self):
        while len(self.hightlighting_lines) > 0:
            address, lineno, color = self.hightlighting_lines.pop()
            self.viewer.EditLineColor(address, lineno, None)


    def AddCodeLinesComments(self, address, comment):
        self.code_lines_comments.append((address, False, comment))


    def ShowCodeLinesComments(self):
        for idx, (address, has_show, comment) in enumerate(self.code_lines_comments):
            if not has_show:
                address_idx = self.codelines_dict.get(address, 0)
                line = self.viewer.GetLine(address, address_idx)
                if line:
                    line_with_comment = f"{line.value}  {comment}"
                    self.viewer.EditLine(address,
                                        address_idx,
                                        CODE_LINE,
                                        line_with_comment,
                                        line.bgcolor,
                                        line.bgcolor)
                    # Replace the tuple with a new one with has_show set to True
                    self.code_lines_comments[idx] = (address, True, comment)


    def ClearCodeLinesComments(self):
        while len(self.code_lines_comments) > 0:
            address, has_show, comment = self.code_lines_comments.pop()
            address_idx = self.codelines_dict.get(address, 0)
            if has_show:
                line = self.viewer.GetLine(address, address_idx)
                if line:
                    line_without_comment = line.value[:-(len(comment)+2)]
                    self.viewer.EditLine(address,
                                        address_idx,
                                        CODE_LINE,
                                        line_without_comment,
                                        line.fgcolor,
                                        line.bgcolor)


    def MarkCurrentInsn(self):
        assert self.current_state is not None, "State not loaded"
        assert self.memory_pages_list, "State data not loaded"

        if self.current_insn_address > 0 and self.current_insn_address >= self.current_range_display_start and self.current_insn_address < self.current_range_display_end:
            # Highlight current instruction in memory range.
            self.AddHightlightLine(self.current_insn_address, self.codelines_dict.get(self.current_insn_address, 0), EXECUTE_INSN_HILIGHT_COLOR)

            # If the current instruction is not recognized as a code by IDA, disassemlby it use capstone.
            if not idc.is_code(ida_bytes.get_flags(self.current_insn_address)):
                count = 0
                if self.execution_counts and self.current_insn_address in self.execution_counts:
                    count = self.execution_counts[self.current_insn_address]
                if len(self.current_state.instruction) != 0:
                    code_bytes = self.current_state.instruction
                    code_size = len(code_bytes)
                    line_text = ColorfulLineGenerator.GenerateDisassemblyCodeLine(self.current_insn_address,
                                                                                              self.addr_len,
                                                                                              code_bytes,
                                                                                              code_size,
                                                                                              count,
                                                                                              True)
                    self.capstone_lines[self.current_insn_address] = (code_bytes, code_size, line_text)
                    self.viewer.UpdateLineRange(self.current_insn_address,
                                                len(self.current_state.instruction),
                                                SINGLE_DATA_LINE,
                                                line_text,
                                                None,
                                                None)



    def ApplyStatePatchesInViewer(self, mem_patch: Optional[List[Tuple[int, bytes]]], page_diff: Optional[SortedDict]):
        """
        Apply memory patches to the viewer and highlight the changed lines.

        :param mem_patch: A list of tuples (address, value) representing the changed memory.
        :param page_diff: A sorted dictionary of memory pages, with keys as start addresses and values as tuples (change_mode, data).
                            change_mode: 1 - removed, 2 - added
        :return: None
        """
        assert self.current_state is not None, "State not loaded"
        assert self.memory_pages_list, "State data not loaded"

        if page_diff:
            need_rebuild = False
            for start_addr, (change_mode, data) in page_diff.items():
                if change_mode == 1:
                    # removed page
                    for i in range(start_addr, start_addr + PAGE_SIZE):
                        if i >= self.current_range_display_start and i < self.current_range_display_end:
                            need_rebuild = True

                elif change_mode == 2:
                    # added page
                    for i in range(start_addr, start_addr + PAGE_SIZE):
                        if i >= self.current_range_display_start and i < self.current_range_display_end:
                            need_rebuild = True
            if need_rebuild:
                self.DisplayMemoryRange(self.current_range_display_start, self.current_range_display_end)

        if mem_patch:
            for addr, value in mem_patch:
                if addr > self.current_range_display_start and addr < self.current_range_display_end:
                    addr_info = self.viewer.GetLine(addr, 0)
                    if addr_info is not None and addr_info.type == SINGLE_DATA_LINE:
                        line_text = ColorfulLineGenerator.GenerateDisassemblyDataLine(addr, self.addr_len, value, 1)
                        self.viewer.EditLine(addr, 0, SINGLE_DATA_LINE, line_text, None, None)
                    else:
                        line_text = ColorfulLineGenerator.GenerateDisassemblyDataLine(addr, self.addr_len, value, 1) # TODO: fix this line_text when data size > 1
                        self.viewer.UpdateLine(addr, 0, SINGLE_DATA_LINE, line_text, None, None)
                self.hightlighting_lines.append((addr, 0, CHANGE_HIGHLIGHT_COLOR))

        self.MarkCurrentInsn()
        self.HighlightLines()
        self.ShowCodeLinesComments()
        self.viewer.Refresh()


    def DisplayMemoryRange(self, range_start, range_end):
        """
        Display memory range in the viewer. This function will clear the previous range and display the new range.
        By the way, it can also be used to refresh the current range.

        :param range_start: start address of the range.
        :param range_end: end address of the range.
        :return: None
        """
        assert self.current_state is not None, "State not loaded"
        assert self.memory_pages_list and self.execution_counts, "State data not loaded"
        assert self.statusbar_memory_range_qlabel, "Status bar not initialized"

        self.viewer.ClearLines()
        self.codelines_dict.clear()
        current_addr = range_start
        for start_addr, (perm, data) in self.memory_pages_list:
            data_length =  len(data)

            if start_addr > range_end or start_addr + data_length <= range_start:
                continue

            # Process empty addresses that may exist before the current page
            while current_addr < start_addr:
                line_text = ColorfulLineGenerator.GenerateUnknownLine(current_addr, self.addr_len)
                self.viewer.AddLine(current_addr, UNKNOW_LINE, line_text)
                self.viewer.AddLine(current_addr, UNKNOW_LINE, line_text)
                current_addr += 1

            while current_addr < start_addr + data_length and current_addr < range_end:
                count = 0
                address_idx = 0
                if current_addr in self.execution_counts:
                    count = self.execution_counts[current_addr]

                current_addr_flag = ida_bytes.get_flags(current_addr)

                # If the current address has a name, display it in a separate line.
                is_named = ida_bytes.has_any_name(current_addr_flag)
                if is_named:
                    empty_line_text = ColorfulLineGenerator.GenerateEmptyLine(current_addr, self.addr_len)
                    line_text = ColorfulLineGenerator.GenerateDisassemblyNameLine(current_addr, self.addr_len)
                    self.viewer.AddLine(current_addr, EMPTY_LINE, empty_line_text)
                    self.viewer.AddLine(current_addr, NAME_LINE, line_text)
                    address_idx += 2

                # If the data at the current address is recognized as code.
                if idc.is_code(current_addr_flag):
                    code_size = idc.get_item_size(current_addr)
                    offset = current_addr - start_addr
                    line_text = ColorfulLineGenerator.GenerateDisassemblyCodeLine(current_addr,
                                                                                       self.addr_len,
                                                                                       data[offset : offset + code_size],
                                                                                       code_size,
                                                                                       count)
                    self.viewer.AddLine(current_addr, CODE_LINE, line_text)
                    self.codelines_dict[current_addr] = address_idx
                    current_addr += code_size
                    continue

                # If the data at the current address isn't recognized as code, but cached at capstone line dict and has the same bytes.
                if current_addr in self.capstone_lines.keys():
                    code_bytes, code_size, line_text = self.capstone_lines[current_addr]
                    if code_bytes == data[current_addr - start_addr : current_addr - start_addr + code_size]:
                        self.viewer.AddLine(current_addr, CODE_LINE, line_text)
                        self.codelines_dict[current_addr] = address_idx
                        current_addr += code_size
                        continue

                # If the data at the current address is recognized as data.
                if idc.is_data(current_addr_flag):
                    data_size = idc.get_item_size(current_addr)
                    offset = current_addr - start_addr
                    line_text = ColorfulLineGenerator.GenerateDisassemblyDataLine(current_addr,
                                                                                  self.addr_len,
                                                                                  data[offset : offset + data_size],
                                                                                  data_size)
                    if data_size == 1:
                        self.viewer.AddLine(current_addr, SINGLE_DATA_LINE, line_text)
                    else:
                        self.viewer.AddLine(current_addr, CODE_LINE, line_text)

                    current_addr += data_size
                    continue

                # Unknown address type.
                else:
                    line_text = ColorfulLineGenerator.GenerateDisassemblyDataLine(current_addr,
                                                                                  self.addr_len,
                                                                                  data[current_addr - start_addr : current_addr - start_addr + 1],
                                                                                  1)
                    self.viewer.AddLine(current_addr, SINGLE_DATA_LINE, line_text)

                    current_addr += 1
                    continue

        # After processing all memory pages, fill in the possible empty addresses.
        while current_addr < range_end:
            line_text = ColorfulLineGenerator.GenerateUnknownLine(current_addr, self.addr_len)
            self.viewer.AddLine(current_addr, UNKNOW_LINE, line_text)
            current_addr += 1

        self.current_range_display_start = range_start
        self.current_range_display_end = range_end

        self.MarkCurrentInsn()
        self.HighlightLines()
        self.ShowCodeLinesComments()
        self.viewer.Refresh()

        # Set status bar memory range label.
        self.statusbar_memory_range_qlabel.setText(f"(Mem: 0x{range_start:0{self.addr_len}X} ~ 0x{range_end:0{self.addr_len}X})")


class TTE_RegistersViewer:
    """
    a subviewer class of TimeTravelEmuViewer to display registers.

    To use it following the steps:
    1. Use self.InitViewer() to initializate the viewer.
    2. Add self.viewer_widget to TimeTravelEmuViewer's layout.
    3. Use self.SetRegisters() to load registers values for a specific state.
    4. Use self.DisplayRegisters() to display the registers values.
    5. Call TimeTravelEmuViewer.Show() to show the viewer with this subviewer.
    """

    title = "TimeTravelEmuRegistersViewer"

    class custviewer(ida_kernwin.simplecustviewer_t):
        def __init__(self):
            super().__init__()
            self.dbl_click_callback = None

        def SetDblClickCallback(self, callback):
            self.dbl_click_callback = callback

        def OnDblClick(self, shift):
            if self.dbl_click_callback:
                return self.dbl_click_callback(self)
            return False


    def __init__(self):
        self.viewer = self.custviewer()
        self.bitness = get_bitness()
        if self.bitness:
            self.hex_len = self.bitness // 4
        else:
            tte_log_err("Failed to get bitness")

        self.current_state_id: Optional[str] = None # Only SetRegisters() change this value.

        self.regs_values: Optional[RegistersDict] = None # Only SetRegisters() change this value.
        self.regs_patch: Optional[List[str]] = None # Only SetRegsPatch() change this value.


    def InitViewer(self):
        self.viewer.Create(self.title)
        self.viewer_widget  = ida_kernwin.PluginForm.FormToPyQtWidget(self.viewer.GetWidget())
        self.statusbar_label = QtWidgets.QLabel("State ID: N\\A")

        self._SetCustomViewerStatusBar()


    def SetDblClickCallback(self, callback):
        self.viewer.SetDblClickCallback(callback)


    def _SetCustomViewerStatusBar(self):
        # Remove original status bar
        viewer_status_bar = self.viewer_widget.findChild(QtWidgets.QStatusBar)
        for widget in viewer_status_bar.findChildren(QtWidgets.QLabel):
            viewer_status_bar.removeWidget(widget)

        viewer_status_bar.addWidget(self.statusbar_label)


    def _RefreshStatusBar(self, state_id: str):
        self.statusbar_label.setText(f"State ID: {state_id}")


    def SetRegisters(self, state_id: str, regs_values: RegistersDict):
        self.current_state_id = state_id
        self.regs_values = regs_values
        self._RefreshStatusBar(state_id)


    def SetRegsPatch(self, state_id: str, regs_patch: Optional[RegistersDict]):
        assert state_id == self.current_state_id
        if regs_patch is not None:
            self.regs_patch = list(regs_patch.keys())


    def DisplayRegisters(self):
        assert self.regs_values is not None, "No state data loaded"

        self.viewer.ClearLines()
        changed_bgcolor = CHANGE_HIGHLIGHT_COLOR
        for reg_name, reg_value in self.regs_values.items():

            line_bgcolor = None

            if self.regs_patch is not None and reg_name in self.regs_patch:
                line_bgcolor = changed_bgcolor

            line_text = ColorfulLineGenerator.GenerateRegisterLine(reg_name, reg_value, self.hex_len)
            self.viewer.AddLine(line_text, bgcolor=line_bgcolor)

        self.viewer.Refresh()



class TTE_MemoryViewer:
    """
    A subviewer class of TimeTravelEmuViewer to display memory.

    To use it, follow these steps:
    1. Use self.InitViewer() to initialize the viewer.
    2. Add self.viewer_widget to TimeTravelEmuViewer's layout.
    3. Use self.LoadState() to load memory pages for a specific state.
    4. Use self.DisplayMemoryRange() to display a specific memory range.
    5. Call TimeTravelEmuViewer.Show() to show the viewer with this subviewer.
    """

    title = "TimeTravelEmuMemoryViewer"
    BYTES_PER_LINE = 16 # How many bytes to display per line in the memory dump

    class MemoryViewerHooks(ida_kernwin.UI_Hooks):
        def __init__(self, viewer):
            ida_kernwin.UI_Hooks.__init__(self)
            self.viewer: AddressAwareCustomViewer = viewer

            # Key: Line number Value: List, each element is (color key, character start index, number of characters)
            self.marked_bytes = {}
            self.hook()

        def get_lines_rendering_info(self, out, widget, rin):
            # Apply coloring only if widget is customview
            if widget == self.viewer.GetWidget():
                for section_lines in rin.sections_lines:
                    for line_info in section_lines:
                        current_line_nr = ida_kernwin.place_t.as_simpleline_place_t(line_info.at).n
                        current_address = self.viewer.GetAddressFromLineNo(current_line_nr)
                        if current_address in self.marked_bytes:
                            directives = self.marked_bytes[current_address]

                            for directive in directives:
                                e = ida_kernwin.line_rendering_output_entry_t(line_info)

                                color, char_start_idx, char_count = directive
                                e.bg_color = color
                                e.cpx = char_start_idx
                                e.nchars = char_count
                                e.flags |= ida_kernwin.LROEF_CPS_RANGE

                                out.entries.push_back(e)


    def __init__(self):
        self.viewer = AddressAwareCustomViewer()
        self.hook: TTE_MemoryViewer.MemoryViewerHooks = self.MemoryViewerHooks(self.viewer)
        self.hightlighting_bytes = self.hook.marked_bytes


        self.bitness = get_bitness()
        if self.bitness:
            self.addr_len = self.bitness // 4
        else:
            tte_log_err("Failed to get bitness")
        self.is_be = get_is_be()

        self.statusbar_state_id_qlabel: Optional[QtWidgets.QLabel] = None
        self.statusbar_memory_range_qlabel: Optional[QtWidgets.QLabel] = None

        self.current_state_id: Optional[str] = None
        self.memory_pages_list: Optional[List[Tuple[int, Tuple[int, bytearray]]]] = None # Sorted list of (start_addr, (perm, data))

        self.current_range_display_start: int = -1
        self.current_range_display_end: int = -1


    def InitViewer(self):
        self.viewer.Create(self.title)
        self.viewer_widget  = ida_kernwin.PluginForm.FormToPyQtWidget(self.viewer.GetWidget())
        self._SetCustomViewerStatusBar()
        self._SetDoubleClickCallback()
        self._SetMenuActions()


    def _SetCustomViewerStatusBar(self):
        viewer_status_bar = self.viewer_widget.findChild(QtWidgets.QStatusBar)
        if not viewer_status_bar:
            # Create a new status bar if it doesn't exist (e.g., if simplecustviewer_t doesn't create one by default)
            viewer_status_bar = QtWidgets.QStatusBar()
            self.viewer_widget.layout().addWidget(viewer_status_bar) # Assuming a layout exists

        # Clear existing widgets from status bar
        for widget in viewer_status_bar.findChildren(QtWidgets.QLabel):
            viewer_status_bar.removeWidget(widget)

        self.statusbar_state_id_qlabel = QtWidgets.QLabel("[State: N\\A ]")
        viewer_status_bar.addWidget(self.statusbar_state_id_qlabel)
        self.statusbar_memory_range_qlabel = QtWidgets.QLabel("(Mem: N\\A )")
        viewer_status_bar.addWidget(self.statusbar_memory_range_qlabel)


    def _SetDoubleClickCallback(self):
        def OnDblClickAction(custom_viewer: AddressAwareCustomViewer):
            """
            Action: If user double-clicks an address, jump to it in IDA View.
            """
            lineno = custom_viewer.GetLineNo() # Get the line number of the clicked line
            if lineno is not None:
                addr = custom_viewer.GetAddressFromLineNo(lineno) # Get the address of the clicked line
                if addr is not None:
                    return idaapi.jumpto(addr)
            return False

        self.viewer.SetDblClickCallback(OnDblClickAction)


    def _SetMenuActions(self):
        self.viewer.AddAction(MenuActionHandler(self.title, lambda : True,
                              f"{self.title}:RefreshAction",
                              self.RefreshAction, "Refresh", ""))
        self.viewer.AddAction(MenuActionHandler(self.title, lambda : True,
                              f"{self.title}:JumpAction",
                              self.InputJumpAction, "Jump to address", "G"))
        self.viewer.AddAction(MenuActionHandler(self.title, lambda : True,
                              f"{self.title}:SetMemoryRangeAction",
                              self.SetDisplayMemoryRangeAction, "Set memory range", "R"))
        self.viewer.AddAction(MenuActionHandler(self.title, lambda : True,
                              f"{self.title}:ExportSelectedMemoryAction",
                              self.ExportSelectedMemoryAction, "Export selected memory", "E"))


    def AddMenuActions(self, action_handler: MenuActionHandler):
        action_handler.parent_title = self.title
        self.viewer.AddAction(action_handler)


    def UnregisterAction(self):
        self.viewer.UnregisterAction()


    def ClearLines(self):
        self.viewer.ClearLines()
        self.current_range_display_start = -1
        self.current_range_display_end = -1


    def JumpTo(self, address):
        """
        Jumps to the given address in the memory viewer.
        If the address is not within the current display range, it will try to load a page around it.
        """
        assert self.memory_pages_list, "Memory pages data not loaded"

        # Check if the address is already within the currently displayed range
        if self.current_range_display_start <= address < self.current_range_display_end:
            self.viewer.Jump(address)
            return

        # Find the page containing the address
        idx = bisect.bisect_right([entry[0] for entry in self.memory_pages_list], address) - 1

        if idx >= 0:
            page_start_addr, _ = self.memory_pages_list[idx]
            if page_start_addr <= address < page_start_addr + PAGE_SIZE:
                # Address is within a known page, display that page
                self.DisplayMemoryRange(page_start_addr, page_start_addr + PAGE_SIZE)
                self.viewer.Jump(address)
                return

        # If the address is not in any known page, or idx is -1,
        # try to display a default PAGE_SIZE block centered/starting at the address.
        # Align to page boundary for display consistency.
        start_display_addr = (address // self.BYTES_PER_LINE) * self.BYTES_PER_LINE
        end_display_addr = start_display_addr + PAGE_SIZE # Display one page size for context
        idaapi.warning(f"Target address 0x{address:X} not loaded in any known memory page. Displaying a default range 0x{start_display_addr:X}-0x{end_display_addr:X}.")
        self.DisplayMemoryRange(start_display_addr, end_display_addr)
        self.viewer.Jump(address)


    def RefreshAction(self):
        self.DisplayMemoryRange(self.current_range_display_start, self.current_range_display_end)


    def InputJumpAction(self):
        n = self.viewer.GetLineNo()
        current_addr = n if n is not None else 0
        target_addr = ida_kernwin.ask_addr(current_addr, "Jump to address in Memory View")
        if target_addr is not None and target_addr != idaapi.BADADDR:
            self.JumpTo(target_addr)
        return None


    def SetDisplayMemoryRangeAction(self):
        assert self.memory_pages_list, "Memory pages data not loaded"

        class RangeInputForm(idaapi.Form):
            def __init__(self, start_addr, end_addr):
                self.start_addr = start_addr
                self.end_addr = end_addr

                self.RangeStart: Optional[ida_kernwin.Form.NumericInput]  = None
                self.RangeEnd: Optional[ida_kernwin.Form.NumericInput] = None
                super().__init__(
                r'''
                {FormChangeCb}
                <Range Start: {RangeStart}> | <Range End: {RangeEnd}>
                ''',
                {
                "FormChangeCb": self.FormChangeCb(self.OnFormChange),
                "RangeStart": self.NumericInput(value = self.start_addr, swidth = 30),
                "RangeEnd": self.NumericInput(value = self.end_addr, swidth = 30),
                }
                )
                self.Compile()

            def OnFormChange(self,fid):
                assert self.RangeStart and self.RangeEnd
                if fid == self.RangeStart.id or fid == self.RangeEnd.id:
                    self.start_addr = self.GetControlValue(self.RangeStart)
                    self.end_addr = self.GetControlValue(self.RangeEnd)
                return 1

        # Use current display range as default for the input form
        form = RangeInputForm(self.current_range_display_start, self.current_range_display_end)
        IsSet = form.Execute()
        if IsSet == 1:
            range_start: int = form.start_addr # type: ignore
            range_end: int = form.end_addr # type: ignore

            if range_start > range_end:
                idaapi.warning("Invalid range, start address should be less than end address")
            elif range_end - range_start > 16 * PAGE_SIZE:
                ok = idaapi.ask_yn(0, f"The range is too large, do you want to continue? (Range: {range_start:X} - {range_end:X})")
                if ok == 1:
                    self.DisplayMemoryRange(range_start, range_end)
            else:
                self.DisplayMemoryRange(range_start, range_end)
        form.Free()


    def ExportSelectedMemoryAction(self):
        """
        Exports the currently selected memory data as a byte array to idaapi.msg.
        """
        if not self.memory_pages_list:
            idaapi.warning("No memory data loaded to export.")
            return

        selection = self.viewer.GetSelection()
        if not selection:
            return

        # GetSelection returns (x1, address1, x2, address2)
        x, start_addr, y, end_addr = selection

        x_offset = max(min((x - self.addr_len - 3) // 3, self.BYTES_PER_LINE ), 0)
        y_offset = max(min((y - self.addr_len - 2) // 3, self.BYTES_PER_LINE ), 0)

        start_addr += x_offset
        end_addr += y_offset

        if start_addr > end_addr:
            start_addr, end_addr = end_addr, start_addr # Swap if selected backwards

        exported_bytes = bytearray()

        # Iterate through the selected range
        current_export_addr = start_addr
        while current_export_addr < end_addr: # <= because end_addr is inclusive from GetSelection
            found_byte = False
            for page_start_addr, (perm, page_content) in self.memory_pages_list:
                if page_start_addr <= current_export_addr < page_start_addr + PAGE_SIZE:
                    offset_in_page = current_export_addr - page_start_addr
                    exported_bytes.append(page_content[offset_in_page])
                    found_byte = True
                    break

            if not found_byte:
                exported_bytes.append(0x00) # Append a null byte for unmapped or unavailable memory

            current_export_addr += 1

        if not exported_bytes:
            idaapi.msg("No data found in the selected range.\n")
            return

        # Format the bytearray for output via idaapi.msg
        hex_dump = ', '.join(f"0x{byte:02x}" for byte in exported_bytes)
        int_dump = int.from_bytes(exported_bytes, byteorder='big' if self.is_be else 'little',  signed=False)
        str_dump = exported_bytes.decode('utf-8', 'ignore')

        output_msg = f"--- Exported Memory Data (0x{start_addr:X} - 0x{end_addr:X}) ---\n"
        output_msg += f"Hex: {hex_dump}\n"
        output_msg += f"Int: {int_dump:X}\n"
        output_msg += f"Str: {str_dump}\n"
        output_msg += f"Length: {len(exported_bytes)} bytes\n"
        output_msg += "----------------------------------------\n"

        idaapi.msg(output_msg)

    def LoadState(self, state_id: str, memory_pages: MemoryPagesDict):
        """
        Loads the memory state for display.
        """
        assert self.statusbar_state_id_qlabel, "Status bar not initialized"
        self.current_state_id = state_id
        # Convert the dictionary to a sorted list of (address, (perm, data)) for efficient iteration
        self.memory_pages_list = sorted(memory_pages.items())
        self.statusbar_state_id_qlabel.setText(f"[State: {self.current_state_id} ]")


    def ClearHighlightBytes(self):
        self.hightlighting_bytes.clear()


    def ApplyStatePatchesInViewer(self, mem_patch: Optional[List[Tuple[int, bytes]]], page_diff: Optional[SortedDict]):
        """
        Applies memory patches and highlights changed memory in the viewer.

        :param mem_patch: A list of tuples (address, value) representing the changed memory bytes.
        :param page_diff: A sorted dictionary of memory pages, with keys as start addresses and values as tuples (change_mode, data).
                            change_mode: 1 - removed, 2 - added
        """
        assert self.memory_pages_list, "Memory pages data not loaded"

        # Check if a full rebuild is needed due to page additions/removals
        need_rebuild_for_page_changes = False
        if page_diff:
            for start_addr, (change_mode, data) in page_diff.items():
                if (start_addr < self.current_range_display_end and
                    start_addr + PAGE_SIZE > self.current_range_display_start):
                    need_rebuild_for_page_changes = True
                    break

        if need_rebuild_for_page_changes:
            # Re-display the entire range if pages were added or removed within it
            self.DisplayMemoryRange(self.current_range_display_start, self.current_range_display_end)

        # Clear previous highlights
        self.ClearHighlightBytes()

        # Apply mem_patch and add new highlights
        if mem_patch:
            # Group patches by the start of their display lines
            patches_by_line_start: Dict[int, Dict[int, bytes]] = defaultdict(dict)
            for addr, value_bytes in mem_patch:
                line_start_addr = (addr // self.BYTES_PER_LINE) * self.BYTES_PER_LINE
                offset_within_line = addr % self.BYTES_PER_LINE
                # Store the change, potentially as a single byte
                for i, byte_val in enumerate(value_bytes):
                    patches_by_line_start[line_start_addr][offset_within_line + i] = byte_val.to_bytes(1, byteorder='big' if self.is_be else 'little')

            for line_start_addr, line_patches in patches_by_line_start.items():
                line_info = self.viewer.GetLine(line_start_addr, 0) # Assuming address_idx 0 for memory lines

                if line_info:
                    # Get the raw bytes for the line from the current memory state
                    # This requires searching the memory_pages_list for the relevant page
                    line_data_bytes = bytearray(self.BYTES_PER_LINE) # Default empty bytes
                    for page_addr, (perm, page_data) in self.memory_pages_list:
                        if page_addr <= line_start_addr < page_addr + PAGE_SIZE:
                            # Calculate offset into page_data
                            offset_in_page = line_start_addr - page_addr
                            # Get the relevant chunk, clamp to page boundary
                            chunk_len = min(self.BYTES_PER_LINE, PAGE_SIZE - offset_in_page)
                            line_data_bytes = bytearray(page_data[offset_in_page : offset_in_page + chunk_len])
                            break

                    # Identify indices within line_data_bytes that were patched
                    patch_indices_within_line = sorted(line_patches.keys())

                    # Regenerate the line with highlight colors
                    new_line_text, hightlight_bytes = ColorfulLineGenerator.GenerateMemoryLine(
                        line_start_addr,
                        self.addr_len,
                        line_data_bytes,
                        self.BYTES_PER_LINE,
                        patch_indices_within_line
                    )
                    self.viewer.EditLine(line_start_addr, 0, DATA_LINE, new_line_text, None, None) # Background is handled by COLSTR now
                    self.hightlighting_bytes[line_start_addr] = hightlight_bytes


                elif self.current_range_display_start <= line_start_addr < self.current_range_display_end:
                    temp_line_data = bytearray([0] * self.BYTES_PER_LINE)
                    for offset, byte_val in line_patches.items():
                        if offset < self.BYTES_PER_LINE:
                            temp_line_data[offset : offset + len(byte_val)] = byte_val

                    new_line_text, hightlight_bytes = ColorfulLineGenerator.GenerateMemoryLine(
                        line_start_addr,
                        self.addr_len,
                        temp_line_data,
                        self.BYTES_PER_LINE,
                        sorted(line_patches.keys())
                    )
                    self.viewer.AddLine(line_start_addr, DATA_LINE, new_line_text, bgcolor=CHANGE_HIGHLIGHT_COLOR, lazy=True)
                    self.hightlighting_bytes[line_start_addr] = hightlight_bytes

        self.viewer.Refresh()


    def DisplayMemoryRange(self, range_start, range_end):
        """
        Displays a specified memory range in the viewer.
        This function clears the current view and repopulates it.

        :param range_start: The starting address of the range to display.
        :param range_end: The ending address (exclusive) of the range to display.
        """
        assert self.statusbar_memory_range_qlabel, "Status bar not initialized"
        assert self.memory_pages_list, "Memory pages data not loaded"

        self.viewer.ClearLines()

        current_addr = (range_start // self.BYTES_PER_LINE) * self.BYTES_PER_LINE # Align to line start

        # Track the actual displayed range for the status bar
        actual_display_start = -1
        actual_display_end = -1

        # Iterate through the requested display range, line by line
        while current_addr < range_end:
            line_data = bytearray(self.BYTES_PER_LINE)
            has_data = False

            # Find which memory page(s) contain the current line
            page_found_for_line = False
            for page_start_addr, (perm, page_content) in self.memory_pages_list:
                if page_start_addr <= current_addr < page_start_addr + PAGE_SIZE:
                    # This page contains part of the current line
                    page_found_for_line = True

                    # Calculate relevant offsets and lengths
                    offset_in_page = current_addr - page_start_addr
                    bytes_to_copy = min(self.BYTES_PER_LINE, PAGE_SIZE - offset_in_page)

                    # Copy data from the memory page into line_data
                    line_data[0:bytes_to_copy] = page_content[offset_in_page : offset_in_page + bytes_to_copy]
                    has_data = True

                    # Update actual displayed range
                    if actual_display_start == -1:
                        actual_display_start = current_addr
                    actual_display_end = current_addr + self.BYTES_PER_LINE
                    break # Assuming one page fully covers or starts the line

            if not page_found_for_line:
                line_text = ColorfulLineGenerator.GenerateEmplyMemoryLine(
                    current_addr,
                    self.addr_len,
                    self.BYTES_PER_LINE
                )
            else:
                line_text, _ = ColorfulLineGenerator.GenerateMemoryLine(
                    current_addr,
                    self.addr_len,
                    line_data,
                    self.BYTES_PER_LINE
                )
            self.viewer.AddLine(current_addr, DATA_LINE, line_text) # Use DATA_LINE for generic memory view

            current_addr += self.BYTES_PER_LINE

        self.current_range_display_start = range_start
        self.current_range_display_end = range_end

        # Update status bar
        display_range_text = f"(Mem: 0x{range_start:0{self.addr_len}X} ~ 0x{range_end:0{self.addr_len}X})"
        if actual_display_start != -1:
            display_range_text += f" (Loaded: 0x{actual_display_start:0{self.addr_len}X} ~ 0x{actual_display_end:0{self.addr_len}X})"
        self.statusbar_memory_range_qlabel.setText(display_range_text)

        self.viewer.Refresh()



class TimeTravelEmuViewer(ida_kernwin.PluginForm):
    """
    The main TimeTravelEmuViewer class.

    To use it, you need to do the following steps:
    1. use self.Init() to initialize the viewer.
    2. use self.LoadESM(state_manager) to load the EmuStateManager into the viewer.
    3. use self.Show(“title”) to show the viewer with a title.

    """

    title = "TimeTravelEmuViewer"

    def __init__(self):
        super().__init__()
        self.is_be = get_is_be()


        self.disassembly_viewer: TTE_DisassemblyViewer =  TTE_DisassemblyViewer()
        self.registers_viewer: TTE_RegistersViewer = TTE_RegistersViewer()
        self.mempages_viewer: TTE_MemoryViewer = TTE_MemoryViewer()

        self.subchooser_list: List[ida_kernwin.Choose] = []

        self.state_manager: Optional[EmuStateManager] = None
        self.state_list: Optional[StateList] = None # List of (state_id, state) formed in order of generation

        self.current_state_idx: int = 0 # Index of current state in state_list.
        self.current_state_id: Optional[str] = None # Only SwitchStateDisplay() can change this value.
        self.current_full_state: Optional[FullEmuState] = None # Only SwitchStateDisplay() can change this value.

        self.current_diffs: Optional[Tuple[Tuple[Optional[str], str],  Optional[RegistersDiffsDict], Optional[SortedDict], Optional[SortedDict]]] = None

        # configs
        self.follow_current_instruction = False # True # Whether to follow the current instruction when switching states.


    def Init(self):
        self.disassembly_viewer.InitViewer()
        self.registers_viewer.InitViewer()
        self.mempages_viewer.InitViewer()

        self.SetRegsViewerDoubleClickCallback()

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:NextStateAction",
                              self.SwitchNextStateAction, "Next state", NEXT_STATE_ACTION_SHORTCUT))

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:PrevStateAction",
                              self.SwitchPrevStateAction, "Previous state", PREV_STATE_ACTION_SHORTCUT))

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:CursorStateAction",
                              self.SwitchCursorStateAction, "Switch to state at cursor address", CURSOR_STATE_ACTION_SHORTCUT))

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:StageInputAction",
                              self.SwitchInputStateAction, "Switch to input state", "I"))

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:ChooseStatesAction",
                              self.ChooseStatesAction,   "Choose states", "C"))

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:ChooseMemoryPagesAction",
                              lambda : self.ChooseMemoryPagesAction(self.disassembly_viewer.title, self.disassembly_viewer.DisplayMemoryRange),   "Choose memory pages", "M"))

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:ShowDiffAction",
                              lambda : self.ShowDiffsAciton(self.disassembly_viewer.title, self.disassembly_viewer.JumpTo),   "Show diff", "D"))

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:ToggleFollowCurrentInstructionAction",
                              self.ToggleFollowCurrentInstructionAction, "Toggle follow current instruction", "F"))

        self.mempages_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.mempages_viewer.title}:ChooseMemoryPagesAction",
                              lambda : self.ChooseMemoryPagesAction(self.mempages_viewer.title, self.mempages_viewer.DisplayMemoryRange),   "Choose memory pages", "M"))

        self.mempages_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.mempages_viewer.title}:ShowDiffAction",
                              lambda : self.ShowDiffsAciton(self.mempages_viewer.title, self.mempages_viewer.JumpTo),   "Show diff", "D"))


    def SetRegsViewerDoubleClickCallback(self):
        """
        Set a double click callback for mempages_viewer to allow user to jump to address in disassembly_viewer.

        """

        def OnDblClickAction(custom_viewer: AddressAwareCustomViewer):
            """
            Action:
                If user double click a address which has execute permission, jump to it in DisassemblyViewer
                If user double click a address which only has read permission, jump to it in MemoryViewer
            """
            dblclick_word = custom_viewer.GetCurrentWord()
            if not dblclick_word:
                return False
            ea = None
            if all(c in "x0123456789abcdefABCDEF" for c in dblclick_word):
                try:
                    ea = int(dblclick_word,16) # word is a address
                    if self.current_full_state:
                        memory_pages_list: List[Tuple[int, int, bytearray]] = [(addr, perm, data) for addr, (perm, data) in self.current_full_state.memory_pages.items()]
                        for start_addr, perm, data in memory_pages_list:
                            if start_addr <= ea < start_addr + len(data) and perm & UC_PROT_EXEC:
                                return self.disassembly_viewer.JumpTo(ea)
                            elif start_addr <= ea < start_addr + len(data) and perm & UC_PROT_READ:
                                return self.mempages_viewer.JumpTo(ea)
                except ValueError:
                    pass
            return False

        self.registers_viewer.SetDblClickCallback(OnDblClickAction)


    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

        self.PopulateForm()


    def OnClose(self, form):
        self.disassembly_viewer.UnregisterAction()
        self.mempages_viewer.UnregisterAction()

        del self.disassembly_viewer
        del self.registers_viewer
        del self.mempages_viewer

        for sub_chooser in self.subchooser_list:
            if sub_chooser:
                sub_chooser.Close()

        del self.subchooser_list
        del self.state_manager
        del self.state_list



    def LoadESM(self, state_manager: EmuStateManager):
        """
        Load the EmuStateManager into the viewer.

        """
        self.state_manager = state_manager

        self.state_list = self.state_manager.get_state_list()

        self.disassembly_viewer.LoadListFromESM(self.state_list)

        self.current_state_idx = 0
        if self.state_list:
            self.SwitchStateDisplay(self.state_list[self.current_state_idx][0])
        else:
            idaapi.warning("No states loaded from EmuStateManager.")


    def PopulateForm(self):
        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal) # type: ignore
        main_splitter.setChildrenCollapsible(True)


        main_splitter.addWidget(self.disassembly_viewer.viewer_widget)


        right_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical) # type: ignore
        right_splitter.setChildrenCollapsible(True)

        right_splitter.addWidget(self.registers_viewer.viewer_widget)
        right_splitter.addWidget(self.mempages_viewer.viewer_widget)

        main_splitter.addWidget(right_splitter)

        main_layout = QtWidgets.QVBoxLayout(self.parent)
        main_layout.addWidget(main_splitter)
        main_layout.setContentsMargins(0, 0, 0, 0)


    def SwitchNextStateAction(self):
        assert self.state_list is not None, "No state_list loaded"
        if self.current_state_idx < len(self.state_list) - 1:
            self.current_state_idx += 1
            self.SwitchStateDisplay(self.state_list[self.current_state_idx][0])


    def SwitchPrevStateAction(self):
        assert self.state_list is not None, "No state_list loaded"
        if self.current_state_idx > 0:
            self.current_state_idx -= 1
            self.SwitchStateDisplay(self.state_list[self.current_state_idx][0])


    def SwitchCursorStateAction(self):
        assert self.state_manager is not None, "No state_manager loaded"
        assert self.state_list is not None, "No state_list loaded"

        address = self.disassembly_viewer.GetCursorAddress()
        if address:
            address_str = f"0x{address:X}"
            target_state_id = next((state_id for state_id, state in self.state_list if address_str in state_id), None)
            if target_state_id:
                self.SwitchState(target_state_id)


    def SwitchInputStateAction(self):
        assert self.state_manager is not None, "No state_manager loaded"
        assert self.state_list is not None, "No state_list loaded"

        input_str = ida_kernwin.ask_str(self.current_state_id if self.current_state_id else "", 0, "Input state ID:")
        if input_str:
            self.SwitchState(input_str)


    def ChooseStatesAction(self):

        class StateChooser(ida_kernwin.Choose):
            def __init__(self, title, state_list: StateList, switch_state_func):
                ida_kernwin.Choose.__init__(
                    self,
                    title,

                    [
                        ["Idx", 10 | ida_kernwin.Choose.CHCOL_DEC],
                        ["State ID", 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ["Instruction", 10 | ida_kernwin.Choose.CHCOL_HEX]
                     ])
                self.is_available = True

                self.state_list = state_list
                self.switch_state_display_func = switch_state_func


            def OnInit(self):
                self.items = [[str(i),
                        state_id,
                        InstrctionParser().parse_instruction_to_str(state.instruction)]
                        for i, (state_id, state) in enumerate(self.state_list)]
                return True

            def OnClose(self):
                self.is_available = False

            def OnGetSize(self):
                return len(self.items)

            def OnGetLine(self, n):
                return self.items[n]

            def OnDeleteLine(self, n):
                pass

            def OnSelectLine(self, n):
                ida_kernwin.msg(f"Switch to state {self.items[n][1]}\n")
                self.switch_state_display_func(self.items[n][1])
                return ida_kernwin.Choose.NOTHING_CHANGED

            def OnRefresh(self, n):
                self.OnInit()
                return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)


        if self.state_list is None:
            tte_log_dbg("No state_list loaded")
            return

        states_chooser = StateChooser("State Chooser", self.state_list, self.SwitchState)
        states_chooser.Show()
        self.subchooser_list.append(states_chooser)


    def ChooseMemoryPagesAction(self, parent_title: str,  display_memory_range_func):

        class MemPageChooser(ida_kernwin.Choose):
            def __init__(self, title, get_current_full_state_func, display_memory_range_func):
                ida_kernwin.Choose.__init__(
                    self,
                    title,
                    [
                        ["address", 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ["R", 3 | ida_kernwin.Choose.CHCOL_DEC],
                        ["W", 3 | ida_kernwin.Choose.CHCOL_DEC],
                        ["X", 3 | ida_kernwin.Choose.CHCOL_DEC],
                        ["size", 10 | ida_kernwin.Choose.CHCOL_HEX],
                    ])
                self.is_available = True

                self.get_current_full_state_func = get_current_full_state_func
                self.display_memory_range_func = display_memory_range_func
                self.bitness = get_bitness()
                if self.bitness:
                    self.hex_len = self.bitness // 4
                else:
                    tte_log_err("Failed to get bitness")
                self.items = [] # Initialize items list

            def OnInit(self):
                full_state = self.get_current_full_state_func()
                if full_state:
                    memory_pages_list: List[Tuple[int, int, bytearray]] = [(addr, perm, data) for addr, (perm, data) in full_state.memory_pages.items()]
                    self.items = [[
                                    f"0x{addr:0{self.hex_len}X}",
                                    "R" if perm & UC_PROT_READ else " ",
                                    "W" if perm & UC_PROT_WRITE else " ",
                                    "X" if perm & UC_PROT_EXEC else " ",
                                    f"0x{len(data):X}"]
                                    for addr, perm, data in memory_pages_list]
                else:
                    self.items = [] # No state, no items
                return True

            def OnClose(self):
                self.is_available = False

            def OnGetSize(self):
                return len(self.items)

            def OnGetLine(self, n):
                return self.items[n]

            def OnDeleteLine(self, n):
                pass

            def OnSelectLine(self, n):
                addr = int(self.items[n][0], 16)
                size = int(self.items[n][4], 16)
                self.display_memory_range_func(addr, addr + size)

                return ida_kernwin.Choose.NOTHING_CHANGED

            def OnRefresh(self, n):
                self.OnInit()
                return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)

        if self.current_full_state is None:
            tte_log_dbg("No current full state")
            return

        memory_pages_chooser = MemPageChooser(f"Memory Chooser for {parent_title}", lambda : self.current_full_state, display_memory_range_func)
        memory_pages_chooser.Show()
        self.subchooser_list.append(memory_pages_chooser)


    def ShowDiffsAciton(self, parent_title: str, jumpto_address_func):

        class DiffsChooser(ida_kernwin.Choose):
            def __init__(self, title, get_current_diff_func, jumpto_address_func):
                ida_kernwin.Choose.__init__(
                    self,
                    title,

                    [
                        ["Diff Type", 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ['Diff Location', 10 | ida_kernwin.Choose.CHCOL_HEX],
                        ["Diff Value", 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                     ])
                self.is_available = True

                self.get_current_diff_func = get_current_diff_func
                self.jumpto_address_func = jumpto_address_func

                self.bitness = get_bitness()
                if self.bitness:
                    self.hex_len = self.bitness // 4
                else:
                    tte_log_err("Failed to get bitness")
                self.items = [] # Initialize items list

            def OnInit(self):
                (prev_state_id, curr_state_id), regs_diff, mem_diff, page_diff = self.get_current_diff_func() # Optional[Tuple[Optional[RegistersPatchDict], Optional[SortedDict], Optional[SortedDict]]]
                tte_log_info(f"Showing differents from {prev_state_id} to {curr_state_id}")
                self.items = []
                if regs_diff:
                    for reg_name, (prev_reg_val, reg_val) in regs_diff.items():
                        self.items.append(["reg diffs",
                            reg_name,
                            f"0x{prev_reg_val:0{self.hex_len}X} -> 0x{reg_val:0{self.hex_len}X}"])
                if mem_diff:
                    for addr, (prev_data, data) in mem_diff.items():
                        # mem_diff stores single byte changes
                        self.items.append(["mem diffs",
                            f"0x{addr:0{self.hex_len}X}",
                            f"0x{prev_data:02X} -> 0x{data:02X}"]) # prev_data and data are int for single bytes
                if page_diff:
                    for addr, (mode, (perm, data)) in page_diff.items(): # data here is bytearray for the whole page
                        if mode == 2: # Added page
                            self.items.append(["add page", f"0x{addr:0{self.hex_len}X}", f"perm: 0x{perm:X}, size: 0x{len(data):X}"])
                        elif mode == 1: # Removed page
                            self.items.append(["del page", f"0x{addr:0{self.hex_len}X}", f"perm: 0x{perm:X}, size: 0x{len(data):X}"])
                return True

            def OnClose(self):
                self.is_available = False

            def OnGetSize(self):
                return len(self.items)

            def OnDeleteLine(self, n):
                pass

            def OnGetLine(self, n):
                return self.items[n]

            def OnSelectLine(self, n):
                locate = self.items[n][1]
                if locate.startswith("0x"):
                    try:
                        addr = int(locate, 16)
                        self.jumpto_address_func(addr)
                    except ValueError:
                        pass # Not a valid address
                return ida_kernwin.Choose.NOTHING_CHANGED

            def OnRefresh(self, n):
                self.OnInit()
                return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)

        if self.state_list is None:
            tte_log_dbg("No state_list loaded")
            return

        diff_chooser = DiffsChooser(
            f"Diffs Chooser for {parent_title}",
            lambda : self.current_diffs, jumpto_address_func)
        diff_chooser.Show()
        self.subchooser_list.append(diff_chooser)


    def ToggleFollowCurrentInstructionAction(self):
        self.follow_current_instruction = not self.follow_current_instruction
        idaapi.msg(f"Follow current instruction: {self.follow_current_instruction}\n")
        # If toggled to True, jump to current instruction
        if self.follow_current_instruction and self.current_full_state:
            self.disassembly_viewer.JumpTo(self.current_full_state.instruction_address)


    def RefreshSubviewers(self):
        self.subchooser_list = [subchooser for subchooser in self.subchooser_list if hasattr(subchooser, "is_available") and subchooser.is_available] # type: ignore
        for chooser in self.subchooser_list:
            chooser.Refresh()


    def SwitchState(self, target_state_id: str):
        assert self.state_list is not None, "No state_list loaded"
        target_state_idx = next((i for i, (x, y) in enumerate(self.state_list) if x == target_state_id), -1)
        if target_state_idx >= 0:
            self.current_state_idx = target_state_idx
            self.SwitchStateDisplay(self.state_list[self.current_state_idx][0])
        self.SwitchStateDisplay(target_state_id)


    def SwitchStateDisplay(self, target_state_id: str):
        assert self.state_manager is not None, "No state_manager loaded"

        # Avoid unnecessary re-rendering if already on this state
        if target_state_id == self.current_state_id and self.current_full_state is not None:
            return

        target_state = self.state_manager.get_state(target_state_id)
        if target_state is None:
            idaapi.warning(f"State {target_state_id} not found in state_manager.")
            return

        target_full_state = target_state.generate_full_state(self.state_manager.states_dict)
        if target_full_state is None:
            idaapi.warning(f"Failed to generate full state for state {target_state_id}.")
            return

        # Catch up all different information between current and target state
        regs_diff: Optional[RegistersDiffsDict] = None
        mem_diff: Optional[SortedDict] = None # SortedDict[address, (prev_value, new_value)] (single byte)
        page_diff: Optional[SortedDict] = None # SortedDict[page_start_addr, (change_mode, (perm, data))]

        regs_patch: Optional[RegistersPatchDict] = None
        mem_patch: Optional[List[Tuple[int, bytes]]] = None # List of (address, value_bytes) for changed memory regions

        if self.current_full_state is not None:
            entry = self.state_manager.compare_states(self.current_full_state, target_full_state)
            if entry:
                regs_diff = entry[0]
                mem_diff_raw = entry[1] # This is SortedDict[address, (prev_int, new_int)]
                page_diff = entry[2]

                regs_patch = {reg_name : reg_value for reg_name, (_, reg_value) in regs_diff.items()}

                # Convert raw mem_diff (single int bytes) to mem_patch (addr, bytes)
                if mem_diff_raw:
                    mem_patch = [(addr, new_val.to_bytes(1, byteorder='big' if get_is_be() else 'little')) for addr, (_, new_val) in mem_diff_raw.items()]
                    # Reconstruct mem_diff for DiffsChooser as SortedDict[addr, (prev_int, new_int)]
                    mem_diff = mem_diff_raw
                else:
                    mem_patch = None
                    mem_diff = None


        self.current_diffs = ((self.current_state_id, target_state_id), regs_diff, mem_diff, page_diff)


        # Update Disassembly Viewer
        self.disassembly_viewer.LoadState(target_state, target_full_state.instruction_address, target_full_state.memory_pages)
        self.disassembly_viewer.ApplyStatePatchesInViewer(mem_patch, page_diff)
        if self.follow_current_instruction or self.current_state_id is None: # Only jump if it's the first load or follow is enabled
            self.disassembly_viewer.JumpTo(target_full_state.instruction_address)

        # Update Registers Viewer
        self.registers_viewer.SetRegisters(target_full_state.state_id, target_full_state.registers_map)
        self.registers_viewer.SetRegsPatch(target_full_state.state_id, regs_patch)
        self.registers_viewer.DisplayRegisters()

        # Update Memory Viewer
        self.mempages_viewer.LoadState(target_state_id, target_full_state.memory_pages)
        # If no previous range, default to displaying around the instruction address.
        if self.mempages_viewer.current_range_display_start == -1:
            default_mem_start = (target_full_state.instruction_address // PAGE_SIZE) * PAGE_SIZE
            self.mempages_viewer.DisplayMemoryRange(default_mem_start, default_mem_start + PAGE_SIZE)

        self.mempages_viewer.ApplyStatePatchesInViewer(mem_patch, page_diff)


        self.current_full_state = target_full_state
        self.current_state_id = target_state_id

        self.RefreshSubviewers() # Refresh Choose dialogs if open



def StartTimeTravelEmulator(settings: EmuSettings) -> None:
    """
    Start the Time Travel Emulator with the given settings and display the Time Travel Emu Viewer.
    :param setting: EmuSettings object containing the emulator settings.
    """
    TTE_Logger().start(settings.log_level, settings.log_file_path)

    emu_executor = EmuExecutor(settings)
    emu_executor.init()

    emu_statesmanager = EmuStateManager()
    emu_tracer = EmuTracer(emu_executor, emu_statesmanager)
    emu_tracer.init_hook()

    continues = emu_executor.execute_preprocessing_code(settings.preprocessing_code, emu_executor)
    if continues != 1:
        return

    emu_executor.run()
    emu_executor.destroy()

    time_travel_emulator_viewer = TimeTravelEmuViewer()
    time_travel_emulator_viewer.Init()
    time_travel_emulator_viewer.LoadESM(emu_statesmanager)
    time_travel_emulator_viewer.Show(time_travel_emulator_viewer.title)

    TTE_Logger().stop()




TTE_RUN_ACTION_NAME =  "TimeTravelEmulator:Run"

class action_handler(ida_kernwin.action_handler_t):
    def __init__(self, handler):
        super().__init__()
        self.handler = handler

    def activate(self, ctx):
        self.handler()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_DISASM else ida_kernwin.AST_DISABLE_FOR_WIDGET

class Hooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup, TTE_RUN_ACTION_NAME, None)
tte_run_menu_hook = None


class TimeTravelEmulator(idaapi.plugin_t):
    flags = idaapi.PLUGIN_DRAW
    comment = "Time Travel Emulator"
    wanted_name = "Time Travel Emulator"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self._data = None

    def term(self):
        pass

    def init(self):
        idaapi.msg(f"[TimeTravelEmulator] Init (version {VERSION})\n")
        arch = get_arch()
        if arch != "":
            # Supported architecture found.
            idaapi.msg(f"[TimeTravelEmulator] CPU architecture: {arch}\n")

            # Register actions
            ida_kernwin.register_action(ida_kernwin.action_desc_t(
                    TTE_RUN_ACTION_NAME,
                    "Run Time Travel Emulator",
                    action_handler(lambda: self.run(None)),
                    PLUGIN_HOTKEY))
            global tte_run_menu_hook
            tte_run_menu_hook = Hooks()
            tte_run_menu_hook.hook()


            idaapi.msg("[TimeTravelEmulator] Ready.\n")
            return idaapi.PLUGIN_KEEP
        else:
            # No supported architecture found.
            idaapi.msg("[TimeTravelEmulator] No supported architecture found.\n")
            idaapi.msg("[TimeTravelEmulator] Disabled.\n")
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        if ida_kernwin.find_widget(TimeTravelEmuViewer.title):
            idaapi.msg("[TimeTravelEmulator] Already running.\n")
            return

        start, end = self.get_ea_range()
        F = EmuSettingsForm(start, end)
        IsEmulate = F.Execute()
        if IsEmulate:
            setting = F.GetSetting()
            if setting is not None:
                StartTimeTravelEmulator(setting)
        F.Free()

    def get_ea_range(self):
        selection, ea_addr, ea_addr_end = idaapi.read_range_selection(None)

        if selection:
            return ea_addr, ea_addr_end
        else:
            ea = idaapi.get_screen_ea()
            if ida_dbg.is_debugger_on():
                start = ida_dbg.get_reg_val(IP_REG_NAME_MAP[get_arch()])
                end =  idc.get_fchunk_attr(ea,8)
            else:
                start = idc.get_func_attr(ea,0)
                end = idc.get_fchunk_attr(ea,8)
            return start, end


def PLUGIN_ENTRY():
    return TimeTravelEmulator()