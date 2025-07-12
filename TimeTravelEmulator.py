import idaapi
import ida_ida
import ida_kernwin
import logging
import ida_nalt
import idc
import ida_bytes
import ida_segment

from abc import ABC
from collections import defaultdict
from typing import Dict, Iterator, List, Literal, Optional, Tuple, Union
from copy import deepcopy
from attr import dataclass



import bsdiff4
from sortedcontainers import SortedDict
from unicorn import *
from unicorn.x86_const import *
from capstone import *


state_montior = None


VERSION = '0.0.1'

PLUGIN_NAME = 'TimeTravelEmulator'
PLUGIN_HOTKEY = 'Shift+T'

# Define page size and page mask, usually 4 kb
PAGE_SIZE = 0x1000
PAGE_MASK = ~(PAGE_SIZE - 1)

# Define default page permission
DEFAULT_PAGE_PERMISSION = UC_PROT_WRITE | UC_PROT_READ







from os import getcwd
LOG_FLIE_PATH = getcwd() + "/tte.log" #TODO: Remove it


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
        "rax": UC_X86_REG_RAX,
        "rbx": UC_X86_REG_RBX,
        "rcx": UC_X86_REG_RCX,
        "rdx": UC_X86_REG_RDX,
        "rsi": UC_X86_REG_RSI,
        "rdi": UC_X86_REG_RDI,
        "rbp": UC_X86_REG_RBP,
        "rsp": UC_X86_REG_RSP,
        "r8": UC_X86_REG_R8,
        "r9": UC_X86_REG_R9,
        "r10": UC_X86_REG_R10,
        "r11": UC_X86_REG_R11,
        "r12": UC_X86_REG_R12,
        "r13": UC_X86_REG_R13,
        "r14": UC_X86_REG_R14,
        "r15": UC_X86_REG_R15,
        # Instruction Pointer
        "rip": UC_X86_REG_RIP,
        # Flags Register
        "rflags": UC_X86_REG_EFLAGS, # In 64-bit, EFLAGS is extended to RFLAGS, but the constant remains EFLAGS
        # Segment Registers
        "cs": UC_X86_REG_CS,
        "ss": UC_X86_REG_SS,
        "ds": UC_X86_REG_DS,
        "es": UC_X86_REG_ES,
        "fs": UC_X86_REG_FS,
        "gs": UC_X86_REG_GS,
    },
    "x86": {
        # General Purpose Registers (GPRs)
        "eax": UC_X86_REG_EAX,
        "ebx": UC_X86_REG_EBX,
        "ecx": UC_X86_REG_ECX,
        "edx": UC_X86_REG_EDX,
        "esi": UC_X86_REG_ESI,
        "edi": UC_X86_REG_EDI,
        "ebp": UC_X86_REG_EBP,
        "esp": UC_X86_REG_ESP,
        # Instruction Pointer
        "eip": UC_X86_REG_EIP,
        # Flags Register
        "eflags": UC_X86_REG_EFLAGS,
        # Segment Registers
        "cs": UC_X86_REG_CS,
        "ss": UC_X86_REG_SS,
        "ds": UC_X86_REG_DS,
        "es": UC_X86_REG_ES,
        "fs": UC_X86_REG_FS,
        "gs": UC_X86_REG_GS,
    }
}


IDA_PERM_TO_UC_PERM_MAP = {
    ida_segment.SEGPERM_EXEC : UC_PROT_EXEC,
    ida_segment.SEGPERM_WRITE : UC_PROT_WRITE,
    ida_segment.SEGPERM_READ : UC_PROT_READ
}


def get_bitness() -> Union[None, Literal[64], Literal[32]]:
    # compatibility IDA 9.0 and above
    if idaapi.IDA_SDK_VERSION >= 900:
        if ida_ida.inf_is_64bit():
            return 64
        elif ida_ida.inf_is_32bit_exactly():
            return 32
    else:
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            return 64
        elif info.is_32bit():
            return 32

def get_is_be() -> bool:
        info = idaapi.get_inf_structure()
        return ida_ida.inf_is_be()

def get_arch() -> str:
    structure_info = idaapi.get_inf_structure()
    proc_name = structure_info.procname
    proc_bitness = get_bitness()

    if proc_bitness == None:
        return ""
    if (proc_name, proc_bitness) not in IDA_PROC_TO_ARCH_MAP:
        return ""
    return IDA_PROC_TO_ARCH_MAP[(proc_name, proc_bitness)]


def get_slice_segment(page_size: int) -> "defaultdict[int, List[Tuple[int, int]]]":
    """
    Slice the segment into pages of the given size.

    :param segment_dict: A list of segment_t objects.
    :param page_size: The size of each page.
    :return: A dictionary, where the key is the start address of the page,
     and the value is a list of tuples (start_ea, end_ea) of the segments in the page.
    """
    result = defaultdict(list)
    segment_list = [ida_segment.getnseg(n) for n in range(ida_segment.get_segm_qty())]
    for seg in segment_list:
        start = seg.start_ea
        end = seg.end_ea

        current_addr = start
        while current_addr < end:
            page_start = (current_addr // page_size) * page_size
            page_end = page_start + page_size

            seg_in_page_start = max(current_addr, page_start)
            seg_in_page_end = min(end, page_end)

            if seg_in_page_start < seg_in_page_end:
                result[page_start].append((seg_in_page_start, seg_in_page_end))
            current_addr = page_end

    return result

def get_segment_prem(addr: int) -> int:
    seg = ida_segment.getseg(addr)
    if seg is not None:
        ida_perm = seg.perm
        uc_perm = 0
        for ida_bit, uc_bit in IDA_PERM_TO_UC_PERM_MAP.items():
            if ida_perm & ida_bit:
                uc_perm |= uc_bit
        return uc_perm
    return DEFAULT_PAGE_PERMISSION


def is_address_range_loaded(start_ea, end_ea) -> bool:
    """
    Check if the given address range is loaded into the database.
    """
    tte_log_dbg(f"Checking if address range {hex(start_ea)} - {hex(end_ea)} is loaded...")
    if start_ea < ida_ida.inf_get_min_ea() or end_ea > ida_ida.inf_get_max_ea():
        return False
    return ida_bytes.next_that(start_ea - 1, end_ea + 1, lambda flags: ida_bytes.has_value(flags)) != idaapi.BADADDR



def catch_dict_diff(
        base_dict: Dict[str, int],
        target_dict: Dict[str, int]
) -> Dict[str, int]:
    """
    Compare the two dictionaries and return different key-value pairs of target_dict relative to base_dict.
    Prerequisite: Two dictionaries have exactly the same set of keys.
    The return value contains only key-value pairs whose values have changed.
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


def catch_bytes_diff(
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
            patches[addr] = (permossion, bsdiff4.diff(base_bytes, target_bytes))
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
            patched_data = bsdiff4.patch(original_data, patch)
            updated_dict[addr] = (permossion, patched_data)
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

    def start(self, log_file=None, log_level=logging.INFO):
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
    start = 0x140001450#start#
    end = -1#0x14000201C#end#
    # emulate_step_limit = 10
    is_load_registers = False
    is_emulate_external_calls = False
    is_log = True
    is_map_mem_permissions = True
    time_out = 0  #TODO: add it in emusetting form
    count = 300  #TODO: add it in emusetting form
    log_level = logging.DEBUG #TODO: add it in emusetting form


class EmuSettingsForm(idaapi.Form):

    def __init__(self, start_ea, end_ea) -> None:

        self.i_start_address: Optional[ida_kernwin.Form.NumericInput] =  None
        self.i_end_address: Optional[ida_kernwin.Form.NumericInput] = None
        self.c_configs_group: Optional[ida_kernwin.Form.ChkGroupControl] = None
        self.i_emulate_step_limit: Optional[ida_kernwin.Form.NumericInput] =  None
        self.i_load_state_file_path: Optional[ida_kernwin.Form.FileInput] = None

        super().__init__(
            r'''STARTITEM {id:i_start_address}
BUTTON YES* Emulate
EmuTrace: Emulator Settings

            {FormChangeCb}
            Emulation Execution Range:
            <Start Address  :{i_start_address}>
            <End Address    :{i_end_address}>
            <Select Function range    :{b_select_function}>

            Configs:
            <Emlate step limit: {i_emulate_step_limit}>

            <load registers:{r_load_register}>
            <emulate external calls:{r_emulate_external_calls}>
            <log:{r_log}>{c_configs_group}>

            State:
            <Load state: {i_load_state_file_path}>

            Advanced Configs:
            ''',
            {
                'FormChangeCb': self.FormChangeCb(self.__on_form_change),
                'i_start_address': self.NumericInput(self.FT_ADDR, value=start_ea,  swidth = 30),
                'i_end_address': self.NumericInput(self.FT_ADDR, value=end_ea, swidth = 30),
                'b_select_function': self.ButtonInput(self.__open_select_function_dialog),

                'i_emulate_step_limit': self.NumericInput(self.FT_DEC, value=100, swidth = 30),
                'c_configs_group': self.ChkGroupControl(("r_load_register", "r_emulate_external_calls", "r_log")),

                'i_load_state_file_path': self.FileInput(open = True,swidth = 30),
            }
         )
        self.Compile()
        self.r_log.checked=True # type: ignore #TODO: Remove it

    def __on_form_change(self, fid: int):
        return 1

    def __open_select_function_dialog(self, code = 0):
        target_func =  ida_kernwin.choose_func("Select target function range",1)
        if not target_func:
            return

        self.__set_emu_range(target_func.start_ea, target_func.end_ea)

    def __set_emu_range(self, start: int = -1, end: int = -1):
        # set range by parameters
        if start != -1 and end != -1:
            start_t = start
            end_t = end

        # set range by edit input
        else:
            try:
                if self.i_start_address is None or self.i_end_address is None:
                    ida_kernwin.warning("Address input controls are not initialized.")
                    return
                start_t =  self.i_start_address.value
                end_t =  self.i_end_address.value
            except ValueError:
                ida_kernwin.warning("Invalid Input: Please enter valid hexadecimal addresses.")
                return

        # check range
        if start_t > end_t:
            ida_kernwin.warning("Invalid Range: Start address must be less than or equal to end address.")
        elif start_t < ida_ida.inf_get_min_ea() or end_t > ida_ida.inf_get_max_ea():
            ida_kernwin.warning("Invalid Range: Address out of range.")

        # set range
        self.sim_range_start = start_t
        self.sim_range_end = end_t

        if start != -1 and end != -1:
            self.SetControlValue(self.i_start_address, start_t)
            self.SetControlValue(self.i_end_address, end_t)


    def GetSetting(self):
        self.__set_emu_range()
        if self.i_emulate_step_limit is None or self.c_configs_group is None:
            ida_kernwin.warning("Form controls are not initialized.")
            return None

        config_value = self.i_emulate_step_limit.value
        is_load_registers = bool(config_value & 0b1)
        is_emulate_external_calls = bool(config_value & 0b10)
        is_log = bool(config_value & 0b100)
        return EmuSettings()#self.sim_range_start,
                        #    self.sim_range_end,
                        #    self.i_emulate_step_limit.value,
                        #    self.c_configs_group.value)








DEFAULT_STACK_POINT_VALUE = 0x70000000
DEFAULT_BASE_POINT_VALUE = DEFAULT_STACK_POINT_VALUE


class EmuExecuter():
    """
    A simulation executor class is used to manage the operation of the entire program, including initialization, loading, running, saving, etc.
    """



    def __init__(self, settings: EmuSettings) -> None:
        self._is_initialized = False

        self.arch = get_arch()
        self.unicorn_arch, self.unicorn_mode = UNICORN_ARCH_MAP[self.arch]
        self.insn_pointer = ARCH_TO_INSN_POINTER_MAP[self.arch]
        self.settings = settings
        tte_log_info("Create EmuExecuter: arch-{}, mode-{}".format(self.unicorn_arch, self.unicorn_mode))

        self.unloaded_binary_page = {}

        self.emu_map_mem_callback = []
        self.emu_run_end_callback = []

    def init(self) -> None:
        """
        Initialize Unicorn emulation, the method must be called before calling other methods.
        """
        if self._is_initialized:
            tte_log_info("EmuExecuter already initialized.")
            return
        if(self.settings.is_log):
            TTE_Logger().start(LOG_FLIE_PATH, self.settings.log_level) #TODO: allow user to select log file path and log level and remove it

        self.unloaded_binary_page = get_slice_segment(PAGE_SIZE) # dict(page_start: [(seg_start, seg_end),...],...)

        # Unicorn instance creation
        self.mu = unicorn.Uc(self.unicorn_arch, self.unicorn_mode)

        # Memory mapping and data loading
        self._map_and_load_binary(self.settings.start, self.settings.end)

        # Register initialization
        self._set_regs_init_value()

        # Hooks setting
        self._hook_mem_unmapped()

        self._is_initialized = True

    def _is_memory_mapped(self, address) -> bool:
        return any(map_start <= address < map_end for map_start, map_end, _ in self.mu.mem_regions())


    def _map_memory(self, map_start, map_size) -> None:
        """
        Map memory pages for the given range.

        :param map_start: Start address of the mapping.Must be page aligned.
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

        seg_data = ida_bytes.get_bytes(load_seg_start, load_seg_end - load_seg_start)
        if seg_data:
            try:
                self.mu.mem_write(load_seg_start, seg_data)
            except UcError as e:
                tte_log_info(f"Writing segment failed 0x{load_seg_start:X}~0x{load_seg_end:X}: {e}")
        else:
            tte_log_warn(f"Warning: Section 0x{load_seg_start:X}~0x{load_seg_end:X} No data")


    def _map_and_load_binary(self, start_ea, end_ea) -> None:
        tte_log_dbg(f"Start map and load binary: 0x{start_ea:X}~0x{end_ea:X}")
        map_start = start_ea & PAGE_MASK
        map_size = (end_ea - map_start + PAGE_SIZE - 1) & PAGE_MASK

        self._map_memory(map_start, map_size)
        if not is_address_range_loaded(start_ea, end_ea):
            return

        segments_to_load: List[List[Tuple[int, int]]] = []
        for page_start_addr in self.unloaded_binary_page.copy().keys():
            if page_start_addr >= map_start and page_start_addr < map_start + map_size:
                segments_to_load.append(self.unloaded_binary_page.pop(page_start_addr))

        for load_range_list in segments_to_load:
            for start_ea, end_ea in load_range_list:
                self._load_binary(start_ea, end_ea )
                tte_log_info(f"Load binary segments {ida_segment.get_segm_name(idaapi.getseg(start_ea))}: 0x{start_ea:X}~0x{end_ea:X}")


    def _hook_mem_unmapped(self) -> None:
        def cb_map_mem_inmapped(uc, access, address, size, value, user_data) -> bool:
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
                tte_log_info(f"Hook callback: Mapping memory failed: {e}")
                return False



        self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, cb_map_mem_inmapped)


    def _set_regs_init_value(self) -> None:
        if not self.settings.is_load_registers and self.unicorn_arch == UC_ARCH_X86: # Set default stack value in x86 mode
            offset = 0
            while(self._is_memory_mapped(DEFAULT_STACK_POINT_VALUE + offset)):
                offset += 0x1000000
            if self.unicorn_mode == UC_MODE_64:
                stack_point, base_point  = UNICORN_REGISTERS_MAP[self.arch]['rsp'], UNICORN_REGISTERS_MAP[self.arch]['rsp']
            elif self.unicorn_mode == UC_MODE_32:
                stack_point, base_point  = UNICORN_REGISTERS_MAP[self.arch]['esp'], UNICORN_REGISTERS_MAP[self.arch]['ebp']

            self.mu.reg_write(stack_point, DEFAULT_STACK_POINT_VALUE + offset)
            self.mu.reg_write(base_point, DEFAULT_BASE_POINT_VALUE + offset)
            tte_log_info(f"Init regs: Sets registers default stack regs value: sp = {DEFAULT_STACK_POINT_VALUE + offset:X}, bp = {DEFAULT_BASE_POINT_VALUE + offset:X}")


    def add_mu_hook(self, htype: int, callback, user_data = None, begin: int = 1, end: int = 0) -> int:
        return self.mu.hook_add(htype, callback, user_data, begin, end)

    CUSTOM_HOOK_MEM_MAP = 0
    CUSTOM_HOOK_EXECUTE_END = 1
    def add_custom_hook(self, htype: int, callback):
        if htype == EmuExecuter.CUSTOM_HOOK_MEM_MAP:
            self.emu_map_mem_callback.append(callback)
        elif htype == EmuExecuter.CUSTOM_HOOK_EXECUTE_END:
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




        tte_log_info(f"Emulation ended: 0x{self.mu.reg_read(self.insn_pointer):X}")
        tte_log_dbg("Emulation: Start calling end callback functions.")
        for callback in self.emu_run_end_callback:
            callback(self.mu)

        tte_log_info("Emulation completed successfully.")

    def destroy(self) -> None:
        """
        End the emulate
        """
        if not self._is_initialized:
            tte_log_info("EmuExecuter not initialized.")
            return

        self.mu.emu_stop()
        self.emu_run_end_callback.clear()
        self.unloaded_binary_page.clear()

        TTE_Logger().stop()
        self._is_initialized = False







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

    def __init__(self, state_id: str, instruction_address: int = -1, execution_count: int = -1) -> None:
        self.state_id = state_id
        self.type = None

        self.instruction_address = instruction_address
        self.execution_count = execution_count

    def generate_full_state(self, states_dict: Dict[str, 'EmuState']) -> Optional['FullEmuState']:
        pass


class FullEmuState(EmuState):
    def __init__(self, state_id: str, instruction_address: int = -1, execution_count: int = -1) -> None:
        super().__init__(state_id, instruction_address, execution_count)
        self.type = EmuState.STATE_TYPE_FULL

        self.registers_map: Dict[str, int] = {} # {reg_name: reg_value}
        self.memory_pages: Dict[int, Tuple[int, bytearray]] = {} # {page_start: (page_permissions, page_data)}


    def set_data(self, registers_map: Dict[str, int], memory_pages: Dict[int, Tuple[int, bytearray]]) -> None:
        """
        Set the full state of the emulator.
        :param registers: Dictionary of register values.
        :param memory_pages: Dictionary of memory pages.
        """
        self.registers_map = registers_map
        self.memory_pages = memory_pages

    def generate_full_state(self, states_dict: Dict[str, EmuState]) -> Optional['FullEmuState']:
        return deepcopy(self)


class HeavyPatchEmuState(EmuState):
    def __init__(self, state_id: str, instruction_address: int = -1, execution_count: int = -1) -> None:
        super().__init__(state_id, instruction_address, execution_count)
        self.type = EmuState.STATE_TYPE_HEAVY_PATCH

        self.base_full_state_id: Optional[str] = None

        self.reg_patches: Dict[str, int] = {} # {reg_name: patch_value}

        # Memory patch stores binary differential data generated by bsdiff4
        self.mem_bsdiff_patches: Dict[int, Tuple[int, bytes]] = {} # {page_start: (page_permissions, bsdiff_patch_bytes)}
        self.new_pages: Dict[int, Tuple[int, bytearray]] = {} # {page_start: (page_permissions, page_data)}

    def set_data(self, base_full_state_id: str, reg_patches: Dict[str, int], mem_bsdiff_patches: Dict[int, Tuple[int, bytes]], new_pages: Dict[int, Tuple[int, bytearray]]):
        """
        Sets the patch status of the emulator.

        :param reg_patches: Dictionary of register patches.
        :param mem_bsdiff_patches: Dictionary of memory patches, need to be applied by bsdiff4.
        """
        self.base_full_state_id = base_full_state_id

        self.reg_patches = reg_patches
        self.mem_bsdiff_patches = mem_bsdiff_patches
        self.new_pages = new_pages

    def generate_full_state(self, states_dict: Dict[str, EmuState]) -> Optional[FullEmuState]:
        tte_log_dbg(f"Generate full state for heavy path state {self.state_id}")
        target_state = FullEmuState(self.state_id, self.instruction_address, self.execution_count)

        assert self.base_full_state_id is not None, "Generate full State: Cannot apply memory patch: base state id not set."
        assert self.base_full_state_id in states_dict, f"Generate full State: Cannot apply memory patch: base state {self.base_full_state_id} not found."
        base_full_state: Optional[EmuState] = states_dict[self.base_full_state_id].generate_full_state(states_dict)

        assert base_full_state is not None, f"Generate full State: Cannot get full state for {self.base_full_state_id}: base state not found."
        assert isinstance(base_full_state, FullEmuState), f"Generate full State: Cannot apply memory patch: base state is not a full state."

        target_registers_map = apply_dict_patch(base_full_state.registers_map, self.reg_patches)
        target_memory_pages = apply_bytes_patch(base_full_state.memory_pages, self.mem_bsdiff_patches, self.new_pages)
        target_state.set_data(target_registers_map, target_memory_pages)

        return deepcopy(target_state)


class LightPatchEmuState(EmuState):
    def __init__(self, state_id: str, instruction_address: int = -1, execution_count: int = -1) -> None:
        super().__init__(state_id, instruction_address, execution_count)
        self.type = EmuState.STATE_TYPE_LIGHT_PATCH

        self.base_full_state_id: Optional[str] = None
        self.prev_state_id: Optional[str] = None

        self.reg_patches: Dict[str, int] = {} # {reg_name: patch_value}
        self.mem_patches: List[Tuple[int, int, bytes]] = [] # List[[address, size, value]...]


    def set_data(self, base_full_state_id: str, prev_state_id: str, reg_patches: Dict[str, int], mem_patches: List[Tuple[int, int, bytes]]):
        """
        Set the patch state of the emulator.
        :param reg_patches: Dictionary of register patches.
        :param mem_patches: Dictionary of memory patches.
        """
        self.base_full_state_id = base_full_state_id
        self.prev_state_id = prev_state_id

        self.reg_patches = reg_patches
        self.mem_patches = mem_patches
        tte_log_dbg(message=f"state:{self.state_id}, mem_patches {self.mem_patches}")


    def generate_full_state(self, states_dict: Dict[str, EmuState]) -> Optional[FullEmuState]:
        tte_log_dbg(f"Generate full state for light path state {self.state_id}")
        target_state = FullEmuState(self.state_id, self.instruction_address, self.execution_count)
        target_memory_patch = self.mem_patches.copy()
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
                target_memory_patch.extend(prev_state.mem_patches)
                prev_state_id = prev_state.prev_state_id

        # Apply register patches
        target_state.registers_map = apply_dict_patch(base_full_state.registers_map, self.reg_patches)

        # Apply memory patches
        assert prev_full_state is not None, "Generate full State: Cannot apply memory patch: previous state not found."
        target_state.memory_pages = prev_full_state.memory_pages
        while target_memory_patch:
            addr, size, value = target_memory_patch.pop()

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
    MAX_HEAVY_PATCH_COUNT = 5
    MAX_CUMULATIVE_DIFF_THRESHOLD = 0x100 # Accumulated difference threshold, if it exceeds it, create a full snapshot
    STATE_ID_FORMAT = "$0x{address:X}#{count}"

    def __init__(self) -> None:
        self.arch = get_arch()

        self.states_dict: Dict[str, EmuState] = {} # dict: {state_id: EmuState}
        # self.storage_path = storage_path
        # os.makedirs(self.storage_path, exist_ok=True)

        self.instruction_execution_counts: Dict[int, int] = defaultdict(int) # {address: count}
        self.last_state_id: Optional[str] = None # Record the status id of the previous created
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


    def _read_memory_pages(self, uc, memory_regions: Iterator[Tuple[int, int, int]]) -> Dict[int, Tuple[int, bytearray]]:
        """
        Read paging memory from Unicorn instance.

        :param uc: The Unicorn instance.
        :param memory_regions: A list of memory regions to read.  Iterator(Tuple[start, end, permission])
        :return: A dictionary of memory pages, where the key is the start address of
         the page and the value is the page's permission and data.
        """
        memory_pages: Dict[int, Tuple[int, bytearray]] = {}
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
                           instruction_address:int,
                           current_registers_map: Dict[str, int],
                           current_memory_pages: Dict[int, Tuple[int, bytearray]]) -> None:
        new_state = FullEmuState(new_state_id,
                                 instruction_address,
                                 self.instruction_execution_counts[instruction_address])
        new_state.set_data(current_registers_map, current_memory_pages)

        self.states_dict[new_state_id] = new_state

        self.patch_chain_count = 0
        self.cumulative_diff_size = 0
        self.last_full_state_id = new_state_id
        self.last_state_id = new_state_id # Update the last status id
        tte_log_dbg(f"State Manager: Created FULL state: {new_state_id}")


    def _create_light_patch_state(self,
                                  new_state_id: str,
                                  instruction_address:int,
                                  current_registers_map: Dict[str, int],
                                  mem_patches: List[Tuple[int, int, bytes]]) -> None:
        assert self.last_full_state_id is not None, "No full base state available for patch creation."
        assert self.last_state_id is not None, "No previous state available for patch creation."

        base_full_state: Optional[FullEmuState] = self.get_state(self.last_full_state_id) # type: ignore
        assert base_full_state is not None, "No full base state available for patch creation."
        assert isinstance(base_full_state, FullEmuState), "Base state is not a full state."

        reg_patches = catch_dict_diff(base_full_state.registers_map, current_registers_map)

        new_state = LightPatchEmuState(new_state_id,
                                       instruction_address,
                                       self.instruction_execution_counts[instruction_address])
        new_state.set_data(self.last_full_state_id, self.last_state_id, reg_patches, mem_patches)

        self.states_dict[new_state_id] = new_state

        self.patch_chain_count += 1
        self.cumulative_diff_size += len(mem_patches)
        self.last_state_id = new_state_id # Update the last status id
        tte_log_dbg(f"State Manager: Created LIGHT PATCH state: {new_state_id}, base:{new_state.base_full_state_id},  prev: {new_state.prev_state_id}")


    def _create_heavy_patch_state(self,
                                  new_state_id: str,
                                  instruction_address:int,
                                  current_registers_map: Dict[str, int],
                                  current_memory_pages: Dict[int, Tuple[int,bytearray]]) -> None:
        assert self.last_full_state_id is not None, "No full base state available for patch creation."

        base_full_state: Optional[FullEmuState] = self.get_state(self.last_full_state_id) # type: ignore
        assert base_full_state is not None, "No full base state available for patch creation."
        assert isinstance(base_full_state, FullEmuState), "Base state is not a full state."

        reg_patches = catch_dict_diff(base_full_state.registers_map, current_registers_map)
        mem_patches,new_pages = catch_bytes_diff(base_full_state.memory_pages, current_memory_pages)

        new_state = HeavyPatchEmuState(new_state_id,
                                       instruction_address,
                                       self.instruction_execution_counts[instruction_address])
        new_state.set_data(self.last_full_state_id, reg_patches, mem_patches, new_pages)

        self.states_dict[new_state_id] = new_state

        self.patch_chain_count += 1
        self.heavy_patch_count += 1
        self.cumulative_diff_size += len(mem_patches)
        self.last_state_id = new_state_id # Update the last status id
        tte_log_dbg(f"State Manager: Created HEAVY PATCH state: {new_state_id}, base: {new_state.base_full_state_id}")


    def get_state(self, state_id: Optional[str]) -> Optional[EmuState]:
        """
        Get the EmuState object by its ID.
        :param state_id: The ID of the state to retrieve.
        :return: The EmuState object if found, otherwise None.
        """
        if state_id is None:
            return None
        return self.states_dict.get(state_id, None)


    def _determine_next_state_type(self):
        if self.last_full_state_id is None or self.heavy_patch_count > self.MAX_HEAVY_PATCH_COUNT:
            # If this is the first full state, always create a full state
            return EmuState.STATE_TYPE_FULL

        elif self.patch_chain_count >= self.MAX_PATCH_CHAIN_LENGTH or self.cumulative_diff_size >= self.MAX_CUMULATIVE_DIFF_THRESHOLD:
            return EmuState.STATE_TYPE_FULL

        elif self.has_map_memory == True:
            self.has_map_memory = False
            return EmuState.STATE_TYPE_HEAVY_PATCH

        return EmuState.STATE_TYPE_LIGHT_PATCH


    def create_state(self,
                     uc,
                     instruction_address: int,
                     memory_regions: Iterator[Tuple[int, int, int]],
                     mem_patches: List[Tuple[int, int, bytes]]) -> None:
        """
        Create a new EmuState object based on the current state of the Unicorn instance.
        Decide whether to create a full state or a patch state based on the difference size or number of steps.

        :param uc: The Unicorn instance.
        :param instruction_address: The address of the current instruction.
        :param memory_regions: A list of memory regions(Iterator[Tuple[start, end, permission]]) to read.
        :param mem_patches: A list of memory patches(List[Tuple[addr, size, value]]) to apply.
        """
        tte_log_dbg(f"State Manager: Create state at 0x{instruction_address:X}")
        new_state_id = self._generate_state_id(instruction_address)

        #TODO testing: remove later
        current_memory_pages = None #   type: ignore

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
                                    instruction_address,
                                    current_registers_map,
                                    current_memory_pages)

        elif next_state_type == EmuState.STATE_TYPE_HEAVY_PATCH:
            # Create a heavy patch status
            current_memory_pages = self._read_memory_pages(uc, memory_regions)
            self._create_heavy_patch_state(new_state_id,
                                           instruction_address,
                                           current_registers_map,
                                           current_memory_pages)

        else:
            # Create a light patch status
            self._create_light_patch_state(new_state_id,
                                           instruction_address,
                                           current_registers_map,
                                           mem_patches)

        # #TODO testing
        # if current_memory_pages == None: #   type: ignore
        #     current_memory_pages= self._read_memory_pages(uc, memory_regions)
        # self.__test__(new_state_id,current_registers_map, current_memory_pages)


    # #TODO testing func: remove later
    # def __test__(self,new_state_id,current_registers_map ,current_memory_pages):
    #     st1 = self.get_state(new_state_id)
    #     assert st1 is not None, "State not found"
    #     st2 = st1.generate_full_state(self.states_dict)
    #     tte_log_dbg(f"State Manager: Test Pass: generate no error")

    #     st3 = FullEmuState(new_state_id)
    #     st3.set_data(current_registers_map, current_memory_pages) #   type: ignore
    #     try:
    #         assert(st2.registers_map == st3.registers_map) #   type: ignore
    #     except:
    #         tte_log_dbg("Cheack reg Fail")
    #         print("st1 patch ",st1.reg_patches) #   type: ignore
    #         print("st2  ",st2.registers_map) #   type: ignore
    #         print("st1  ",st3.registers_map)

    #     tte_log_dbg("Cheack regs Pass")
    #     try:
    #         assert(st2.memory_pages == st3.memory_pages) #   type: ignore
    #         tte_log_dbg("Cheack mem Pass")
    #     except:
    #         tte_log_dbg("Cheack mem Fail")
    #         print(st2.memory_pages) #   type: ignore
    #         print(st3.memory_pages)
    #         # print(self.get_state(st1.prev_state_id).generate_full_state(self.states_dict).__dict__)  #   type: ignore

    def compare_states(self, state1_id: str, state2_id: str):
        """
        Compares any two EmuState objects (full or patch) and returns their differences.

        :param EmuStateManager: An instance of EmuStateManager to extract full states if needed.
        :param state1: The first EmuState object.
        :param state2: The second EmuState object.
        :return: A tuple (regs_diff, mem_diff, pages_diff) representing the differences.
                 regs_diff: Dict of changed registers in state2 relative to state1.
                 mem_diff: List of memory different from state1 to state2.
                 pages_diff: List of page different from state1 to state2.
        """
        tte_log_dbg(f"\n--- Comparing states: {state1_id} vs {state2_id} ---")

        state1 = self.get_state(state1_id)
        state2 = self.get_state(state2_id)

        assert state1, "State 1 not found: {}".format(state1_id)
        assert state2, "State 2 not found: {}".format(state2_id)

        full_state1 = state1.generate_full_state(self.states_dict)
        full_state2 = state2.generate_full_state(self.states_dict)


        if not full_state1:
            tte_log_warn(f"Could not generate full state for '{state1_id}'. Comparison aborted.")
            return
        if not full_state2:
            tte_log_warn(f"Could not generate full state for '{state2_id}'. Comparison aborted.")
            return

        tte_log_dbg(f"Comparison between State '{state1_id}' (Type: {state1.type}) and State '{state2_id}' (Type: {state2.type}):")
        tte_log_dbg(f"Instruction Address: 0x{full_state1.instruction_address:X} -> 0x{full_state2.instruction_address:X}")
        tte_log_dbg(f"Execution Count: {full_state1.execution_count} -> {full_state2.execution_count}")

        regs_diff = catch_dict_diff(full_state1.registers_map, full_state2.registers_map)

        if not regs_diff:
            print("No register differences found.")
        else:
            for reg_name, new_val in regs_diff.items():
                old_val = full_state1.registers_map.get(reg_name, "N/A")
                print(f"  {reg_name}: 0x{old_val:X} -> 0x{new_val:X}")

        mem_diff = SortedDict()
        def catch_mem_diff(page_start_addr, bytes1: bytearray, bytes2: bytearray):
            assert len(bytes1) == len(bytes2), "Byte arrays must be of equal length."
            for offset_addr, (b1, b2) in enumerate(zip(bytes1, bytes2)):
                if b1 != b2:
                    tte_log_dbg(f"Memory difference found at 0x{page_start_addr + offset_addr:X}: 0x{b1:X} -> 0x{b2:X}")
                    mem_diff[page_start_addr + offset_addr] = [b1, b2]

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
    Class for tracking EmuExecuter and creating state snapshots in EmuStateManager when appropriate.
    """
    @dataclass
    class state_buffer_t(object):
        mem_patches: List[Tuple[int, int, bytes]]

    def __init__(self, executer:EmuExecuter, state_manager:EmuStateManager) -> None:
        self.executer: EmuExecuter = executer
        self.state_manager: EmuStateManager = state_manager

        self.arch = self.executer.arch
        self.capstone_arch, self.capstone_mode= CAPSTONE_ARCH_MAP[self.arch]
        self.md = Cs(self.capstone_arch, self.capstone_mode)

        self.state_buffer = self.state_buffer_t([])

        self._init_hook()


    def _init_hook(self) -> None:
        self._trace_code()
        self._trace_mem_write()

        self._trace_custom_operate()


    def _trace_code(self):
        # self.executer.add_mu_hook(UC_HOOK_MEM_READ, self.trace_mem_read)
        self.executer.add_mu_hook(UC_HOOK_CODE, self.cb_log_insn_execution)
        self.executer.add_mu_hook(UC_HOOK_CODE, self.cb_create_emu_state)


    def _trace_mem_write(self):
        self.executer.add_mu_hook(UC_HOOK_MEM_WRITE, self.cb_log_mem_write)
        self.executer.add_mu_hook(UC_HOOK_MEM_WRITE, self.cb_catch_mem_write)


    def _trace_custom_operate(self):
        self.executer.add_custom_hook(EmuExecuter.CUSTOM_HOOK_EXECUTE_END, self.cb_create_emu_end_state)
        self.executer.add_custom_hook(EmuExecuter.CUSTOM_HOOK_MEM_MAP, self.cb_mark_mem_map)




    def cb_log_mem_write(self, uc, access, address, size, value, user_data):
        tte_log_dbg(f"Memory write: access={access}, address=0x{address:X}, size={size}, value=0x{value:X}, insn={uc.reg_read(ARCH_TO_INSN_POINTER_MAP[self.arch]):X}")
        return True



    def cb_log_insn_execution(self, uc, address, size, user_data) -> bool:
        tte_log_dbg(f"Tracing instruction at 0x{address:X}, instruction size = {size:X}")
        for i in self.md.disasm(uc.mem_read(address, size), 0):
            tte_log_dbg("Executing instruction:    %s\t%s" % (i.mnemonic, i.op_str))
        return True


    def cb_create_emu_state(self, uc, address, size, user_data) -> bool:
        """
        @Callback function for hook "UC_HOOK_CODE"
        Note: UC_HOOK_CODE triggers callback before the instruction is actually executed

        This function will perform two operations:
        Create the simulated state saved to the status buffer as a new EmuState and add it to the EmuStateManager
        Create a new simulated state in the state buffer
        """

        self.state_manager.create_state(uc,
                                        address,
                                        self.executer.get_mem_regions(),
                                        self.state_buffer.mem_patches)

        # Save the current state to the state buffer
        self.state_buffer.mem_patches = []

        return True


    def cb_catch_mem_write(self, uc, access, address:int, size:int, value:int, user_data) -> bool:
        """
        @Callback function for hook "UC_HOOK_MEM_WRITE"

        """
        value_bytes = value.to_bytes(size, byteorder='big' if get_is_be() else 'little')
        # Save the memory patch to the state buffer
        self.state_buffer.mem_patches.append((address, size, value_bytes))
        return True


    def cb_create_emu_end_state(self, uc):
        insn_pointer = uc.reg_read(ARCH_TO_INSN_POINTER_MAP[self.arch])
        self.state_manager.create_state(uc,
                                        insn_pointer,
                                        self.executer.get_mem_regions(),
                                        self.state_buffer.mem_patches)

    def cb_mark_mem_map(self, uc):
        """
        Callback function to mark that the binary has been loaded.
        This is used to determine whether to create a full state or a patch state.
        """

        self.state_manager.has_map_memory = True
        tte_log_dbg("Binary has been loaded, will create heavy patch state next time.")


























class EmuViewer(ida_kernwin.simplecustviewer_t):
    pass








import cProfile
import pstats




if __name__ == "__main__":
    t = 0x140001450
    start = idc.get_func_attr(t,0)
    end = idc.get_fchunk_attr(t,8)
    F = EmuSettingsForm(start,end)
    F.Execute()

    ee = EmuExecuter(F.GetSetting()) # type: ignore
    ee.init()

    esm = EmuStateManager()

    et = EmuTracer(ee,esm) # type: ignore

    ee.run()

    esm.compare_states("$0x140001464#1","$0x14000146B#1")

    # st = esm.get_state("$0x14000146B#1")
    # t = st.generate_full_state(esm.states_dict)
    # print(t.memory_pages)

    # print(esm.generate_full_state("$0x140001458#1").__dict__)


    # esm2 = EmuStateManager()
    # esm2.create_state(ee.mu, ee.mu.reg_read(ee.insn_pointer), ee.get_mem_regions(), et.state_buffer.mem_patches)


    # print(esm2.get_state("$0x140001458#1").__dict__)

    ee.destroy()
    F.Free()













# class EmuTrace(idaapi.plugin_t):
#     flags = idaapi.PLUGIN_DRAW
#     comment = "XXX"
#     help = ""
#     wanted_name = "EmuTrace"
#     wanted_hotkey = "Ctrl+Alt+Shift+F12"
#     wanted_hotkey = ""


#     def __init__(self):
#         super(EmuTrace, self).__init__()
#         self._data = None

#     def term(self):
#         pass

#     def init(self):
#         return idaapi.PLUGIN_OK

#     def run(self, arg):
#         pass

# def PLUGIN_ENTRY():
#     return EmuTrace()