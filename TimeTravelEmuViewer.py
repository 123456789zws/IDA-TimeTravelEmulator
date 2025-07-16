import idaapi
import ida_lines
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
from sortedcontainers import SortedList
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from PyQt5 import QtGui, QtCore, QtWidgets


from TimeTravelEmulator import *



PAGE_SIZE = 0x1000




CHAMGE_HIGHLIGHT_COLOR   = 0xFFD073








# Line types
UNKNOW_TYPE_LINE = 0
DATA_LINE = 1
CODE_LINE = 2
NAME_LINE = 3

@dataclass
class address_line_info:
    address: int
    address_idx: int = 0
    type: int = UNKNOW_TYPE_LINE
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

    def Close(self):
        self.CheckRebuild()
        return super().Close()

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
        lineno = self._get_lineno_left_from_address(address)
        if lineno != -1:
            return super().Jump(lineno, x, y)
        return False

    # --- Overridden methods that return line numbers (need conversion) ---

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

    def GetPos(self, mouse = 0):
        """
        Returns the current cursor or mouse position, with the line number
        converted to a binary address.

        :param mouse: return mouse position.
        :return: Returns a tuple (address, x, y) or None if position cannot be determined.
        """
        self.CheckRebuild()
        pos = super().GetPos(mouse)
        if pos:
            lineno, x, y = pos
            info = self._get_address_info_from_lineno(lineno)
            if info is not None:
                return (info.address, x, y)
        return None

    def GetLineNo(self, mouse = 0):
        """
        Returns the binary address of the current line.

        :param mouse: return mouse position.
        :return: Returns the binary address or None on failure.
        """
        self.CheckRebuild()
        lineno = super().GetLineNo(mouse)
        if lineno != -1:
            info = self._get_address_info_from_lineno(lineno)
            if info is not None:
                return info.address
        return None


class ColorfulLineGenerator():
    def __init__(self):
        pass

    @staticmethod
    def generate_register_line(reg_name, reg_value, value_len) -> str:
        colored_reg_name = f" {reg_name:>6}"
        colored_reg_value = ida_lines.COLSTR(f"0x{reg_value:0{value_len}X}", ida_lines.SCOLOR_SYMBOL)
        return colored_reg_name + ": " + colored_reg_value



class TTE_DisassemblyViewer():
    """
    a subviewer class of TimeTravelEmuViewer to display disassembly.

    To use it following the steps:
    1. use self.InitViewer() to initializate the viewer.
    2. add some data to the viewer.
    3. add self.viewer_widegt to TimeTravelEmuViewer's layout.
    4. call TimeTravelEmuViewer.Show() to show viewer with the subviewer.
    """


    def __init__(self):
        self.viewer = AddressAwareCustomViewer()
        self.bitness = get_bitness()
        if self.bitness:
            self.addr_len = self.bitness // 4
        else:
            tte_log_err("Failed to get bitness")



    def InitViewer(self):
        self.viewer.Create("TimeTravelEmuDisassembly")
        self.viewer_widegt  = ida_kernwin.PluginForm.FormToPyQtWidget(self.viewer.GetWidget())
        self._SetCustomViewerStatusBar()


    def _SetCustomViewerStatusBar(self):
        # Remove original status bar
        viewer_status_bar = self.viewer_widegt.findChild(QtWidgets.QStatusBar)
        for widget in viewer_status_bar.findChildren(QtWidgets.QLabel):
            viewer_status_bar.removeWidget(widget)

        # Add custom status bar
        viewer_status_bar.addWidget(QtWidgets.QLabel(" [ Flags Status: "))

        flags_refresh_button = QtWidgets.QPushButton("Refresh")
        flags_refresh_button.clicked.connect(lambda: ida_kernwin.msg("Flags refreshed!\n"))
        viewer_status_bar.addWidget(flags_refresh_button)
        viewer_status_bar.addWidget(QtWidgets.QLabel(" ] "))

        viewer_status_bar.addPermanentWidget(QtWidgets.QLabel("Flags: OK "))


    def LoadMemoryPages(self, range_start, range_end,  memory_pages: Dict[int, Tuple[int, bytearray]], execution_counts: Dict[int, int]):

        def get_addr_type(address) -> int:
            addr_flag = ida_bytes.get_flags(address)
            if idc.is_code(addr_flag):
                return CODE_LINE
            elif idc.is_data(addr_flag):
                return DATA_LINE
            else:
                return UNKNOW_TYPE_LINE


        memory_pages_list = sorted(memory_pages.items())
        current_addr = 0
        for start_addr, (perm, data) in memory_pages_list:
            if current_addr < start_addr:
                current_addr = start_addr
            assert len(data) == PAGE_SIZE
            for offset in range(PAGE_SIZE):

                line_addr_str = format(current_addr, f"0{self.addr_len}x")




                self.viewer.AddLine(start_addr + offset,
                                    DATA_LINE,
                                     f".{line_addr_str}: {data[offset]}",
                                    None,
                                    None,
                                    True)
                current_addr = start_addr + offset
        self.viewer.Refresh()



class TTE_RegistersViewer:
    """
    a subviewer class of TimeTravelEmuViewer to display registers.

    To use it following the steps:
    1. use self.InitViewer() to initializate the viewer.
    2. use self.LoadRegisters() to load registers lines
    3. add self.viewer_widegt to TimeTravelEmuViewer's layout.
    4. call TimeTravelEmuViewer.Show() to show viewer with the subviewer.
    """

    def __init__(self):
        self.viewer = ida_kernwin.simplecustviewer_t()
        self.bitness = get_bitness()
        if self.bitness:
            self.hex_len = self.bitness // 4
        else:
            tte_log_err("Failed to get bitness")


    def InitViewer(self):
        self.viewer.Create("TimeTravelEmuRegisters")
        self.viewer_widegt  = ida_kernwin.PluginForm.FormToPyQtWidget(self.viewer.GetWidget())
        self.statusbar_label = QtWidgets.QLabel("State ID: N\\A")

        self._SetCustomViewerStatusBar()

    def _SetCustomViewerStatusBar(self):
        # Remove original status bar
        viewer_status_bar = self.viewer_widegt.findChild(QtWidgets.QStatusBar)
        for widget in viewer_status_bar.findChildren(QtWidgets.QLabel):
            viewer_status_bar.removeWidget(widget)

        viewer_status_bar.addWidget(self.statusbar_label)


    def _RefreshStatusBar(self, state_id: str):
        self.statusbar_label.setText(f"State ID: {state_id}")





    def LoadRegisters(self, state_id: str, registers: Dict[str, int], regs_diff: Optional[List[str]]):
        changed_fgcolor = CHAMGE_HIGHLIGHT_COLOR
        for reg_name, reg_value in registers.items():

            line_bgcolor = None

            if regs_diff is not None and reg_name in regs_diff:
                line_bgcolor = changed_fgcolor

            line_text = ColorfulLineGenerator.generate_register_line(reg_name, reg_value, self.hex_len)
            self.viewer.AddLine(line_text, bgcolor=line_bgcolor)

        self.viewer.Refresh()

        self._RefreshStatusBar(state_id)





class TTE_MemoryViewer:
    def __init__(self):
        self.viewer = ida_kernwin.simplecustviewer_t()


    def InitViewer(self):
        self.viewer.Create("TimeTravelEmuRegisters")
        self.viewer_widegt  = ida_kernwin.PluginForm.FormToPyQtWidget(self.viewer.GetWidget())












# from TimeTravelEmulator import EmuStateManager



class TimeTravelEmuViewer(ida_kernwin.PluginForm):
    """
    The main TimeTravelEmuViewer class.

    To use it, you need to do the following steps:
    1. use self.Init() to initialize the viewer.
    2. use self.LoadESM(state_manager) to load the EmuStateManager into the viewer.
    3. use self.Show(“title”) to show the viewer with a title.

    """


    def __init__(self):
        super().__init__()

        self.disassembly_viewer: TTE_DisassemblyViewer =  TTE_DisassemblyViewer()
        self.registers_viewer: TTE_RegistersViewer = TTE_RegistersViewer()
        self.mempages_viewer: TTE_MemoryViewer = TTE_MemoryViewer()

        self.state_manager: Optional[EmuStateManager] = None



    def Init(self):
        self.disassembly_viewer.InitViewer()
        self.registers_viewer.InitViewer()
        self.mempages_viewer.InitViewer()


    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

        self.PopulateForm()

    def LoadESM(self, state_manager: EmuStateManager):
        """
        Load the EmuStateManager into the viewer.

        """
        self.state_manager = state_manager


        enter = next(reversed(state_manager.states_dict.items()))
        if not enter:
            raise ValueError("No state found in state_manager")
        last_key, last_state  = enter

        self.execution_counts =  {item[1]: item[3] for item in self.state_manager.get_state_list_with_insn()}



        self.SwitchStateDisplay(last_key)


    def PopulateForm(self):
        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal) # type: ignore
        main_splitter.setChildrenCollapsible(True)


        main_splitter.addWidget(self.disassembly_viewer.viewer_widegt)


        right_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical) # type: ignore
        right_splitter.setChildrenCollapsible(True)

        right_splitter.addWidget(self.registers_viewer.viewer_widegt)
        right_splitter.addWidget(self.mempages_viewer.viewer_widegt)

        main_splitter.addWidget(right_splitter)

        main_layout = QtWidgets.QVBoxLayout(self.parent)
        main_layout.addWidget(main_splitter)
        main_layout.setContentsMargins(0, 0, 0, 0)





    def SwitchStateDisplay(self, state_id: str):
        assert self.state_manager is not None, "No state_manager loaded"

        target_state = self.state_manager.get_state(state_id)
        assert target_state is not None, f"State {state_id} not found in state_manager"

        target_full_state = target_state.generate_full_state(self.state_manager.states_dict)
        assert target_full_state is not None, f"Failed to generate full state for state {state_id}"


        self.disassembly_viewer.LoadMemoryPages(-1, -1, target_full_state.memory_pages ,self.execution_counts)

        regs_diff = None
        mem_diff = None
        entry= self.state_manager.get_state_change(target_full_state.state_id)

        if entry:
            regs_diff, mem_diff = entry
            regs_diff = list(regs_diff)

        self.registers_viewer.LoadRegisters(target_full_state.state_id, target_full_state.registers_map, regs_diff)




















