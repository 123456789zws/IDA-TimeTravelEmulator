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
from sortedcontainers import SortedList
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from PyQt5 import QtGui, QtCore, QtWidgets



# Line types
DATA_LINE = 0
CODE_LINE = 1
NAME_LINE = 2

@dataclass
class address_line_info:
    address: int
    address_idx: int = 0
    type: int = DATA_LINE
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
        Adds a colored line associated with a binary address.

        :param lazy: If True, the viewer will not be refreshed after the deletion.
        :return: Boolean indicating success.
        """
        # Find if the address already exists
        idx = self._get_lineno_right_from_address(address)
        addr_idx = 0
        if idx != -1 and idx < len(self._lines_data) and self._lines_data[idx].address == address: # type: ignore
            # Address exists
            addr_idx = self._lines_data[idx].address_idx + 1 # type: ignore

        # Add the new or updated entry. SortedList.add() will place it correctly.
        new_line_info = address_line_info(address, addr_idx,address_type, line, fgcolor, bgcolor)
        self._lines_data.add(new_line_info)
        if lazy:
            self.need_rebuild = True
            return True
        else:
            actual_lineno_inserted = self._lines_data.index(new_line_info)
            super().InsertLine(actual_lineno_inserted, line, fgcolor, bgcolor) # Call base InsertLine

    def InsertLine(self, address, address_type, line, fgcolor=None, bgcolor=None):
        """
        Inserts a line at the position determined by the given address.
        This is equivalent to AddLine as lines are always kept sorted by address.

        :return: Boolean indicating success.
        """
        return self.AddLine(address, address_type, line, fgcolor, bgcolor)

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

aacv = AddressAwareCustomViewer()
aacv.Create("AAA")


for addr in range(0x1000, 0x1010):
    aacv.AddLine(addr, 0, f"{addr}: Hello, world!")
    aacv.AddLine(addr, 0, f"{addr}: Hello, world!")
aacv.Show()

print(aacv._lines_data)








class TTE_DisassemblyViewer(ida_kernwin.PluginForm):
    def __init__(self):
        super(TTE_DisassemblyViewer, self).__init__()
        self.viewer = AddressAwareCustomViewer()


    def Init(self, memory_pages: Dict[int, Tuple[int, bytearray]]):
        self.title = "TimeTravelEmuDisassembly"
        self.icon = ":/icons/timetravel_icon.png"

        memory_pages_list = sorted(memory_pages.items())
        for start_addr, (perm, data) in memory_pages_list:
            assert len(data) == PAGE_SIZE
            end_addr = start_addr + PAGE_SIZE



    def _insert_memory_page(self, start_addr: int, end_addr: int, data: bytearray):
        for address in range(start_addr, end_addr, 16):
            addr_name = idc.get_name(address)
            if addr_name:
                self.viewer.CustomAddLine()









    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self._InitializeViewer()
        self.PopulateForm()


    def _InitializeViewer(self):
        self.viewer.Create("Disassembly Viewer")
        self.viewer_widegt  = self.FormToPyQtWidget(self.viewer.GetWidget())

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








    def PopulateForm(self):
        vbox = QtWidgets.QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(self.viewer_widegt)

        self.parent.setLayout(vbox)









# w = TTE_DisassemblyViewer()
# w.Show("TEST IDA")




class TTE_MemoryViewer:
    pass



class TTE_RegistersViewer:
    pass



class TTE_StatesViewer:
    pass














# from TimeTravelEmulator import EmuStateManager



# class TimeTravelEmuViewer():

#     def __init__(self, states_manager: EmuStateManager):
#         super().__init__()
#         self.states_manager: EmuStateManager = states_manager
#         self.disassembly_viewer: TTE_DisassemblyViewer =  TTE_DisassemblyViewer()
#         self.memory_viewer: TTE_MemoryViewer = TTE_MemoryViewer()
#         self.registers_viewer: TTE_RegistersViewer = TTE_RegistersViewer()
#         self.states_viewer: TTE_StatesViewer = TTE_StatesViewer()


#     def init(self, memory_regions: Iterator[Tuple[int, int, int]]):
#         """

#         """
#         pass




#         seg_data = ida_bytes.get_bytes()
#         self.viewer =



























