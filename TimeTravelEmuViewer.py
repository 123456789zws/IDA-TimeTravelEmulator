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



class AddressAwareCustomViewer(ida_kernwin.simplecustviewer_t):
    def __init__(self):
        super().__init__()
        self._lines_data = SortedList(key=lambda x: x[0]) # SortedList[[address, line_str, fgcolor, bgcolor]], using address as key
        self.need_rebuild = False # Flag to indicate if the viewer needs to be refreshed

    def _get_lineno_from_address(self, address):
        """
        Gets the current line number for a given address using SortedList's bisect_left.
        Returns -1 if address not found.
        """
        # bisect_left returns an insertion point. We need to check if the item at that point
        # actually matches the address. We provide a dummy tuple for comparison.
        idx = self._lines_data.bisect_left((address, None, None, None))
        if idx < len(self._lines_data) and self._lines_data[idx][0] == address:
            return idx
        return -1


    def _get_address_from_lineno(self, lineno):
        """
        Gets the address for a given line number.
        Returns None if lineno is out of bounds.
        """
        if 0 <= lineno < len(self._lines_data):
            return self._lines_data[lineno][0]
        return None


    def _rebuild_viewer_content(self):
        """
        Internal helper to clear the underlying simplecustviewer_t (which is self)
        and repopulate it from the sorted _lines_data.
        Notes: It is a performance-consuming function, so it is handed over to external manual calls
        """
        super(AddressAwareCustomViewer, self).ClearLines() # Call base ClearLines
        for address, line_str, fgcolor, bgcolor in self._lines_data:
            super(AddressAwareCustomViewer, self).AddLine(line_str, fgcolor, bgcolor) # Call base AddLine
        super(AddressAwareCustomViewer, self).Refresh() # Refresh the viewer

    def CheckRebuild(self):
        if self.need_rebuild:
            self._rebuild_viewer_content()
            self.need_rebuild = False

    def Create(self, title):
        return super(AddressAwareCustomViewer, self).Create(title)

    def Close(self):
        self.CheckRebuild()
        return super(AddressAwareCustomViewer, self).Close()

    def Show(self):
        self.CheckRebuild()
        return super(AddressAwareCustomViewer, self).Show()

    def Refresh(self):
        self.CheckRebuild()
        return super(AddressAwareCustomViewer, self).Refresh()


    def ClearLines(self):
        self._lines_data.clear() # Use SortedList's clear method
        super(AddressAwareCustomViewer, self).ClearLines() # Call base ClearLines
        super(AddressAwareCustomViewer, self).Refresh() # Refresh the viewer


    def AddLine(self, address, line, fgcolor=None, bgcolor=None):
        """
        Adds a colored line associated with a binary address.
        If the address already exists, it will update the existing line.
        Otherwise, it inserts the line in the correct sorted position.
        @return: Boolean indicating success.
        """
        # Find if the address already exists
        idx = self._lines_data.bisect_left((address, None, None, None))
        if idx < len(self._lines_data) and self._lines_data[idx][0] == address:
            # Address exists, remove old entry and add new one
            del self._lines_data[idx] # Remove by index, SortedList shifts automatically

        # Add the new or updated entry. SortedList.add() will place it correctly.
        self._lines_data.add((address, line, fgcolor, bgcolor))
        self.need_rebuild = True
        # self.RebuildViewerContent(): # To improve performance, we don't rebuild it here, it must be called manually later
        return True

    def InsertLine(self, address, line, fgcolor=None, bgcolor=None):
        """
        Inserts a line at the position determined by the given address.
        This is equivalent to AddLine as lines are always kept sorted by address.
        @return: Boolean indicating success.
        """
        # With SortedList, InsertLine is effectively the same as AddLine
        # because SortedList maintains sorted order automatically.
        return self.AddLine(address, line, fgcolor, bgcolor)

    def EditLine(self, address, line, fgcolor=None, bgcolor=None):
        """
        Edits an existing line identified by its binary address.
        @return: Boolean indicating success.
        """
        self.CheckRebuild()
        lineno = self._get_lineno_from_address(address)
        if lineno != -1:
            # Remove old entry and add updated one
            del self._lines_data[lineno]
            self._lines_data.add((address, line, fgcolor, bgcolor))
            super(AddressAwareCustomViewer, self).EditLine(lineno, line, fgcolor, bgcolor) # Call base EditLine
            return True
        return False

    def PatchLine(self, address, offs, value):
        """
        Patches an existing line character at the given offset within the line.
        """
        self.CheckRebuild()
        lineno = self._get_lineno_from_address(address)
        if lineno != -1:
            # Call the base class's PatchLine
            return super(AddressAwareCustomViewer, self).PatchLine(lineno, offs, value)
        return False

    def DelLine(self, address):
        """
        Deletes an existing line identified by its binary address.
        @return: Boolean indicating success.
        """
        lineno = self._get_lineno_from_address(address)
        if lineno != -1:
            del self._lines_data[lineno] # Delete by index
            self.need_rebuild = True
            return True
        return False

    def GetLine(self, address):
        """
        Returns a line's content and colors identified by its binary address.
        @param address: The binary address (integer) of the line.
        @return: Returns a tuple (colored_line, fgcolor, bgcolor) or None if address not found.
        """
        self.CheckRebuild()
        lineno = self._get_lineno_from_address(address)
        if lineno != -1:
            # Retrieve the full tuple, then extract line_str, fgcolor, bgcolor
            _, line_str, fgcolor, bgcolor = self._lines_data[lineno]
            return (line_str, fgcolor, bgcolor)
        return None

    def Jump(self, address, x=0, y=0):
        """
        Jumps to the line associated with the given binary address.
        @param address: The binary address to jump to.
        @param x: Horizontal cursor position (optional).
        @param y: Vertical cursor position (optional).
        @return: Boolean indicating success.
        """
        self.CheckRebuild()
        lineno = self._get_lineno_from_address(address)
        if lineno != -1:
            return super(AddressAwareCustomViewer, self).Jump(lineno, x, y)
        return False

    # --- Overridden methods that return line numbers (need conversion) ---

    def GetSelection(self):
        """
        Returns the selected range in terms of addresses or None.
        @return:     - tuple(x1, address1, x2, address2)
                    - None if no selection
        """
        self.CheckRebuild()
        selection = super(AddressAwareCustomViewer, self).GetSelection()
        if selection:
            x1, y1, x2, y2 = selection
            addr1 = self._get_address_from_lineno(y1)
            addr2 = self._get_address_from_lineno(y2)
            if addr1 is not None and addr2 is not None:
                return (x1, addr1, x2, addr2)
        return None

    def GetPos(self, mouse = 0):
        """
        Returns the current cursor or mouse position, with the line number
        converted to a binary address.
        @param mouse: return mouse position.
        @return: Returns a tuple (address, x, y) or None if position cannot be determined.
        """
        self.CheckRebuild()
        pos = super(AddressAwareCustomViewer, self).GetPos(mouse)
        if pos:
            lineno, x, y = pos
            address = self._get_address_from_lineno(lineno)
            if address is not None:
                return (address, x, y)
        return None

    def GetLineNo(self, mouse = 0):
        """
        Returns the binary address of the current line.
        @param mouse: return mouse position.
        @return: Returns the binary address or None on failure.
        """
        self.CheckRebuild()
        lineno = super(AddressAwareCustomViewer, self).GetLineNo(mouse)
        if lineno != -1:
            return self._get_address_from_lineno(lineno)
        return None

class TTE_DisassemblyViewer(ida_kernwin.PluginForm):
    def __init__(self):
        super(TTE_DisassemblyViewer, self).__init__()
        self.viewer = AddressAwareCustomViewer()


    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self._InitializeViewer()
        self.PopulateForm()


    def _InitializeViewer(self):
        self.viewer.Create("Emu Disassembly Viewer")
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









w = TTE_DisassemblyViewer()
w.Show("TEST IDA")




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



























