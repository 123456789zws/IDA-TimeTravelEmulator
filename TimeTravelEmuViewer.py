import bisect

from sortedcontainers.sorteddict import SortedDict
from TimeTravelEmulator import EmuState
import idaapi
import ida_lines
import ida_ida
import ida_kernwin
import logging
import ida_nalt
import idc
import ida_bytes
import ida_name
import ida_segment

from abc import ABC
from collections import defaultdict
from typing import Callable, Dict, Iterator, List, Literal, Optional, Tuple, Union
from copy import deepcopy
from attr import dataclass
from re import split


import bsdiff4
from sortedcontainers import SortedList
from sympy import N, false
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from PyQt5 import QtGui, QtCore, QtWidgets


from TimeTravelEmulator import *



PAGE_SIZE = 0x1000

NEXT_STATE_ACTION_SHORTCUT = "F3"
PREV_STATE_ACTION_SHORTCUT = "F2"

EXECUTE_INSN_HILIGHT_COLOR = 0xFFD073
CHANGE_HIGHLIGHT_COLOR   = 0xFFD073





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
        for action_handler in self.menu_action_handlers:
            action_handler.unregister()


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
        or inserts a new line if it does not exist.

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
                self.DelLine(address, lazy=False)
                return self.InsertLine(address, address_type, line, fgcolor, bgcolor)
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
        idx = self._lines_data.bisect_left(address_line_info(address = address + 1 ,address_idx = -1))
        if idx > 0:
            lineno = idx - 1
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
            return lineno
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


    def SetDblChickCallback(self, callback):
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
        action_handler.register()
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
    def GenerateDisassemblyCodeLine(address, address_len, value, value_len, execution_counts) -> str:
        if execution_counts == 0:
            execution_counts_str = "    "
        elif execution_counts == 1:
            execution_counts_str = ida_lines.COLSTR(f"{execution_counts: 4}", ida_lines.SCOLOR_AUTOCMT)
        else:
            execution_counts_str = ida_lines.COLSTR(f"{execution_counts: 4}", ida_lines.SCOLOR_REGCMT)


        addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}", ida_lines.SCOLOR_PREFIX)
        insn = ida_lines.generate_disasm_line(address)
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
    def GenerateMemoryLine(address, address_len, data_bytes, bytes_per_line=16, data_patch_indices: Optional[List[int]] = None) -> str:
        """
        Generates a colored memory dump line.
        Example: 0x00401000  48 83 EC 28 48 8B C4 48 | H. .(.H. .H
        """
        addr_str = ida_lines.COLSTR(f"0x{address:0{address_len}X}", ida_lines.SCOLOR_PREFIX)

        hex_dump_parts = []
        ascii_dump_parts = []
        for i, byte_val in enumerate(data_bytes):
            hex_part = f"{byte_val:02X}"

            # Check if this byte is part of a patch
            if data_patch_indices and i in data_patch_indices:
                hex_dump_parts.append(ida_lines.COLSTR(hex_part, ida_lines.SCOLOR_ERROR)) # Highlight changed bytes
            else:
                hex_dump_parts.append(ida_lines.COLSTR(hex_part, ida_lines.SCOLOR_BINPREF)) # Default color

            if 0x20 <= byte_val <= 0x7E:
                ascii_dump_parts.append(chr(byte_val))
            else:
                ascii_dump_parts.append('.')

        hex_str = ' '.join(hex_dump_parts).ljust(bytes_per_line * 3 - 1)
        ascii_str = ''.join(ascii_dump_parts)

        return f"{addr_str}  {hex_str} | {ascii_str}"



class TTE_DisassemblyViewer():
    """
    a subviewer class of TimeTravelEmuViewer to display disassembly.

    To use it following the steps:
    1. Use self.InitViewer() to initializate the viewer.
    2. Set data: including self.memory_pages_list and self.execution_counts
    3. Add self.viewer_widegt to TimeTravelEmuViewer's layout.
    4. Use self.DisplayMemoryRange to display memory pages in range.
    5. Call TimeTravelEmuViewer.Show() to show viewer with the subviewer.
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
        self.codelines_list:Dict[int, int] = {}  # {address : address_idx)}


        self.current_state_id = None
        self.memory_pages_list = None

        self.current_insn_address: int = -1
        self.current_range_display_start: int = -1;
        self.current_range_display_end: int = -1;


        self.hightlighting_lines: List[Tuple[int, int, Optional[int]]] = [] # [(address, lineno, color),...]



    def InitViewer(self):
        self.viewer.Create(self.title)
        self.viewer_widegt  = ida_kernwin.PluginForm.FormToPyQtWidget(self.viewer.GetWidget())
        self._SetCustomViewerStatusBar()
        self._SetDoubleClickCallback()
        self._SetMenuActions()



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

        self.viewer.SetDblChickCallback(OnDblClickAction)




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
        if IsSet is not None:
            range_start = form.start_addr
            range_end = form.end_addr
            self.DisplayMemoryRange(range_start, range_end)
        form.Free()



    def _SetCustomViewerStatusBar(self):
        # Remove original status bar
        viewer_status_bar = self.viewer_widegt.findChild(QtWidgets.QStatusBar)
        for widget in viewer_status_bar.findChildren(QtWidgets.QLabel):
            viewer_status_bar.removeWidget(widget)

        self.statusbar_state_id_qlabel = QtWidgets.QLabel("[Status: N\\A ]")
        viewer_status_bar.addWidget(self.statusbar_state_id_qlabel)
        self.statusbar_memory_range_qlabel = QtWidgets.QLabel("(Memory Range: N\\A )")
        viewer_status_bar.addWidget(self.statusbar_memory_range_qlabel)



    def LoadListFromESM(self, state_list: List[Tuple[str, EmuState]]):
        self.execution_counts= {state.instruction_address: state.execution_count for _, state in state_list}


    def LoadState(self, state_id: str, insn_address: int, memory_pages: Dict[int, Tuple[int, bytearray]]):
        assert self.statusbar_state_id_qlabel, "Status bar not initialized"

        self.current_insn_address = insn_address
        self.current_state_id = state_id
        self.memory_pages_list = sorted(memory_pages.items())
        self.statusbar_state_id_qlabel.setText(f"[State: {self.current_state_id} ]")


    def AddHightlightLine(self, address, address_idx, color):
        self.hightlighting_lines.append((address, address_idx, color))


    def HighlightLines(self):
        for address, address_idx, color in self.hightlighting_lines:
            self.viewer.EditLineColor(address, address_idx, 0, color)


    def ClearHighlightLines(self):
        while len(self.hightlighting_lines) > 0:
            address, lineno, color = self.hightlighting_lines.pop()
            self.viewer.EditLineColor(address, lineno, None)


    def ApplyStatePatchesInViewer(self, mem_patch: Optional[List[Tuple[int, bytes]]], page_diff: Optional[SortedDict]):
        """
        Apply memory patches to the viewer and highlight the changed lines.

        :param mem_patch: A list of tuples (address, value) representing the changed memory.
        :param page_diff: A sorted dictionary of memory pages, with keys as start addresses and values as tuples (change_mode, data).
                            change_mode: 1 - removed, 2 - added
        :return: None
        """
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
                        line_text = ColorfulLineGenerator.GenerateDisassemblyDataLine(addr, self.addr_len, value, 1)
                        self.viewer.UpdateLine(addr, 0, SINGLE_DATA_LINE, line_text, None, None)
                self.hightlighting_lines.append((addr, 0, CHANGE_HIGHLIGHT_COLOR))

        if self.current_insn_address > 0 and self.current_insn_address > self.current_range_display_start and self.current_insn_address < self.current_range_display_end:
            self.AddHightlightLine(self.current_insn_address, self.codelines_list.get(self.current_insn_address, 0), EXECUTE_INSN_HILIGHT_COLOR)
        self.HighlightLines()
        self.viewer.Refresh()

    def DisplayMemoryRange(self, range_start, range_end):
        """
        Display memory range in the viewer. This function will clear the previous range and display the new range.
        By the way, it can also be used to refresh the current range.

        :param range_start: start address of the range.
        :param range_end: end address of the range.
        :return: None
        """
        assert self.statusbar_memory_range_qlabel, "Status bar not initialized"
        assert self.memory_pages_list and self.execution_counts, "State data not loaded"

        self.viewer.ClearLines()
        current_addr = range_start
        for start_addr, (perm, data) in self.memory_pages_list:
            assert len(data) == PAGE_SIZE

            if start_addr > range_end or start_addr + PAGE_SIZE <= range_start:
                continue

            # Process empty addresses that may exist before the current page
            while current_addr < start_addr:
                line_text = ColorfulLineGenerator.GenerateUnknownLine(current_addr, self.addr_len)
                self.viewer.AddLine(current_addr, UNKNOW_LINE, line_text)
                self.viewer.AddLine(current_addr, UNKNOW_LINE, line_text)
                current_addr += 1

            while current_addr < start_addr + PAGE_SIZE and current_addr < range_end:
                count = 0
                address_idx = 0
                if current_addr in self.execution_counts:
                    count = self.execution_counts[current_addr]

                current_addr_flag = ida_bytes.get_flags(current_addr)

                is_named = ida_bytes.has_any_name(current_addr_flag)
                if is_named:
                    empty_line_text = ColorfulLineGenerator.GenerateEmptyLine(current_addr, self.addr_len)
                    line_text = ColorfulLineGenerator.GenerateDisassemblyNameLine(current_addr, self.addr_len)
                    self.viewer.AddLine(current_addr, EMPTY_LINE, empty_line_text)
                    self.viewer.AddLine(current_addr, NAME_LINE, line_text)
                    address_idx += 2

                if idc.is_code(current_addr_flag):
                    code_size = idc.get_item_size(current_addr)
                    line_text = ColorfulLineGenerator.GenerateDisassemblyCodeLine(current_addr,
                                                                                       self.addr_len,
                                                                                       data[current_addr - start_addr],
                                                                                       code_size,
                                                                                       count)
                    self.viewer.AddLine(current_addr, CODE_LINE, line_text)
                    self.codelines_list[current_addr] = address_idx
                    current_addr += code_size
                    continue

                elif idc.is_data(current_addr_flag):
                    data_size = idc.get_item_size(current_addr)
                    offset = current_addr - start_addr
                    line_text = ColorfulLineGenerator.GenerateDisassemblyDataLine(current_addr, self.addr_len, data[offset : offset + data_size], data_size)
                    if data_size == 1:
                        self.viewer.AddLine(current_addr, SINGLE_DATA_LINE, line_text)
                    else:
                        self.viewer.AddLine(current_addr, CODE_LINE, line_text)

                    current_addr += data_size
                    continue
                else:
                    line_text = ColorfulLineGenerator.GenerateDisassemblyDataLine(current_addr, self.addr_len, data[current_addr - start_addr : current_addr - start_addr + 1], 1)
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

        # Highlight current instruction in memory range.
        self.AddHightlightLine(self.current_insn_address, self.codelines_list.get(self.current_insn_address, 0), EXECUTE_INSN_HILIGHT_COLOR)
        # Set status bar memory range label.
        self.statusbar_memory_range_qlabel.setText(f"(Mem: 0x{range_start:0{self.addr_len}X} ~ 0x{range_end:0{self.addr_len}X})")
        self.HighlightLines()
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

    title = "TimeTravelEmuRegistersViewer"

    class custviewer(ida_kernwin.simplecustviewer_t):
        def __init__(self):
            super().__init__()
            self.dbl_click_callback = None

        def SetDblChickCallback(self, callback):
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

        self.regs_values: Optional[Dict[str, int]] = None # Only SetRegisters() change this value.
        self.regs_patch: Optional[List[str]] = None # Only SetRegsPatch() change this value.


    def InitViewer(self):
        self.viewer.Create(self.title)
        self.viewer_widegt  = ida_kernwin.PluginForm.FormToPyQtWidget(self.viewer.GetWidget())
        self.statusbar_label = QtWidgets.QLabel("State ID: N\\A")

        self._SetCustomViewerStatusBar()


    def SetDblChickCallback(self, callback):
        self.viewer.SetDblChickCallback(callback)


    def _SetCustomViewerStatusBar(self):
        # Remove original status bar
        viewer_status_bar = self.viewer_widegt.findChild(QtWidgets.QStatusBar)
        for widget in viewer_status_bar.findChildren(QtWidgets.QLabel):
            viewer_status_bar.removeWidget(widget)

        viewer_status_bar.addWidget(self.statusbar_label)


    def _RefreshStatusBar(self, state_id: str):
        self.statusbar_label.setText(f"State ID: {state_id}")


    def SetRegisters(self, state_id: str, regs_values: Dict[str, int]):
        self.current_state_id = state_id
        self.regs_values = regs_values
        self._RefreshStatusBar(state_id)


    def SetRegsPatch(self, state_id: str, regs_patch: Optional[Dict[str, int]]):
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
    2. Use self.LoadState() to load memory pages for a specific state.
    3. Add self.viewer_widget to TimeTravelEmuViewer's layout.
    4. Use self.DisplayMemoryRange() to display a specific memory range.
    5. Call TimeTravelEmuViewer.Show() to show the viewer with this subviewer.
    """

    title = "TimeTravelEmuMemoryViewer"
    BYTES_PER_LINE = 16 # How many bytes to display per line in the memory dump

    def __init__(self):
        self.viewer = AddressAwareCustomViewer()
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

        self.hightlighting_lines: List[Tuple[int, int, Optional[int]]] = [] # [(address, address_idx, color),...]


    def InitViewer(self):
        self.viewer.Create(self.title)
        self.viewer_widegt  = ida_kernwin.PluginForm.FormToPyQtWidget(self.viewer.GetWidget())
        self._SetCustomViewerStatusBar()
        self._SetDoubleClickCallback()
        self._SetMenuActions()

    def _SetDoubleClickCallback(self):
        def OnDblClickAction(custom_viewer: AddressAwareCustomViewer):
            """
            Action: If user double-clicks an address, jump to it in IDA View.
            """
            addr = custom_viewer.GetLineNo() # Get the address of the clicked line
            if addr is not None and addr != idaapi.BADADDR:
                return idaapi.jumpto(addr)
            return False

        self.viewer.SetDblChickCallback(OnDblClickAction)

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

    def AddMenuActions(self, action_handler: MenuActionHandler):
        action_handler.parent_title = self.title
        self.viewer.AddAction(action_handler)

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
        if IsSet is not None:
            range_start = form.start_addr
            range_end = form.end_addr
            self.DisplayMemoryRange(range_start, range_end)
        form.Free()

    def _SetCustomViewerStatusBar(self):
        viewer_status_bar = self.viewer_widegt.findChild(QtWidgets.QStatusBar)
        if not viewer_status_bar:
            # Create a new status bar if it doesn't exist (e.g., if simplecustviewer_t doesn't create one by default)
            viewer_status_bar = QtWidgets.QStatusBar()
            self.viewer_widegt.layout().addWidget(viewer_status_bar) # Assuming a layout exists

        # Clear existing widgets from status bar
        for widget in viewer_status_bar.findChildren(QtWidgets.QLabel):
            viewer_status_bar.removeWidget(widget)

        self.statusbar_state_id_qlabel = QtWidgets.QLabel("[State: N\\A ]")
        viewer_status_bar.addWidget(self.statusbar_state_id_qlabel)
        self.statusbar_memory_range_qlabel = QtWidgets.QLabel("(Mem: N\\A )")
        viewer_status_bar.addWidget(self.statusbar_memory_range_qlabel)

    def LoadState(self, state_id: str, memory_pages: Dict[int, Tuple[int, bytearray]]):
        """
        Loads the memory state for display.
        """
        assert self.statusbar_state_id_qlabel, "Status bar not initialized"
        self.current_state_id = state_id
        # Convert the dictionary to a sorted list of (address, (perm, data)) for efficient iteration
        self.memory_pages_list = sorted(memory_pages.items())
        self.statusbar_state_id_qlabel.setText(f"[State: {self.current_state_id} ]")

    def AddHighlightLine(self, address, address_idx, color):
        self.hightlighting_lines.append((address, address_idx, color))

    def HighlightLines(self):
        for address, address_idx, color in self.hightlighting_lines:
            self.viewer.EditLineColor(address, address_idx, None, color) # Set bgcolor

    def ClearHighlightLines(self):
        while len(self.hightlighting_lines) > 0:
            address, address_idx, color = self.hightlighting_lines.pop()
            self.viewer.EditLineColor(address, address_idx, None, None) # Clear bgcolor


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
        self.ClearHighlightLines()

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
                    new_line_text = ColorfulLineGenerator.GenerateMemoryLine(
                        line_start_addr,
                        self.addr_len,
                        line_data_bytes,
                        self.BYTES_PER_LINE,
                        patch_indices_within_line
                    )
                    self.viewer.EditLine(line_start_addr, 0, DATA_LINE, new_line_text, None, None) # Background is handled by COLSTR now
                    self.AddHighlightLine(line_start_addr, 0, CHANGE_HIGHLIGHT_COLOR) # Highlight the whole line

                elif self.current_range_display_start <= line_start_addr < self.current_range_display_end:
                    temp_line_data = bytearray([0] * self.BYTES_PER_LINE)
                    for offset, byte_val in line_patches.items():
                        if offset < self.BYTES_PER_LINE:
                            temp_line_data[offset : offset + len(byte_val)] = byte_val

                    new_line_text = ColorfulLineGenerator.GenerateMemoryLine(
                        line_start_addr,
                        self.addr_len,
                        temp_line_data,
                        self.BYTES_PER_LINE,
                        sorted(line_patches.keys())
                    )
                    self.viewer.AddLine(line_start_addr, DATA_LINE, new_line_text, bgcolor=CHANGE_HIGHLIGHT_COLOR, lazy=True)
                    self.AddHighlightLine(line_start_addr, 0, CHANGE_HIGHLIGHT_COLOR)


        self.HighlightLines() # Apply all collected highlights
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
        self.ClearHighlightLines() # Clear any old highlights as we're rebuilding everything

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
                # If no page covers this address range, it's unknown/unmapped memory
                # line_data remains all zeros (initialized as such)
                pass # Already initialized as zeros.

            line_text = ColorfulLineGenerator.GenerateMemoryLine(
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
        self.state_list: Optional[List[Tuple[str, EmuState]]] = None # List of (state_id, state) formed in order of generation

        self.current_state_idx: int = 0 # Index of current state in state_list.
        self.current_state_id: Optional[str] = None # Only SwitchStateDisplay() can change this value.
        self.current_full_state: Optional[FullEmuState] = None # Only SwitchStateDisplay() can change this value.

        self.current_diffs: Optional[Tuple[Optional[Dict[str, Tuple[int, int]]], Optional[SortedDict], Optional[SortedDict]]] = None

        # configs
        self.follow_current_instruction = False # True # Whether to follow the current instruction when switching states.



    def Init(self):
        self.disassembly_viewer.InitViewer()
        self.registers_viewer.InitViewer()
        self.mempages_viewer.InitViewer()

        self.SetDoubleClickCallback()

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:NextStateAction",
                              self.DisplayNextStateAction, "Next state", NEXT_STATE_ACTION_SHORTCUT))

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:PrevStateAction",
                              self.DisplayPrevStateAction, "Previous state", PREV_STATE_ACTION_SHORTCUT))

        self.disassembly_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.disassembly_viewer.title}:StageInputAction",
                              self.DisplayInputStateAction, "Switch to input state", "S"))

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
                              self.ToggleFollowCurrentInstructionAction, "Toggle follow current instruction (F)", "F"))

        self.mempages_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.mempages_viewer.title}:ChooseMemoryPagesAction",
                              lambda : self.ChooseMemoryPagesAction(self.mempages_viewer.title, self.mempages_viewer.DisplayMemoryRange),   "Choose memory pages", "M"))

        self.mempages_viewer.AddMenuActions(MenuActionHandler(None, lambda : True,
                              f"{self.mempages_viewer.title}:ShowDiffAction",
                              lambda : self.ShowDiffsAciton(self.mempages_viewer.title, self.mempages_viewer.JumpTo),   "Show diff", "D"))



    def SetDoubleClickCallback(self):
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

        self.registers_viewer.SetDblChickCallback(OnDblClickAction)


    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

        self.PopulateForm()


    def OnClose(self, form):
        for sub_chooser in self.subchooser_list:
            if sub_chooser:
                sub_chooser.Close()


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


        main_splitter.addWidget(self.disassembly_viewer.viewer_widegt)


        right_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical) # type: ignore
        right_splitter.setChildrenCollapsible(True)

        right_splitter.addWidget(self.registers_viewer.viewer_widegt)
        right_splitter.addWidget(self.mempages_viewer.viewer_widegt)

        main_splitter.addWidget(right_splitter)

        main_layout = QtWidgets.QVBoxLayout(self.parent)
        main_layout.addWidget(main_splitter)
        main_layout.setContentsMargins(0, 0, 0, 0)


    def DisplayNextStateAction(self):
        assert self.state_list is not None, "No state_list loaded"
        if self.current_state_idx < len(self.state_list) - 1:
            self.current_state_idx += 1
            self.SwitchStateDisplay(self.state_list[self.current_state_idx][0])
        # else:
        #     idaapi.msg("Already at the last state.\n")


    def DisplayPrevStateAction(self):
        assert self.state_list is not None, "No state_list loaded"
        if self.current_state_idx > 0:
            self.current_state_idx -= 1
            self.SwitchStateDisplay(self.state_list[self.current_state_idx][0])
        # else:
        #     idaapi.msg("Already at the first state.\n")


    def DisplayInputStateAction(self):
        assert self.state_manager is not None, "No state_manager loaded"
        assert self.state_list is not None, "No state_list loaded"

        input_str = ida_kernwin.ask_str(self.current_state_id if self.current_state_id else "", 0, "Input state ID:")
        if input_str:
            target_state_idx = next((i for i, (x, y) in enumerate(self.state_list) if x == input_str), -1)
            if target_state_idx >= 0:
                self.current_state_idx = target_state_idx
                self.SwitchStateDisplay(self.state_list[self.current_state_idx][0])
            else:
                idaapi.warning("Input state ID not found")


    def ChooseStatesAction(self):

        class StateChooser(ida_kernwin.Choose):
            def __init__(self, title, state_list: List[Tuple[str, EmuState]], switch_state_display_func):
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
                self.switch_state_display_func = switch_state_display_func


            def OnInit(self):
                self.items = [[str(i),
                        state_id,
                        InstrctionParser().parse_instruction(state.instruction)]
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

        self.states_chooser = StateChooser("State Chooser", self.state_list, self.SwitchStateDisplay)
        self.states_chooser.Show()
        self.subchooser_list.append(self.states_chooser)


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

        self.memory_pages_chooser = MemPageChooser(f"Memory Chooser for {parent_title}", lambda : self.current_full_state, display_memory_range_func)
        self.memory_pages_chooser.Show()
        self.subchooser_list.append(self.memory_pages_chooser)


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
                regs_diff, mem_diff, page_diff = self.get_current_diff_func() # Optional[Tuple[Optional[Dict[str, int]], Optional[SortedDict], Optional[SortedDict]]]
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

        self.diff_chooser = DiffsChooser(
            f"Diffs Chooser for {parent_title}",
            lambda : self.current_diffs, jumpto_address_func)
        self.diff_chooser.Show()
        self.subchooser_list.append(self.diff_chooser)


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


    def SwitchStateDisplay(self, state_id: str):
        assert self.state_manager is not None, "No state_manager loaded"

        # Avoid unnecessary re-rendering if already on this state
        if state_id == self.current_state_id and self.current_full_state is not None:
            return

        target_state = self.state_manager.get_state(state_id)
        if target_state is None:
            idaapi.warning(f"State {state_id} not found in state_manager.")
            return

        target_full_state = target_state.generate_full_state(self.state_manager.states_dict)
        if target_full_state is None:
            idaapi.warning(f"Failed to generate full state for state {state_id}.")
            return

        regs_diff: Optional[Dict[str, Tuple[int, int]]] = None
        mem_diff: Optional[SortedDict] = None # SortedDict[address, (prev_value, new_value)] (single byte)
        page_diff: Optional[SortedDict] = None # SortedDict[page_start_addr, (change_mode, (perm, data))]

        regs_patch: Optional[Dict[str, int]] = None
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


        self.current_diffs = (regs_diff, mem_diff, page_diff)


        # Update Disassembly Viewer
        self.disassembly_viewer.ClearHighlightLines()
        self.disassembly_viewer.LoadState(state_id, target_full_state.instruction_address, target_full_state.memory_pages)
        self.disassembly_viewer.ApplyStatePatchesInViewer(mem_patch, page_diff)

        if self.follow_current_instruction or self.current_state_id is None: # Only jump if it's the first load or follow is enabled
            self.disassembly_viewer.JumpTo(target_full_state.instruction_address)

        # Update Registers Viewer
        self.registers_viewer.SetRegisters(target_full_state.state_id, target_full_state.registers_map)
        self.registers_viewer.SetRegsPatch(target_full_state.state_id, regs_patch)
        self.registers_viewer.DisplayRegisters()

        # Update Memory Viewer (New)
        self.mempages_viewer.LoadState(state_id, target_full_state.memory_pages)
        # If no previous range, default to displaying around the instruction address.
        if self.mempages_viewer.current_range_display_start == -1:
            default_mem_start = (target_full_state.instruction_address // PAGE_SIZE) * PAGE_SIZE
            self.mempages_viewer.DisplayMemoryRange(default_mem_start, default_mem_start + PAGE_SIZE)

        self.mempages_viewer.ApplyStatePatchesInViewer(mem_patch, page_diff)


        self.current_full_state = target_full_state
        self.current_state_id = state_id

        self.RefreshSubviewers() # Refresh Choose dialogs if open








