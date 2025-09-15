## Author: @xorhex
## Copyright: 2024

__author__ = "https://infosec.exchange/@xorhex"

import idaapi
import idautils
import idc

from idaextras.Helpers import get_ida_version
from idaextras.Logger import Logger
from idaextras.IDAExtrasListExportsForm import ExportListUI

ida_ver = get_ida_version()
if ida_ver >= 9.2:
  from PySide6 import QtCore
  from PySide6 import QtGui
  from PySide6 import QtWidgets
  bwn_hex = idaapi.BWN_HEXVIEW
else:
  from PyQt5 import QtCore
  from PyQt5 import QtGui
  from PyQt5 import QtWidgets
  bwn_hex = idaapi.BWN_DUMP

import struct

ACTION_NAME_IDA_EXTRAS = "idaextras"

logger = Logger()


## Custom Export Window

CUSTOM_EXPORT_WINDOW_DISPLAY_NAME = f"exports"
CUSTOM_EXPORT_WINDOW = f"{ACTION_NAME_IDA_EXTRAS}:{CUSTOM_EXPORT_WINDOW_DISPLAY_NAME}"

class ExportsDisplay(idaapi.action_handler_t):
  def __init__(self):
    idaapi.action_handler_t.__init__(self)
    self.exports = ExportListUI()

  def activate(self, ctx):
      self.exports.Show(f"IDA Extras: {CUSTOM_EXPORT_WINDOW_DISPLAY_NAME.title()}")

  def update(self, ctx):
    return idaapi.AST_ENABLE_ALWAYS

if idaapi.register_action(idaapi.action_desc_t(
  CUSTOM_EXPORT_WINDOW,
  CUSTOM_EXPORT_WINDOW_DISPLAY_NAME.title(),
  ExportsDisplay(),
  "Ctrl-Alt-E")):
  idaapi.attach_action_to_menu("View/IDA Extras Views/", CUSTOM_EXPORT_WINDOW, idaapi.SETMENU_INS)
  logger.log(CUSTOM_EXPORT_WINDOW, "register_action", "Attached")
else:
  idaapi.unregister_action(CUSTOM_EXPORT_WINDOW)


class context_handler_copy_bytes(idaapi.action_handler_t):
  def __init__(self):
    super().__init__()

  def activate(self, ctx):
    ea = idc.read_selection_start()
    bites = []
    
    instr_bites = idaapi.get_bytes(ea, idc.read_selection_end() - idc.read_selection_start())
    for b in instr_bites:
      bites.append(f'{b:02x}')

    cb = QtWidgets.QApplication.instance().clipboard()
    cb.clear(mode = cb.Clipboard)
    cb.setText(f'{" ".join(bites)}', mode=cb.Clipboard)

  def update(self, ctx):
    return super().update(ctx)

### Region
#### Helper Functions
#### Convert hard coded data into sockaddr_in.sin_port and sockaddr_in.sin_addr types
def dword_to_ip(dword: int) -> str:
  ip = []
  for x in range(4):
    ip.append(str((dword >> (8 * x)) & 0xff))
  return '.'.join(ip)

def is_valid_ip(ip: str) -> bool:
  """
  This function is not perfect as an IP address can end in 255 but the likelyhood that a
  threat actor is using it is low as it's reserved.  Same with IP addresses that start
  with 0.
  """
  parts = ip.split('.')
  if len(parts) != 4:
    return False
  if int(parts[0], 10) == 0x0:
    return False
  if int(parts[3], 10) == 0xff:
    return False
  return True

def word_to_port(word: int) -> str:
  return str(struct.unpack('>H', struct.pack('<H', word))[0])
### End Region

class context_handler_set_cmt(idaapi.action_handler_t):
  def __init__(self, value):
    super().__init__()
    self.value= value

  def activate(self, ctx):
    idaapi.set_cmt(idaapi.get_screen_ea(), self.value, False)

  def update(self, ctx):
    return super().update(ctx)

class ContextHooks(idaapi.UI_Hooks):
  def finish_populating_widget_popup(self, form, popup) -> None:
    flags = idaapi.get_flags(idaapi.get_screen_ea())
    if idaapi.get_widget_type(form) in [idaapi.BWN_DISASM, bwn_hex]:
      if idc.read_selection_start() != idaapi.BADADDR and idc.read_selection_end() != idaapi.BADADDR:
        ## This is a quick simple context menu item to Copy Bytes (native functionality is Shift+E)
        action_copy_bytes = idaapi.action_desc_t(None, f"Copy Bytes", context_handler_copy_bytes())
        idaapi.attach_dynamic_action_to_popup(form, popup, action_copy_bytes, None, idaapi.SETMENU_FIRST)
    if idaapi.get_widget_type(form) in [idaapi.BWN_DISASM]:
      if idaapi.is_code(flags):
        if not idaapi.is_defarg(flags, idaapi.get_opnum()) or idaapi.is_numop(flags, idaapi.get_opnum()):
          instr = idautils.DecodeInstruction(idaapi.get_screen_ea())
          op = instr.ops[idaapi.get_opnum()]
          if op.type == idaapi.o_imm:
            if op.dtype == idaapi.dt_dword:
              ip = dword_to_ip(op.value & 0xffffffff)
              if is_valid_ip(ip):
                action_dword_to_ipv4 = idaapi.action_desc_t(None, f"sockaddr_in.sin_addr: {ip}", context_handler_set_cmt(ip))
                idaapi.attach_dynamic_action_to_popup(form, popup, action_dword_to_ipv4, "Manual", idaapi.SETMENU_INS)
            if op.dtype == idaapi.dt_word or (op.dtype == idaapi.dt_dword and op.value < 0x10000):
              action_word_to_port = idaapi.action_desc_t(None, f"sockaddr_in.sin_port: {word_to_port(op.value & 0xffff)}", context_handler_set_cmt(word_to_port(op.value & 0xffff)))
              idaapi.attach_dynamic_action_to_popup(form, popup, action_word_to_port, "Manual", idaapi.SETMENU_INS)


hooks = ContextHooks()
hooks.hook()
