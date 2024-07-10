import idaapi
import ida_kernwin
import idc
import idaapi
import idautils
from lib.PringGUID import GUID
CONTEXT_MENU_PATH = 'Kiwi/'
ITEM_NAME = 'PrintGUID'


class handler_class(idaapi.action_handler_t):
    def activate(self,ctx):
        """
        This function reads 16 bytes from the specified address and interprets them as a GUID.
        """
        ea = idc.get_screen_ea()
        GUID.printGUID(ea)
    def update(self, ctx):
        pass

class ContextHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        tft = idaapi.get_widget_type(form)
        if tft == idaapi.BWN_DISASM:
            action_name_xorhex = idaapi.action_desc_t(
                None, ITEM_NAME, handler_class()
            )
            idaapi.attach_dynamic_action_to_popup(
                form,
                popup,
                action_name_xorhex,
                CONTEXT_MENU_PATH,
                idaapi.SETMENU_INS,
            )
        elif tft == idaapi.BWN_PSEUDOCODE:
            pass

hooks = ContextHooks()
hooks.hook()
