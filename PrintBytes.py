import idaapi
import ida_kernwin
import idc
import idautils

CONTEXT_MENU_PATH = 'Kiwi/'
ITEM_NAME = 'PrintBytes'


class handler_class(idaapi.action_handler_t):
    def activate(self, ctx):
        """
        This function prompts the user for the number of bytes to read from the specified address and prints them.
        """
        ea = idc.get_screen_ea()

        # Prompt the user for the number of bytes
        num_bytes = ida_kernwin.ask_long(16, "Enter the number of bytes to print:")
        if num_bytes is None or num_bytes <= 0:
            ida_kernwin.msg("Invalid number of bytes entered.\n")
            return False

        byte_data = idaapi.get_bytes(ea, num_bytes)
        if not byte_data:
            ida_kernwin.msg("Failed to read bytes at cursor.\n")
            return False

        # Print the bytes in hex format
        byte_str = ' '.join(f'{b:02X}' for b in byte_data)
        ida_kernwin.msg(f"Bytes at cursor ({num_bytes} bytes): {byte_str}\n")
        return True

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ContextHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        tft = idaapi.get_widget_type(form)
        if tft == idaapi.BWN_DISASM:
            action_desc = idaapi.action_desc_t(
                None, ITEM_NAME, handler_class()
            )
            idaapi.attach_dynamic_action_to_popup(
                form,
                popup,
                action_desc,
                CONTEXT_MENU_PATH,
                idaapi.SETMENU_INS,
            )
        elif tft == idaapi.BWN_PSEUDOCODE:
            pass


hooks = ContextHooks()
hooks.hook()
