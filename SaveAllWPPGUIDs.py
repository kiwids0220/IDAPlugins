import idaapi
import ida_kernwin
import idc
import idautils
import re
from lib.PringGUID import GUID

CONTEXT_MENU_PATH = 'Kiwi/'
ITEM_NAME = 'SearchWPP'

class handler_class(idaapi.action_handler_t):
    def activate(self, ctx):
        """
        This function searches the .rdata section for symbols with names like WPP_ followed by 32 hexadecimal characters.
        It prompts the user to choose whether to save the output to a file or print it out.
        """
        pattern = ida_kernwin.ask_str("", 0, "Enter Regex Pattern")
        if not pattern:
            ida_kernwin.msg(r"Regex pattern not provided. Using the default pattern ^WPP_[0-9A-Fa-f]{32}\n")
            pattern = r'^WPP_[0-9A-Fa-f]{32}'
        try:
            compiled_pattern = re.compile(pattern)
        except re.error as e:
            ida_kernwin.msg(f"Invalid regex pattern: {str(e)}\n")
            return False

        # Search for symbols that match the pattern in the .rdata section
        results = []
        for name in idautils.Names():
            if compiled_pattern.search(name[1]):
                results.append(name)

        if results:
            # Prompt the user to choose action: save to file or print out
            choice = ida_kernwin.ask_buttons(
                        "Yes",
                        "Hell No",
                        "",
                        ida_kernwin.ASKBTN_YES,
                       "Do you WISH to save the output in a file?"
                    )
            
            if choice == ida_kernwin.ASKBTN_YES:  # Save to file
                save_path = ida_kernwin.ask_file(False, "*.txt", "Save output to file")
                if save_path:
                    try:
                        with open(save_path, 'w') as f:
                            f.write("Found symbols:\n")
                            for addr, name in results:
                                f.write(f"{name} at {addr:X}\n")
                                guid = GUID.printGUID(addr)
                                f.write(guid)
                        ida_kernwin.msg(f"Output saved to: {save_path}\n")
                    except Exception as e:
                        ida_kernwin.msg(f"Failed to save output: {str(e)}\n")
                else:
                    ida_kernwin.msg("File save operation cancelled.\n")
            
            else:  # Print out
                ida_kernwin.msg("Found symbols:\n")
                for addr, name in results:
                    ida_kernwin.msg(f"{name} at {addr:X}\n")
      

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
