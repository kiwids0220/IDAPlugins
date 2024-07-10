import idaapi
import ida_kernwin
import idc
import idautils
import re

CONTEXT_MENU_PATH = 'Kiwi/'
ITEM_NAME = 'SearchWPP'


class handler_class(idaapi.action_handler_t):
    def activate(self, ctx):
        """
        This function searches the .rdata section for symbols with names like WPP_ followed by 32 hexadecimal characters.
        It prompts the user to choose whether to save the output to a file or print it out.
        """
        # Find the .rdata section
        rdata_start = None
        rdata_end = None
        for seg in idautils.Segments():
            if idc.get_segm_name(seg) == '.rdata':
                rdata_start = idc.get_segm_start(seg)
                rdata_end = idc.get_segm_end(seg)
                break

        if rdata_start is None or rdata_end is None:
            ida_kernwin.msg(".rdata section not found.\n")
            return False
        # Search for symbols that match the pattern in the .rdata section
        results = []
        for name in idautils.Names():
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
