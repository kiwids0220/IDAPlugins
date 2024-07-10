import idaapi
import ida_kernwin
import idc
import idaapi
import idautils
class GUID:
    def printGUID(ea):
        """
        This function reads 16 bytes from the specified address and interprets them as a GUID.
        """
        ea = idc.get_screen_ea()

        guid_bytes = idaapi.get_bytes(ea, 16)
        if not guid_bytes:
            return None

        # GUID is structured as {4-2-2-2-6} byte fields
        if guid_bytes:
            data1 = int.from_bytes(guid_bytes[:4], 'little')
            data2 = int.from_bytes(guid_bytes[4:6], 'little')
            data3 = int.from_bytes(guid_bytes[6:8], 'little')
            data4 = guid_bytes[8:10]
            data5 = guid_bytes[10:16]
        
        guid_str = f'{data1:08X}-{data2:04X}-{data3:04X}-{data4.hex().upper()}-{data5.hex().upper()}'

        if guid_str:
            ida_kernwin.msg("GUID at cursor: {}\n".format(guid_str))
            return guid_str
        else:
            ida_kernwin.msg("Failed to read GUID at cursor.\n")
            return False

if __name__ == "__main__":
    pass