# IDAPlugins

## What Is This
A repo storing all IDA Python scripts that I often use.

## How To Use
Credit to [gaasedelen](https://github.com/gaasedelen) for the installation steps


1. From your disassembler's python console, run the following command to find its plugin directory:

IDA Pro: 
    ```
    import idaapi, os; os.path.join(idaapi.get_user_idadir(), "plugins")
    ```

2. Copy the contents of this repository's /plugins/ folder to the listed directory.

3. Restart your disassembler.

The scripts are tested on IDA Pro 8.3

## List of Scripts
- PrintGUID.py - Prints out the GUID bytes pointed by the cursor
- PrintBytes.py - Prints out the number of bytes specified by the user at the cursor location
- SaveAllSymbol.py - Saves all symbols by name and ea addresses in a txt file
- SaveAllWPPGUIDs.py - Saves all WPP_* trace log providers GUIDs in a txt file or print them out to the IDA console