using System.Runtime.InteropServices;


namespace HttpLdapRelay
{
    /// <summary>
    /// Helper methods to trigger WebClient start
    /// </summary>
    public class WebClientTrigger
    {
        static public int _attempt = 0;

        // Code stolen from https://github.com/eversinc33/SharpStartWebclient/blob/main/SharpStartWebclient/Program.cs
        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public class EVENT_DESCRIPTOR
        {
            [FieldOffset(0)]
            ushort Id = 1;
            [FieldOffset(2)]
            byte Version = 0;
            [FieldOffset(3)]
            byte Channel = 0;
            [FieldOffset(4)]
            byte Level = 4;
            [FieldOffset(5)]
            byte Opcode = 0;
            [FieldOffset(6)]
            ushort Task = 0;
            [FieldOffset(8)]
            long Keyword = 0;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public struct EventData
        {
            [FieldOffset(0)]
            internal UInt16 DataPointer;
            [FieldOffset(8)]
            internal uint Size;
            [FieldOffset(12)]
            internal int Reserved;
        }

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern uint EventRegister(ref Guid guid, IntPtr EnableCallback, IntPtr CallbackContext, ref long RegHandle);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern unsafe uint EventWrite(long RegHandle, ref EVENT_DESCRIPTOR EventDescriptor, uint UserDataCount, EventData* UserData);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern uint EventUnregister(long RegHandle);


        // =============== STRUCTURES ===============

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NETRESOURCE
        {
            public int dwScope;
            public int dwType;
            public int dwDisplayType;
            public int dwUsage;
            public string lpLocalName;
            public string lpRemoteName;
            public string lpComment;
            public string lpProvider;
        }

        // =============== P/INVOKE ===============

        [DllImport("mpr.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int WNetAddConnection2(
            ref NETRESOURCE lpNetResource,
            string lpPassword,
            string lpUsername,
            int dwFlags
        );

        [DllImport("mpr.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int WNetCancelConnection2(
            string lpName,
            int dwFlags,
            bool fForce
        );

        // =============== PUBLIC METHODS ===============

        /// <summary>
        /// Start WebClient service if not running
        /// </summary>
        public static bool EnsureWebClientRunning()
        {
            try
            {
                if(_attempt >= 1)
                {
                    Console.WriteLine("[*] New attempt to start WebClient service.");
                }
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "sc",
                        Arguments = "query webclient",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                if (output.Contains("RUNNING"))
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] WebClient service is running");
                    Console.ResetColor();
                    return true;
                }
                else
                {
                    Console.WriteLine("[!] WebClient service is not running");
                    _attempt += 1;
                    forceWebClientStart();
                    Console.WriteLine("[*] Waiting 2 seconds for service to start...");
                    Thread.Sleep(2000);
                    if (_attempt >= 3)
                    {
                        Console.WriteLine("[-] Failed to star WebClient service.");
                        return false;
                    }
                    else
                    {
                        return EnsureWebClientRunning();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error checking WebClient status: {ex.Message}");
                return false;
            }
        }

        public static bool forceWebClientStart()
        {
            Console.WriteLine($"[*] Trying to force the start of WebClient (if Manual trigger is enabled, it should work)");
            // Code stolen from https://github.com/eversinc33/SharpStartWebclient/blob/main/SharpStartWebclient/Program.cs
            Guid WebClientTrigger = new Guid(0x22B6D684, 0xFA63, 0x4578, 0x87, 0xC9, 0xEF, 0xFC, 0xBE, 0x66, 0x43, 0xC7);
            long RegistrationHandle = 0;

            if (EventRegister(ref WebClientTrigger, IntPtr.Zero, IntPtr.Zero, ref RegistrationHandle) == 0)
            {
                EVENT_DESCRIPTOR EventDescriptor = new EVENT_DESCRIPTOR();

                unsafe
                {
                    EventWrite(RegistrationHandle, ref EventDescriptor, 0, null);
                    EventUnregister(RegistrationHandle);
                }

                Console.WriteLine("[*] Webclient should be started now");
            }
            return true;
        }

    }
}