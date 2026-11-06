// PA_PK_AS_REQ.cs - PKINIT Pre-Authentication Data
// Adapted from Rubeus (GhostPack) - BSD 3-Clause License
// Uses System.Security.Cryptography.Pkcs for CMS SignedData

using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace HttpLdapRelay.Kerberos
{
    public class PA_PK_AS_REQ
    {
        private X509Certificate2 _certificate;
        private KDCKeyAgreement _agreement;
        private byte[] _reqBodyHash;
        private uint _nonce;
        private DateTime _ctime;
        private int _cusec;
        private bool _verifyCerts;

        // OID for PKINIT AuthData content type
        public static readonly Oid PkinitAuthDataOid = new Oid("1.3.6.1.5.2.3.1");

        public PA_PK_AS_REQ(X509Certificate2 cert, KDCKeyAgreement agreement, byte[] reqBodyHash,
                           uint nonce, DateTime ctime, int cusec, bool verifyCerts = false)
        {
            _certificate = cert;
            _agreement = agreement;
            _reqBodyHash = reqBodyHash;
            _nonce = nonce;
            _ctime = ctime;
            _cusec = cusec;
            _verifyCerts = verifyCerts;
        }

        public KDCKeyAgreement Agreement => _agreement;

        public byte[] Encode()
        {
            // Build AuthPack
            byte[] authPack = BuildAuthPack();

            // Sign AuthPack using CMS SignedData
            byte[] signedAuthPack = SignAuthPack(authPack);

            // Build PA-PK-AS-REQ structure
            // PA-PK-AS-REQ ::= SEQUENCE {
            //   signedAuthPack [0] IMPLICIT OCTET STRING,
            //   trustedCertifiers [1] SEQUENCE OF ExternalPrincipalIdentifier OPTIONAL,
            //   kdcPkId [2] IMPLICIT OCTET STRING OPTIONAL
            // }

            // [0] IMPLICIT OCTET STRING means:
            // - Replace the OCTET STRING tag (04) with context tag [0]
            // - Since content is raw bytes (not constructed), use primitive form (0x80)
            var signedAuthPackElement = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                AsnElt.MakeOctetString(signedAuthPack));

            var paPkAsReq = AsnElt.MakeSequence(signedAuthPackElement);
            return paPkAsReq.Encode();
        }

        private byte[] BuildAuthPack()
        {
            // AuthPack ::= SEQUENCE {
            //   pkAuthenticator [0] PKAuthenticator,
            //   clientPublicValue [1] SubjectPublicKeyInfo OPTIONAL,
            //   supportedCMSTypes [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
            //   clientDHNonce [3] DHNonce OPTIONAL
            // }

            // PKAuthenticator ::= SEQUENCE {
            //   cusec [0] INTEGER,
            //   ctime [1] KerberosTime,
            //   nonce [2] INTEGER,
            //   paChecksum [3] OCTET STRING OPTIONAL
            // }

            var pkAuthenticator = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(_cusec)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeGeneralizedTime(_ctime)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeInteger(_nonce)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, AsnElt.MakeOctetString(_reqBodyHash))
            );

            // clientPublicValue - DH public key
            var clientPublicValue = _agreement.EncodeSubjectPublicKeyInfo();

            var authPack = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, pkAuthenticator),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, clientPublicValue)
            );

            return authPack.Encode();
        }

        private byte[] SignAuthPack(byte[] authPack)
        {
            // Use System.Security.Cryptography.Pkcs to create CMS SignedData
            // Content type is id-pkinit-authData (1.3.6.1.5.2.3.1)

            ContentInfo contentInfo = new ContentInfo(PkinitAuthDataOid, authPack);
            SignedCms signedCms = new SignedCms(contentInfo, false); // false = include content

            // Create signer info
            CmsSigner signer = new CmsSigner(_certificate);
            signer.DigestAlgorithm = new Oid("1.3.14.3.2.26"); // SHA1
            signer.IncludeOption = X509IncludeOption.EndCertOnly;

            // Compute signature
            try
            {
                signedCms.ComputeSignature(signer, false); // false = not silent
            }
            catch (CryptographicException ex)
            {
                // If we get "Keyset does not exist", the certificate might need to be
                // loaded with Exportable flag and added to a temp store
                throw new Exception($"Failed to sign AuthPack: {ex.Message}. " +
                    "Make sure the certificate has an exportable private key.", ex);
            }

            return signedCms.Encode();
        }
    }

    public class PA_PK_AS_REP
    {
        public DHRepInfo DHRepInfo { get; set; }

        public static PA_PK_AS_REP Decode(byte[] data)
        {
            // PA-PK-AS-REP ::= CHOICE {
            //   dhInfo [0] DHRepInfo,
            //   encKeyPack [1] IMPLICIT OCTET STRING
            // }

            AsnElt ae = AsnElt.Decode(data);
            PA_PK_AS_REP rep = new PA_PK_AS_REP();
            if (ae.TagClass == AsnElt.CONTEXT && ae.TagValue == 0)
            {
                // DHRepInfo - [0] is EXPLICIT, so the actual DHRepInfo SEQUENCE is inside
                AsnElt dhRepInfoSeq = ae;
                if (ae.Constructed && ae.Sub != null && ae.Sub.Length > 0)
                {
                    dhRepInfoSeq = ae.Sub[0];
                }
                rep.DHRepInfo = DHRepInfo.Decode(dhRepInfoSeq);
            }
            else
            {
                Console.WriteLine($"[!] Unexpected PA-PK-AS-REP format");
            }

            return rep;
        }
    }

    public class DHRepInfo
    {
        public byte[] DHSignedData { get; set; }
        public byte[] ServerDHNonce { get; set; }
        public KDCDHKeyInfo KDCDHKeyInfo { get; set; }

        public static DHRepInfo Decode(AsnElt ae)
        {
            DHRepInfo info = new DHRepInfo();

            // DHRepInfo ::= SEQUENCE {
            //   dhSignedData [0] IMPLICIT OCTET STRING,
            //   serverDHNonce [1] DHNonce OPTIONAL,
            //   ...
            // }
            if (ae.Sub != null)
            {
                foreach (var sub in ae.Sub)
                {

                    if (sub.TagClass == AsnElt.CONTEXT)
                    {
                        switch (sub.TagValue)
                        {
                            case 0:
                                // [0] IMPLICIT OCTET STRING - the SignedData is directly in the tag
                                // For IMPLICIT, the content is the raw data
                                if (sub.Constructed && sub.Sub != null && sub.Sub.Length > 0)
                                {
                                    // If constructed, we need to get the actual content
                                    info.DHSignedData = sub.Sub[0].Encode();
                                    // Actually, for CMS SignedData which is a SEQUENCE, 
                                    // we need to re-encode the whole structure
                                    info.DHSignedData = sub.Encode();
                                    // Remove the context tag wrapper - rebuild as SEQUENCE
                                    List<byte> rebuilt = new List<byte>();
                                    rebuilt.Add(0x30); // SEQUENCE tag
                                    // Get length
                                    byte[] innerContent = new byte[0];
                                    if (sub.Sub != null)
                                    {
                                        List<byte> inner = new List<byte>();
                                        foreach (var s in sub.Sub)
                                            inner.AddRange(s.Encode());
                                        innerContent = inner.ToArray();
                                    }
                                    // Encode length
                                    if (innerContent.Length < 0x80)
                                    {
                                        rebuilt.Add((byte)innerContent.Length);
                                    }
                                    else if (innerContent.Length < 0x100)
                                    {
                                        rebuilt.Add(0x81);
                                        rebuilt.Add((byte)innerContent.Length);
                                    }
                                    else
                                    {
                                        rebuilt.Add(0x82);
                                        rebuilt.Add((byte)(innerContent.Length >> 8));
                                        rebuilt.Add((byte)(innerContent.Length & 0xFF));
                                    }
                                    rebuilt.AddRange(innerContent);
                                    info.DHSignedData = rebuilt.ToArray();
                                }
                                else
                                {
                                    info.DHSignedData = sub.ObjectData;
                                }
                                // Parse the CMS SignedData to get the KDC DH key
                                info.ParseDHSignedData();
                                break;
                            case 1:
                                // serverDHNonce
                                if (sub.Constructed && sub.Sub != null && sub.Sub.Length > 0)
                                {
                                    info.ServerDHNonce = sub.Sub[0].ObjectData;
                                }
                                else
                                {
                                    info.ServerDHNonce = sub.ObjectData;
                                }
                                break;
                        }
                    }
                }
            }

            return info;
        }

        private void ParseDHSignedData()
        {
            if (DHSignedData == null || DHSignedData.Length == 0)
            {
                Console.WriteLine("[!] DHSignedData is null or empty");
                return;
            }

            try
            {
                // Parse CMS SignedData
                SignedCms signedCms = new SignedCms();
                signedCms.Decode(DHSignedData);
                // Get the content (KDCDHKeyInfo)
                byte[] content = signedCms.ContentInfo.Content;

                if (content != null && content.Length > 0)
                {
                    KDCDHKeyInfo = KDCDHKeyInfo.Decode(content);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to parse DHSignedData as CMS: {ex.Message}");

                // Try parsing as raw ASN.1 (in case it's not wrapped in CMS)
                try
                {
                    KDCDHKeyInfo = KDCDHKeyInfo.Decode(DHSignedData);
                }
                catch (Exception ex2)
                {
                    Console.WriteLine($"[!] Raw ASN.1 parse also failed: {ex2.Message}");
                }
            }
        }
    }

    public class KDCDHKeyInfo
    {
        public byte[] SubjectPublicKey { get; set; }
        public uint Nonce { get; set; }
        public DateTime? DHKeyExpiration { get; set; }

        public static KDCDHKeyInfo Decode(byte[] data)
        {
            // KDCDHKeyInfo ::= SEQUENCE {
            //   subjectPublicKey [0] BIT STRING,
            //   nonce [1] INTEGER (0..4294967295),
            //   dhKeyExpiration [2] KerberosTime OPTIONAL,
            //   ...
            // }



            AsnElt ae = AsnElt.Decode(data);
            KDCDHKeyInfo info = new KDCDHKeyInfo();


            if (ae.Sub != null)
            {
                foreach (var sub in ae.Sub)
                {

                    if (sub.TagClass == AsnElt.CONTEXT)
                    {
                        switch (sub.TagValue)
                        {
                            case 0:
                                // [0] BIT STRING containing the DH public key
                                // The BIT STRING contains a DER-encoded INTEGER
                                byte[] bitString = null;

                                if (sub.Constructed && sub.Sub != null && sub.Sub.Length > 0)
                                {
                                    // EXPLICIT tag - BIT STRING is inside
                                    var bitStringElt = sub.Sub[0];
                                    bitString = bitStringElt.ObjectData;
                                }
                                else
                                {
                                    // IMPLICIT or direct
                                    bitString = sub.ObjectData;
                                }

                                if (bitString != null && bitString.Length > 1)
                                {
                                    // First byte of BIT STRING is unused bits count
                                    int unusedBits = bitString[0];

                                    // Rest is the DER-encoded INTEGER
                                    byte[] derInteger = new byte[bitString.Length - 1];
                                    Array.Copy(bitString, 1, derInteger, 0, bitString.Length - 1);


                                    // Parse the DER INTEGER to get raw bytes
                                    try
                                    {
                                        AsnElt pkAe = AsnElt.Decode(derInteger);
                                        if (pkAe.TagValue == AsnElt.INTEGER)
                                        {
                                            info.SubjectPublicKey = pkAe.ObjectData;
                                        }
                                        else
                                        {
                                            info.SubjectPublicKey = derInteger;
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        info.SubjectPublicKey = derInteger;
                                    }
                                }
                                break;

                            case 1:
                                // nonce
                                AsnElt nonceElt = sub;
                                if (sub.Constructed && sub.Sub != null && sub.Sub.Length > 0)
                                {
                                    nonceElt = sub.Sub[0];
                                }
                                info.Nonce = (uint)nonceElt.GetInteger();
                                break;

                            case 2:
                                // dhKeyExpiration (optional)
                                break;
                        }
                    }
                }
            }

            return info;
        }
    }
}