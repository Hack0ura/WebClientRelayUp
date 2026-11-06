// AS_REQ.cs - Kerberos AS-REQ message construction for PKINIT
// Adapted from Rubeus (GhostPack) - BSD 3-Clause License

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HttpLdapRelay.Kerberos
{
    public class AS_REQ
    {
        public int pvno = 5;
        public int msg_type = Interop.AS_REQ;
        public List<PA_DATA> padata;
        public KDC_REQ_BODY req_body;

        // For PKINIT
        public PA_PK_AS_REQ PkAsReq { get; private set; }

        // Constructor for PKINIT
        public AS_REQ(string userName, string domain, X509Certificate2 cert, KDCKeyAgreement agreement,
                      Interop.KERB_ETYPE etype, bool verifyCerts = false, string service = null)
        {
            padata = new List<PA_DATA>();

            // Build req-body first (needed for paChecksum)
            req_body = new KDC_REQ_BODY();
            req_body.cname = new PrincipalName(Interop.PRINCIPAL_TYPE.NT_PRINCIPAL, userName);
            req_body.realm = domain.ToUpper();

            if (string.IsNullOrEmpty(service))
            {
                req_body.sname = new PrincipalName(Interop.PRINCIPAL_TYPE.NT_SRV_INST, "krbtgt", domain.ToUpper());
            }
            else
            {
                req_body.sname = new PrincipalName(Interop.PRINCIPAL_TYPE.NT_SRV_INST, service.Split('/'));
            }

            req_body.till = DateTime.UtcNow.AddDays(1);
            req_body.rtime = DateTime.UtcNow.AddDays(7);
            req_body.nonce = GenerateNonce();

            // KDC options
            req_body.kdcOptions = Interop.KdcOptions.FORWARDABLE |
                                  Interop.KdcOptions.RENEWABLE |
                                  Interop.KdcOptions.RENEWABLEOK;

            // Encryption types
            req_body.etypes = new List<Interop.KERB_ETYPE>();
            req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
            req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
            req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);

            // Compute paChecksum = SHA1(req-body encoded)
            byte[] reqBodyBytes = req_body.Encode();
            byte[] paChecksum;
            using (var sha1 = SHA1.Create())
            {
                paChecksum = sha1.ComputeHash(reqBodyBytes);
            }

            // Build PKINIT PA-DATA
            DateTime ctime = DateTime.UtcNow;
            int cusec = ctime.Millisecond * 1000;

            PkAsReq = new PA_PK_AS_REQ(cert, agreement, paChecksum, req_body.nonce, ctime, cusec, verifyCerts);

            // Add PA-PK-AS-REQ (padata-type = 16)
            padata.Add(new PA_DATA(Interop.PADATA_TYPE.PA_PK_AS_REQ, PkAsReq.Encode()));

            // Add PA-PAC-REQUEST (padata-type = 128) - request PAC
            var pacRequest = new PA_PAC_REQUEST(true);
            padata.Add(new PA_DATA(Interop.PADATA_TYPE.PA_PAC_REQUEST, pacRequest.Encode()));
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

        public byte[] Encode()
        {
            // AS-REQ ::= [APPLICATION 10] KDC-REQ
            // KDC-REQ ::= SEQUENCE {
            //   pvno [1] INTEGER,
            //   msg-type [2] INTEGER,
            //   padata [3] SEQUENCE OF PA-DATA OPTIONAL,
            //   req-body [4] KDC-REQ-BODY
            // }

            List<AsnElt> kdcReqElements = new List<AsnElt>();

            // pvno [1]
            kdcReqElements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeInteger(pvno)));

            // msg-type [2]
            kdcReqElements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeInteger(msg_type)));

            // padata [3]
            if (padata != null && padata.Count > 0)
            {
                List<AsnElt> padataElements = new List<AsnElt>();
                foreach (var pa in padata)
                {
                    padataElements.Add(pa.Encode());
                }
                var padataSeq = AsnElt.MakeSequence(padataElements.ToArray());
                kdcReqElements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, padataSeq));
            }

            // req-body [4]
            kdcReqElements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 4,
                AsnElt.Decode(req_body.Encode()))); // Re-decode to get proper structure

            var kdcReq = AsnElt.MakeSequence(kdcReqElements.ToArray());

            // Wrap in APPLICATION 10 tag
            var asReq = new AsnElt
            {
                TagClass = AsnElt.APPLICATION,
                TagValue = 10,
                Constructed = true,
                Sub = new AsnElt[] { kdcReq }
            };

            return asReq.Encode();
        }
    }

    public class KDC_REQ_BODY
    {
        public Interop.KdcOptions kdcOptions;
        public PrincipalName cname;
        public string realm;
        public PrincipalName sname;
        public DateTime? from;
        public DateTime till;
        public DateTime? rtime;
        public uint nonce;
        public List<Interop.KERB_ETYPE> etypes;

        public byte[] Encode()
        {
            // KDC-REQ-BODY ::= SEQUENCE {
            //   kdc-options [0] KDCOptions,
            //   cname [1] PrincipalName OPTIONAL,
            //   realm [2] Realm,
            //   sname [3] PrincipalName OPTIONAL,
            //   from [4] KerberosTime OPTIONAL,
            //   till [5] KerberosTime,
            //   rtime [6] KerberosTime OPTIONAL,
            //   nonce [7] UInt32,
            //   etype [8] SEQUENCE OF Int32,
            //   ...
            // }

            List<AsnElt> elements = new List<AsnElt>();

            // kdc-options [0] - 4 bytes bit string
            byte[] kdcOptionsBytes = BitConverter.GetBytes((uint)kdcOptions);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(kdcOptionsBytes);
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeBitString(kdcOptionsBytes)));

            // cname [1]
            if (cname != null)
            {
                elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, cname.Encode()));
            }

            // realm [2]
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeGeneralString(realm)));

            // sname [3]
            if (sname != null)
            {
                elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, sname.Encode()));
            }

            // from [4] - optional

            // till [5]
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 5, AsnElt.MakeGeneralizedTime(till)));

            // rtime [6]
            if (rtime.HasValue)
            {
                elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 6, AsnElt.MakeGeneralizedTime(rtime.Value)));
            }

            // nonce [7]
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 7, AsnElt.MakeInteger(nonce)));

            // etype [8]
            List<AsnElt> etypeElements = new List<AsnElt>();
            foreach (var etype in etypes)
            {
                etypeElements.Add(AsnElt.MakeInteger((int)etype));
            }
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 8, AsnElt.MakeSequence(etypeElements.ToArray())));

            return AsnElt.MakeSequence(elements.ToArray()).Encode();
        }
    }

    public partial class PrincipalName
    {
        public Interop.PRINCIPAL_TYPE name_type;
        public List<string> name_string;

        public PrincipalName(Interop.PRINCIPAL_TYPE type, params string[] names)
        {
            name_type = type;
            name_string = new List<string>(names);
        }

        public AsnElt Encode()
        {
            // PrincipalName ::= SEQUENCE {
            //   name-type [0] Int32,
            //   name-string [1] SEQUENCE OF KerberosString
            // }

            List<AsnElt> nameStrings = new List<AsnElt>();
            foreach (var name in name_string)
            {
                nameStrings.Add(AsnElt.MakeGeneralString(name));
            }

            return AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger((int)name_type)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeSequence(nameStrings.ToArray()))
            );
        }
    }

    public class PA_DATA
    {
        public Interop.PADATA_TYPE type;
        public byte[] value;

        public PA_DATA(Interop.PADATA_TYPE type, byte[] value)
        {
            this.type = type;
            this.value = value;
        }

        public AsnElt Encode()
        {
            // PA-DATA ::= SEQUENCE {
            //   padata-type [1] Int32,
            //   padata-value [2] OCTET STRING
            // }

            return AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeInteger((int)type)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeOctetString(value))
            );
        }

        public static PA_DATA Decode(AsnElt ae)
        {
            Interop.PADATA_TYPE type = 0;
            byte[] value = null;

            if (ae.Sub != null)
            {
                foreach (var sub in ae.Sub)
                {
                    if (sub.TagClass == AsnElt.CONTEXT)
                    {
                        switch (sub.TagValue)
                        {
                            case 1:
                                type = (Interop.PADATA_TYPE)sub.Sub[0].GetInteger();
                                break;
                            case 2:
                                value = sub.Sub[0].GetOctetString();
                                break;
                        }
                    }
                }
            }

            return new PA_DATA(type, value);
        }
    }

    public class PA_PAC_REQUEST
    {
        public bool include_pac;

        public PA_PAC_REQUEST(bool includePac)
        {
            include_pac = includePac;
        }

        public byte[] Encode()
        {
            // KERB-PA-PAC-REQUEST ::= SEQUENCE {
            //   include-pac [0] BOOLEAN
            // }
            return AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeBool(include_pac))
            ).Encode();
        }
    }
}