// AS_REP.cs - Kerberos AS-REP message parsing
// Adapted from Rubeus (GhostPack) - BSD 3-Clause License

namespace HttpLdapRelay.Kerberos
{
    public class AS_REP
    {
        public int pvno;
        public int msg_type;
        public List<PA_DATA> padata;
        public string crealm;
        public PrincipalName cname;
        public Ticket ticket;
        public EncryptedData enc_part;

        public static AS_REP Decode(byte[] data)
        {
            AsnElt ae = AsnElt.Decode(data);
            return Decode(ae);
        }

        public static AS_REP Decode(AsnElt ae)
        {
            // AS-REP ::= [APPLICATION 11] KDC-REP
            if (ae.TagClass != AsnElt.APPLICATION || ae.TagValue != 11)
            {
                throw new Exception($"Expected AS-REP (APPLICATION 11), got tag class {ae.TagClass}, value {ae.TagValue}");
            }

            AS_REP rep = new AS_REP();
            
            // Get the inner SEQUENCE
            AsnElt kdcRep = ae.Sub[0];

            foreach (var sub in kdcRep.Sub)
            {
                if (sub.TagClass == AsnElt.CONTEXT)
                {
                    switch (sub.TagValue)
                    {
                        case 0: // pvno
                            rep.pvno = sub.Sub[0].GetInteger();
                            break;
                        case 1: // msg-type
                            rep.msg_type = sub.Sub[0].GetInteger();
                            break;
                        case 2: // padata
                            rep.padata = new List<PA_DATA>();
                            foreach (var paElt in sub.Sub[0].Sub)
                            {
                                rep.padata.Add(PA_DATA.Decode(paElt));
                            }
                            break;
                        case 3: // crealm
                            rep.crealm = sub.Sub[0].GetString();
                            break;
                        case 4: // cname
                            rep.cname = PrincipalName.Decode(sub.Sub[0]);
                            break;
                        case 5: // ticket
                            rep.ticket = Ticket.Decode(sub.Sub[0]);
                            break;
                        case 6: // enc-part
                            rep.enc_part = EncryptedData.Decode(sub.Sub[0]);
                            break;
                    }
                }
            }

            return rep;
        }
    }

    public class KRB_ERROR
    {
        public int pvno;
        public int msg_type;
        public DateTime? ctime;
        public int? cusec;
        public DateTime stime;
        public int susec;
        public int error_code;
        public string crealm;
        public PrincipalName cname;
        public string realm;
        public PrincipalName sname;
        public string e_text;
        public byte[] e_data;

        public static KRB_ERROR Decode(byte[] data)
        {
            AsnElt ae = AsnElt.Decode(data);
            return Decode(ae);
        }

        public static KRB_ERROR Decode(AsnElt ae)
        {
            // KRB-ERROR ::= [APPLICATION 30] SEQUENCE
            if (ae.TagClass != AsnElt.APPLICATION || ae.TagValue != 30)
            {
                throw new Exception($"Expected KRB-ERROR (APPLICATION 30), got tag class {ae.TagClass}, value {ae.TagValue}");
            }

            KRB_ERROR err = new KRB_ERROR();
            AsnElt errSeq = ae.Sub[0];

            foreach (var sub in errSeq.Sub)
            {
                if (sub.TagClass == AsnElt.CONTEXT)
                {
                    switch (sub.TagValue)
                    {
                        case 0: // pvno
                            err.pvno = sub.Sub[0].GetInteger();
                            break;
                        case 1: // msg-type
                            err.msg_type = sub.Sub[0].GetInteger();
                            break;
                        case 2: // ctime
                            // Optional - parse if present
                            break;
                        case 3: // cusec
                            // Optional
                            break;
                        case 4: // stime
                            // Parse GeneralizedTime
                            break;
                        case 5: // susec
                            err.susec = sub.Sub[0].GetInteger();
                            break;
                        case 6: // error-code
                            err.error_code = sub.Sub[0].GetInteger();
                            break;
                        case 7: // crealm
                            err.crealm = sub.Sub[0].GetString();
                            break;
                        case 8: // cname
                            err.cname = PrincipalName.Decode(sub.Sub[0]);
                            break;
                        case 9: // realm
                            err.realm = sub.Sub[0].GetString();
                            break;
                        case 10: // sname
                            err.sname = PrincipalName.Decode(sub.Sub[0]);
                            break;
                        case 11: // e-text
                            err.e_text = sub.Sub[0].GetString();
                            break;
                        case 12: // e-data
                            err.e_data = sub.Sub[0].GetOctetString();
                            break;
                    }
                }
            }

            return err;
        }

        public string GetErrorMessage()
        {
            if (Enum.IsDefined(typeof(Interop.KERBEROS_ERROR), (uint)error_code))
            {
                return ((Interop.KERBEROS_ERROR)error_code).ToString();
            }
            return $"UNKNOWN ({error_code})";
        }
    }

    public class Ticket
    {
        public int tkt_vno;
        public string realm;
        public PrincipalName sname;
        public EncryptedData enc_part;
        
        private byte[] _rawBytes;

        public byte[] RawBytes => _rawBytes;

        public static Ticket Decode(AsnElt ae)
        {
            Ticket ticket = new Ticket();
            ticket._rawBytes = ae.Encode();

            // Ticket ::= [APPLICATION 1] SEQUENCE {
            //   tkt-vno [0] INTEGER,
            //   realm [1] Realm,
            //   sname [2] PrincipalName,
            //   enc-part [3] EncryptedData
            // }

            AsnElt inner = ae;
            if (ae.TagClass == AsnElt.APPLICATION && ae.TagValue == 1)
            {
                inner = ae.Sub[0];
            }

            foreach (var sub in inner.Sub)
            {
                if (sub.TagClass == AsnElt.CONTEXT)
                {
                    switch (sub.TagValue)
                    {
                        case 0:
                            ticket.tkt_vno = sub.Sub[0].GetInteger();
                            break;
                        case 1:
                            ticket.realm = sub.Sub[0].GetString();
                            break;
                        case 2:
                            ticket.sname = PrincipalName.Decode(sub.Sub[0]);
                            break;
                        case 3:
                            ticket.enc_part = EncryptedData.Decode(sub.Sub[0]);
                            break;
                    }
                }
            }

            return ticket;
        }

        public AsnElt Encode()
        {
            if (_rawBytes != null)
            {
                return AsnElt.Decode(_rawBytes);
            }

            var inner = AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(tkt_vno)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeGeneralString(realm)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, sname.Encode()),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 3, enc_part.Encode())
            );

            return new AsnElt
            {
                TagClass = AsnElt.APPLICATION,
                TagValue = 1,
                Constructed = true,
                Sub = new AsnElt[] { inner }
            };
        }
    }

    public class EncryptedData
    {
        public int etype;
        public int? kvno;
        public byte[] cipher;

        public static EncryptedData Decode(AsnElt ae)
        {
            EncryptedData ed = new EncryptedData();

            foreach (var sub in ae.Sub)
            {
                if (sub.TagClass == AsnElt.CONTEXT)
                {
                    switch (sub.TagValue)
                    {
                        case 0:
                            ed.etype = sub.Sub[0].GetInteger();
                            break;
                        case 1:
                            ed.kvno = sub.Sub[0].GetInteger();
                            break;
                        case 2:
                            ed.cipher = sub.Sub[0].GetOctetString();
                            break;
                    }
                }
            }

            return ed;
        }

        public AsnElt Encode()
        {
            var elements = new List<AsnElt>();
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(etype)));
            if (kvno.HasValue)
            {
                elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeInteger(kvno.Value)));
            }
            elements.Add(AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeOctetString(cipher)));
            return AsnElt.MakeSequence(elements.ToArray());
        }
    }

    // Extension for PrincipalName decoding
    public partial class PrincipalName
    {
        public static PrincipalName Decode(AsnElt ae)
        {
            Interop.PRINCIPAL_TYPE nameType = 0;
            List<string> names = new List<string>();

            foreach (var sub in ae.Sub)
            {
                if (sub.TagClass == AsnElt.CONTEXT)
                {
                    switch (sub.TagValue)
                    {
                        case 0:
                            nameType = (Interop.PRINCIPAL_TYPE)sub.Sub[0].GetInteger();
                            break;
                        case 1:
                            foreach (var nameElt in sub.Sub[0].Sub)
                            {
                                names.Add(nameElt.GetString());
                            }
                            break;
                    }
                }
            }

            return new PrincipalName(nameType, names.ToArray());
        }
    }
}
