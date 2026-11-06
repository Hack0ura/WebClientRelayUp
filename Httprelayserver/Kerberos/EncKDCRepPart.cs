// EncKDCRepPart.cs - Decrypted part of AS-REP/TGS-REP
// Adapted from Rubeus (GhostPack) - BSD 3-Clause License


namespace HttpLdapRelay.Kerberos
{
    public class EncKDCRepPart
    {
        public EncryptionKey key;
        public LastReq last_req;
        public uint nonce;
        public DateTime? key_expiration;
        public TicketFlags flags;
        public DateTime authtime;
        public DateTime? starttime;
        public DateTime endtime;
        public DateTime? renew_till;
        public string srealm;
        public PrincipalName sname;

        public static EncKDCRepPart Decode(byte[] data)
        {
            AsnElt ae = AsnElt.Decode(data);
            return Decode(ae);
        }

        public static EncKDCRepPart Decode(AsnElt ae)
        {
            EncKDCRepPart part = new EncKDCRepPart();

            // EncASRepPart is [APPLICATION 25], EncTGSRepPart is [APPLICATION 26]
            AsnElt inner = ae;
            if (ae.TagClass == AsnElt.APPLICATION && (ae.TagValue == 25 || ae.TagValue == 26))
            {
                inner = ae.Sub[0];
            }

            foreach (var sub in inner.Sub)
            {
                if (sub.TagClass == AsnElt.CONTEXT)
                {
                    switch (sub.TagValue)
                    {
                        case 0: // key
                            part.key = EncryptionKey.Decode(sub.Sub[0]);
                            break;
                        case 1: // last-req
                            part.last_req = LastReq.Decode(sub.Sub[0]);
                            break;
                        case 2: // nonce
                            part.nonce = (uint)sub.Sub[0].GetInteger();
                            break;
                        case 3: // key-expiration
                            part.key_expiration = ParseKerberosTime(sub.Sub[0]);
                            break;
                        case 4: // flags
                            part.flags = TicketFlags.Decode(sub.Sub[0]);
                            break;
                        case 5: // authtime
                            part.authtime = ParseKerberosTime(sub.Sub[0]) ?? DateTime.MinValue;
                            break;
                        case 6: // starttime
                            part.starttime = ParseKerberosTime(sub.Sub[0]);
                            break;
                        case 7: // endtime
                            part.endtime = ParseKerberosTime(sub.Sub[0]) ?? DateTime.MaxValue;
                            break;
                        case 8: // renew-till
                            part.renew_till = ParseKerberosTime(sub.Sub[0]);
                            break;
                        case 9: // srealm
                            part.srealm = sub.Sub[0].GetString();
                            break;
                        case 10: // sname
                            part.sname = PrincipalName.Decode(sub.Sub[0]);
                            break;
                    }
                }
            }

            return part;
        }

        private static DateTime? ParseKerberosTime(AsnElt ae)
        {
            if (ae == null || ae.ObjectData == null)
                return null;

            string timeStr = ae.GetString();
            // Format: YYYYMMDDHHmmssZ
            if (timeStr.Length >= 14)
            {
                try
                {
                    int year = int.Parse(timeStr.Substring(0, 4));
                    int month = int.Parse(timeStr.Substring(4, 2));
                    int day = int.Parse(timeStr.Substring(6, 2));
                    int hour = int.Parse(timeStr.Substring(8, 2));
                    int minute = int.Parse(timeStr.Substring(10, 2));
                    int second = int.Parse(timeStr.Substring(12, 2));
                    return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
                }
                catch { }
            }
            return null;
        }
    }

    public class EncryptionKey
    {
        public int keytype;
        public byte[] keyvalue;

        public static EncryptionKey Decode(AsnElt ae)
        {
            EncryptionKey key = new EncryptionKey();

            foreach (var sub in ae.Sub)
            {
                if (sub.TagClass == AsnElt.CONTEXT)
                {
                    switch (sub.TagValue)
                    {
                        case 0:
                            key.keytype = sub.Sub[0].GetInteger();
                            break;
                        case 1:
                            key.keyvalue = sub.Sub[0].GetOctetString();
                            break;
                    }
                }
            }

            return key;
        }

        public AsnElt Encode()
        {
            return AsnElt.MakeSequence(
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(keytype)),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 1, AsnElt.MakeOctetString(keyvalue))
            );
        }
    }

    public class LastReq
    {
        public List<LastReqEntry> entries;

        public static LastReq Decode(AsnElt ae)
        {
            LastReq lr = new LastReq();
            lr.entries = new List<LastReqEntry>();

            if (ae.Sub != null)
            {
                foreach (var sub in ae.Sub)
                {
                    lr.entries.Add(LastReqEntry.Decode(sub));
                }
            }

            return lr;
        }
    }

    public class LastReqEntry
    {
        public int lr_type;
        public DateTime lr_value;

        public static LastReqEntry Decode(AsnElt ae)
        {
            LastReqEntry entry = new LastReqEntry();

            foreach (var sub in ae.Sub)
            {
                if (sub.TagClass == AsnElt.CONTEXT)
                {
                    switch (sub.TagValue)
                    {
                        case 0:
                            entry.lr_type = sub.Sub[0].GetInteger();
                            break;
                        case 1:
                            string timeStr = sub.Sub[0].GetString();
                            // Parse GeneralizedTime
                            break;
                    }
                }
            }

            return entry;
        }
    }

    public class TicketFlags
    {
        public uint flags;

        // Flag constants
        public const uint RESERVED = 0x80000000;
        public const uint FORWARDABLE = 0x40000000;
        public const uint FORWARDED = 0x20000000;
        public const uint PROXIABLE = 0x10000000;
        public const uint PROXY = 0x08000000;
        public const uint MAY_POSTDATE = 0x04000000;
        public const uint POSTDATED = 0x02000000;
        public const uint INVALID = 0x01000000;
        public const uint RENEWABLE = 0x00800000;
        public const uint INITIAL = 0x00400000;
        public const uint PRE_AUTHENT = 0x00200000;
        public const uint HW_AUTHENT = 0x00100000;
        public const uint OK_AS_DELEGATE = 0x00040000;
        public const uint NAME_CANONICALIZE = 0x00010000;

        public static TicketFlags Decode(AsnElt ae)
        {
            TicketFlags tf = new TicketFlags();

            byte[] data = ae.ObjectData;
            if (data != null && data.Length > 1)
            {
                // First byte is unused bits count
                int unusedBits = data[0];
                
                // Convert remaining bytes to flags (big-endian)
                tf.flags = 0;
                for (int i = 1; i < data.Length && i < 5; i++)
                {
                    tf.flags = (tf.flags << 8) | data[i];
                }
            }

            return tf;
        }

        public AsnElt Encode()
        {
            byte[] data = new byte[5];
            data[0] = 0; // No unused bits
            data[1] = (byte)((flags >> 24) & 0xFF);
            data[2] = (byte)((flags >> 16) & 0xFF);
            data[3] = (byte)((flags >> 8) & 0xFF);
            data[4] = (byte)(flags & 0xFF);

            return new AsnElt
            {
                TagClass = AsnElt.UNIVERSAL,
                TagValue = AsnElt.BIT_STRING,
                Constructed = false,
                ObjectData = data
            };
        }

        public override string ToString()
        {
            List<string> flagNames = new List<string>();
            if ((flags & FORWARDABLE) != 0) flagNames.Add("forwardable");
            if ((flags & FORWARDED) != 0) flagNames.Add("forwarded");
            if ((flags & PROXIABLE) != 0) flagNames.Add("proxiable");
            if ((flags & PROXY) != 0) flagNames.Add("proxy");
            if ((flags & MAY_POSTDATE) != 0) flagNames.Add("may-postdate");
            if ((flags & POSTDATED) != 0) flagNames.Add("postdated");
            if ((flags & INVALID) != 0) flagNames.Add("invalid");
            if ((flags & RENEWABLE) != 0) flagNames.Add("renewable");
            if ((flags & INITIAL) != 0) flagNames.Add("initial");
            if ((flags & PRE_AUTHENT) != 0) flagNames.Add("pre-authent");
            if ((flags & HW_AUTHENT) != 0) flagNames.Add("hw-authent");
            if ((flags & OK_AS_DELEGATE) != 0) flagNames.Add("ok-as-delegate");
            if ((flags & NAME_CANONICALIZE) != 0) flagNames.Add("name-canonicalize");
            return string.Join(", ", flagNames);
        }
    }
}
