// AsnElt.cs - Simplified ASN.1 encoding/decoding
// Inspired by DDer library used in Rubeus (MIT-like license)

using System.Text;

namespace HttpLdapRelay.Kerberos
{
    public class AsnElt
    {
        // Tag classes
        public const int UNIVERSAL = 0;
        public const int APPLICATION = 1;
        public const int CONTEXT = 2;
        public const int PRIVATE = 3;

        // Universal tags
        public const int BOOLEAN = 1;
        public const int INTEGER = 2;
        public const int BIT_STRING = 3;
        public const int OCTET_STRING = 4;
        public const int NULL = 5;
        public const int OBJECT_IDENTIFIER = 6;
        public const int UTF8String = 12;
        public const int SEQUENCE = 16;
        public const int SET = 17;
        public const int PrintableString = 19;
        public const int IA5String = 22;
        public const int UTCTime = 23;
        public const int GeneralizedTime = 24;
        public const int GeneralString = 27;

        public int TagClass { get; set; }
        public int TagValue { get; set; }
        public bool Constructed { get; set; }
        public byte[] ObjectData { get; set; }
        public AsnElt[] Sub { get; set; }

        // Decode from bytes
        public static AsnElt Decode(byte[] data)
        {
            return Decode(data, 0, data.Length);
        }

        public static AsnElt Decode(byte[] data, int offset, int length)
        {
            int off = offset;
            int end = offset + length;

            if (off >= end)
                throw new Exception("ASN.1: truncated object");

            int tag = data[off++];
            int tagClass = tag >> 6;
            bool constructed = (tag & 0x20) != 0;
            int tagValue = tag & 0x1F;

            if (tagValue == 0x1F)
            {
                tagValue = 0;
                while (true)
                {
                    if (off >= end)
                        throw new Exception("ASN.1: truncated tag");
                    int c = data[off++];
                    tagValue = (tagValue << 7) | (c & 0x7F);
                    if ((c & 0x80) == 0)
                        break;
                }
            }

            if (off >= end)
                throw new Exception("ASN.1: truncated length");

            int len = data[off++];
            if (len >= 0x80)
            {
                int lenLen = len - 0x80;
                if (lenLen > 4)
                    throw new Exception("ASN.1: unsupported length");
                len = 0;
                while (lenLen-- > 0)
                {
                    if (off >= end)
                        throw new Exception("ASN.1: truncated length");
                    len = (len << 8) | data[off++];
                }
            }

            if (len > (end - off))
                throw new Exception("ASN.1: truncated value");

            AsnElt ae = new AsnElt();
            ae.TagClass = tagClass;
            ae.TagValue = tagValue;
            ae.Constructed = constructed;

            if (constructed)
            {
                List<AsnElt> subs = new List<AsnElt>();
                int subOff = off;
                int subEnd = off + len;
                while (subOff < subEnd)
                {
                    AsnElt sub = Decode(data, subOff, subEnd - subOff);
                    subs.Add(sub);
                    subOff += sub.EncodedLength();
                }
                ae.Sub = subs.ToArray();
            }
            else
            {
                ae.ObjectData = new byte[len];
                Array.Copy(data, off, ae.ObjectData, 0, len);
            }

            return ae;
        }

        public int EncodedLength()
        {
            int contentLen = GetContentLength();
            int tagLen = GetTagLength();
            int lenLen = GetLengthOfLength(contentLen);
            return tagLen + lenLen + contentLen;
        }

        private int GetTagLength()
        {
            if (TagValue < 31)
                return 1;
            int n = 1;
            int v = TagValue;
            while (v > 0)
            {
                n++;
                v >>= 7;
            }
            return n;
        }

        private int GetContentLength()
        {
            if (Sub != null && Sub.Length > 0)
            {
                int len = 0;
                foreach (var sub in Sub)
                    len += sub.EncodedLength();
                return len;
            }
            return ObjectData?.Length ?? 0;
        }

        private static int GetLengthOfLength(int len)
        {
            if (len < 0x80) return 1;
            if (len < 0x100) return 2;
            if (len < 0x10000) return 3;
            if (len < 0x1000000) return 4;
            return 5;
        }

        public byte[] Encode()
        {
            List<byte> result = new List<byte>();

            // Encode tag
            int tag = (TagClass << 6) | (Constructed ? 0x20 : 0) | (TagValue < 31 ? TagValue : 0x1F);
            result.Add((byte)tag);
            if (TagValue >= 31)
            {
                List<byte> tagBytes = new List<byte>();
                int v = TagValue;
                tagBytes.Add((byte)(v & 0x7F));
                v >>= 7;
                while (v > 0)
                {
                    tagBytes.Add((byte)((v & 0x7F) | 0x80));
                    v >>= 7;
                }
                tagBytes.Reverse();
                result.AddRange(tagBytes);
            }

            // Get content
            byte[] content;
            if (Sub != null && Sub.Length > 0)
            {
                List<byte> c = new List<byte>();
                foreach (var sub in Sub)
                    c.AddRange(sub.Encode());
                content = c.ToArray();
            }
            else
            {
                content = ObjectData ?? new byte[0];
            }

            // Encode length
            int len = content.Length;
            if (len < 0x80)
            {
                result.Add((byte)len);
            }
            else if (len < 0x100)
            {
                result.Add(0x81);
                result.Add((byte)len);
            }
            else if (len < 0x10000)
            {
                result.Add(0x82);
                result.Add((byte)(len >> 8));
                result.Add((byte)(len & 0xFF));
            }
            else if (len < 0x1000000)
            {
                result.Add(0x83);
                result.Add((byte)(len >> 16));
                result.Add((byte)((len >> 8) & 0xFF));
                result.Add((byte)(len & 0xFF));
            }
            else
            {
                result.Add(0x84);
                result.Add((byte)(len >> 24));
                result.Add((byte)((len >> 16) & 0xFF));
                result.Add((byte)((len >> 8) & 0xFF));
                result.Add((byte)(len & 0xFF));
            }

            result.AddRange(content);
            return result.ToArray();
        }

        // Factory methods
        public static AsnElt MakeSequence(params AsnElt[] elements)
        {
            return new AsnElt
            {
                TagClass = UNIVERSAL,
                TagValue = SEQUENCE,
                Constructed = true,
                Sub = elements
            };
        }

        public static AsnElt MakeImplicit(int tagClass, int tagValue, AsnElt inner)
        {
            AsnElt ae = new AsnElt();
            ae.TagClass = tagClass;
            ae.TagValue = tagValue;
            
            if (inner.Constructed)
            {
                ae.Constructed = true;
                ae.Sub = inner.Sub;
            }
            else
            {
                ae.Constructed = false;
                ae.ObjectData = inner.ObjectData;
            }
            return ae;
        }

        public static AsnElt MakeExplicit(int tagClass, int tagValue, AsnElt inner)
        {
            return new AsnElt
            {
                TagClass = tagClass,
                TagValue = tagValue,
                Constructed = true,
                Sub = new AsnElt[] { inner }
            };
        }

        public static AsnElt MakeInteger(long value)
        {
            List<byte> bytes = new List<byte>();
            if (value == 0)
            {
                bytes.Add(0);
            }
            else if (value > 0)
            {
                while (value > 0)
                {
                    bytes.Insert(0, (byte)(value & 0xFF));
                    value >>= 8;
                }
                if ((bytes[0] & 0x80) != 0)
                    bytes.Insert(0, 0);
            }
            else
            {
                while (value < -1)
                {
                    bytes.Insert(0, (byte)(value & 0xFF));
                    value >>= 8;
                }
                bytes.Insert(0, (byte)(value & 0xFF));
            }

            return new AsnElt
            {
                TagClass = UNIVERSAL,
                TagValue = INTEGER,
                Constructed = false,
                ObjectData = bytes.ToArray()
            };
        }

        public static AsnElt MakeInteger(byte[] value)
        {
            List<byte> bytes = value.ToList();
            // Remove leading zeros but keep at least one byte
            while (bytes.Count > 1 && bytes[0] == 0)
                bytes.RemoveAt(0);
            // Add leading zero if high bit set
            if ((bytes[0] & 0x80) != 0)
                bytes.Insert(0, 0);

            return new AsnElt
            {
                TagClass = UNIVERSAL,
                TagValue = INTEGER,
                Constructed = false,
                ObjectData = bytes.ToArray()
            };
        }

        public static AsnElt MakeOctetString(byte[] data)
        {
            return new AsnElt
            {
                TagClass = UNIVERSAL,
                TagValue = OCTET_STRING,
                Constructed = false,
                ObjectData = data
            };
        }

        public static AsnElt MakeBitString(byte[] data)
        {
            byte[] withPadding = new byte[data.Length + 1];
            withPadding[0] = 0; // no unused bits
            Array.Copy(data, 0, withPadding, 1, data.Length);

            return new AsnElt
            {
                TagClass = UNIVERSAL,
                TagValue = BIT_STRING,
                Constructed = false,
                ObjectData = withPadding
            };
        }

        public static AsnElt MakeGeneralString(string s)
        {
            return new AsnElt
            {
                TagClass = UNIVERSAL,
                TagValue = GeneralString,
                Constructed = false,
                ObjectData = Encoding.ASCII.GetBytes(s)
            };
        }

        public static AsnElt MakeGeneralizedTime(DateTime dt)
        {
            string s = dt.ToUniversalTime().ToString("yyyyMMddHHmmss") + "Z";
            return new AsnElt
            {
                TagClass = UNIVERSAL,
                TagValue = GeneralizedTime,
                Constructed = false,
                ObjectData = Encoding.ASCII.GetBytes(s)
            };
        }

        public static AsnElt MakeOID(string oid)
        {
            string[] parts = oid.Split('.');
            List<byte> bytes = new List<byte>();

            int v0 = int.Parse(parts[0]);
            int v1 = int.Parse(parts[1]);
            bytes.Add((byte)(v0 * 40 + v1));

            for (int i = 2; i < parts.Length; i++)
            {
                int v = int.Parse(parts[i]);
                if (v < 128)
                {
                    bytes.Add((byte)v);
                }
                else
                {
                    List<byte> enc = new List<byte>();
                    while (v > 0)
                    {
                        enc.Insert(0, (byte)((v & 0x7F) | (enc.Count > 0 ? 0x80 : 0)));
                        v >>= 7;
                    }
                    bytes.AddRange(enc);
                }
            }

            return new AsnElt
            {
                TagClass = UNIVERSAL,
                TagValue = OBJECT_IDENTIFIER,
                Constructed = false,
                ObjectData = bytes.ToArray()
            };
        }

        public static AsnElt MakeBool(bool value)
        {
            return new AsnElt
            {
                TagClass = UNIVERSAL,
                TagValue = BOOLEAN,
                Constructed = false,
                ObjectData = new byte[] { (byte)(value ? 0xFF : 0x00) }
            };
        }

        // Accessors
        public int GetInteger()
        {
            if (ObjectData == null || ObjectData.Length == 0)
                return 0;

            int val = 0;
            bool negative = (ObjectData[0] & 0x80) != 0;
            
            foreach (byte b in ObjectData)
            {
                val = (val << 8) | b;
            }
            
            return val;
        }

        public string GetString()
        {
            if (ObjectData == null)
                return "";
            return Encoding.ASCII.GetString(ObjectData);
        }

        public byte[] GetOctetString()
        {
            return ObjectData ?? new byte[0];
        }

        public byte[] CopyValue()
        {
            if (ObjectData != null)
            {
                byte[] copy = new byte[ObjectData.Length];
                Array.Copy(ObjectData, copy, ObjectData.Length);
                return copy;
            }
            return new byte[0];
        }

        // Find sub-element by context tag
        public AsnElt FirstElement
        {
            get { return (Sub != null && Sub.Length > 0) ? Sub[0] : null; }
        }
    }
}
