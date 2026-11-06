// KDCKeyAgreement.cs - Diffie-Hellman Key Agreement for PKINIT
// Adapted from Rubeus (GhostPack) - BSD 3-Clause License

using System.Numerics;
using System.Security.Cryptography;

namespace HttpLdapRelay.Kerberos
{
    public class KDCKeyAgreement
    {
        // RFC 2409 MODP Group 2 (1024-bit)
        private static readonly byte[] MODP2_P = HexToBytes(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
            "FFFFFFFFFFFFFFFF");

        private static readonly byte[] MODP2_G = new byte[] { 0x02 };

        private static readonly byte[] MODP2_Q = HexToBytes(
            "7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68" +
            "948127044533E63A0105DF531D89CD9128A5043CC71A026E" +
            "F7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122" +
            "F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6" +
            "F71C35FDAD44CFD2D74F9208BE258FF324943328F67329C0" +
            "FFFFFFFFFFFFFFFF");

        private BigInteger _p;
        private BigInteger _g;
        private BigInteger _q;
        private BigInteger _privateKey;
        private BigInteger _publicKey;

        public byte[] P => MODP2_P;
        public byte[] G => MODP2_G;
        public byte[] Q => MODP2_Q;

        public KDCKeyAgreement()
        {
            _p = new BigInteger(MODP2_P, true, true);
            _g = new BigInteger(MODP2_G, true, true);
            _q = new BigInteger(MODP2_Q, true, true);

            GenerateKeyPair();
        }

        private void GenerateKeyPair()
        {
            // Generate random private key in range [2, q-2]
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] privBytes = new byte[MODP2_Q.Length];
                rng.GetBytes(privBytes);

                BigInteger privCandidate = new BigInteger(privBytes, true, true);
                _privateKey = (privCandidate % (_q - 2)) + 2;
            }

            // Compute public key: g^x mod p
            _publicKey = BigInteger.ModPow(_g, _privateKey, _p);
        }

        public byte[] PublicKey
        {
            get
            {
                byte[] pubKeyBytes = _publicKey.ToByteArray(true, true);

                // Pad to 128 bytes (1024 bits) if needed
                if (pubKeyBytes.Length < 128)
                {
                    byte[] padded = new byte[128];
                    Array.Copy(pubKeyBytes, 0, padded, 128 - pubKeyBytes.Length, pubKeyBytes.Length);
                    return padded;
                }

                return pubKeyBytes;
            }
        }

        /// <summary>
        /// Generate the session key from the KDC's public key
        /// This matches Rubeus implementation exactly
        /// </summary>
        public byte[] GenerateKey(byte[] kdcPublicKey, byte[] clientDHNonce, byte[] serverDHNonce, int keySize)
        {
            // Remove leading zeros from KDC public key (DepadLeft)
            byte[] kdcPubKeyDepadded = DepadLeft(kdcPublicKey);

            // Parse KDC's public key as big-endian unsigned
            BigInteger kdcPubKey = new BigInteger(kdcPubKeyDepadded, true, true);

            // Compute shared secret: (KDC_pub)^x mod p
            BigInteger sharedSecret = BigInteger.ModPow(kdcPubKey, _privateKey, _p);

            // Convert to bytes (big-endian, unsigned)
            byte[] sharedSecretBytes = sharedSecret.ToByteArray(true, true);

            // Pad to 128 bytes if needed (MODP Group 2 is 1024-bit)
            if (sharedSecretBytes.Length < 128)
            {
                byte[] padded = new byte[128];
                Array.Copy(sharedSecretBytes, 0, padded, 128 - sharedSecretBytes.Length, sharedSecretBytes.Length);
                sharedSecretBytes = padded;
            }

            // Derive key using PKINIT key derivation (RFC 4556)
            // K = truncate(SHA1(x-data), keySize)
            // where x-data = DHSharedSecret | serverDHNonce (if present)
            return OctetString2Key(sharedSecretBytes, serverDHNonce, keySize);
        }

        /// <summary>
        /// PKINIT key derivation function according to RFC 4556 section 3.2.3.1
        /// octetstring2key(x) = random-to-key(K-truncate(SHA1(0x00 | x) | SHA1(0x01 | x) | ...))
        /// </summary>
        private byte[] OctetString2Key(byte[] sharedSecret, byte[] serverDHNonce, int keySize)
        {
            // Build x-data = DHSharedSecret | serverDHNonce (if present)
            byte[] xData;

            if (serverDHNonce != null && serverDHNonce.Length > 0)
            {
                xData = new byte[sharedSecret.Length + serverDHNonce.Length];
                Array.Copy(sharedSecret, 0, xData, 0, sharedSecret.Length);
                Array.Copy(serverDHNonce, 0, xData, sharedSecret.Length, serverDHNonce.Length);
            }
            else
            {
                xData = sharedSecret;
            }

            // RFC 4556: K = truncate(SHA1(0x00 | x) | SHA1(0x01 | x) | ..., keySize)
            // Counter is a SINGLE BYTE at the beginning
            byte[] key = new byte[keySize];
            int offset = 0;

            using (var sha1 = SHA1.Create())
            {
                for (byte counter = 0; offset < keySize; counter++)
                {
                    // Hash: SHA1(counter || x-data)
                    // counter is a single byte: 0x00, 0x01, 0x02, ...
                    byte[] input = new byte[1 + xData.Length];
                    input[0] = counter;
                    Array.Copy(xData, 0, input, 1, xData.Length);

                    byte[] hash = sha1.ComputeHash(input);

                    int toCopy = Math.Min(hash.Length, keySize - offset);
                    Array.Copy(hash, 0, key, offset, toCopy);
                    offset += toCopy;
                }
            }
            return key;
        }

        /// <summary>
        /// Remove leading zero bytes from array
        /// </summary>
        private static byte[] DepadLeft(byte[] data)
        {
            if (data == null || data.Length == 0)
                return data;

            int startIndex = 0;
            while (startIndex < data.Length - 1 && data[startIndex] == 0)
                startIndex++;

            if (startIndex == 0)
                return data;

            byte[] result = new byte[data.Length - startIndex];
            Array.Copy(data, startIndex, result, 0, result.Length);
            return result;
        }

        // Build the SubjectPublicKeyInfo ASN.1 structure
        public AsnElt EncodeSubjectPublicKeyInfo()
        {
            // AlgorithmIdentifier for DH
            // OID: 1.2.840.10046.2.1 (dhpublicnumber)
            var algOid = AsnElt.MakeOID("1.2.840.10046.2.1");

            // DomainParameters ::= SEQUENCE {
            //   p INTEGER,
            //   g INTEGER,
            //   q INTEGER OPTIONAL
            // }
            // NOTE: NO context tags! These are plain INTEGERs
            var domainParams = AsnElt.MakeSequence(
                AsnElt.MakeInteger(MODP2_P),
                AsnElt.MakeInteger(MODP2_G),
                AsnElt.MakeInteger(MODP2_Q)
            );

            var algId = AsnElt.MakeSequence(algOid, domainParams);

            // subjectPublicKey is BIT STRING containing INTEGER (public key value)
            var pubKeyInt = AsnElt.MakeInteger(PublicKey);
            var subjectPublicKey = AsnElt.MakeBitString(pubKeyInt.Encode());

            // SubjectPublicKeyInfo ::= SEQUENCE {
            //   algorithm AlgorithmIdentifier,
            //   subjectPublicKey BIT STRING
            // }
            return AsnElt.MakeSequence(algId, subjectPublicKey);
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }
    }

    // Extension method to remove leading zeros from byte array
    public static class ByteArrayExtensions
    {
        public static byte[] DepadLeft(this byte[] data)
        {
            if (data == null || data.Length == 0)
                return data;

            int startIndex = 0;
            while (startIndex < data.Length - 1 && data[startIndex] == 0)
                startIndex++;

            if (startIndex == 0)
                return data;

            byte[] result = new byte[data.Length - startIndex];
            Array.Copy(data, startIndex, result, 0, result.Length);
            return result;
        }
    }
}