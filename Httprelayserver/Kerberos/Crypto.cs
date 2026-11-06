// Crypto.cs - RFC 3961 Kerberos Crypto Implementation
// Corrected NFold and key derivation for AES encryption types

using System.Security.Cryptography;

namespace HttpLdapRelay.Kerberos
{
    /// <summary>
    /// RFC 3961 Kerberos Crypto Implementation
    /// Corrected NFold and key derivation for AES encryption types
    /// </summary>
    public static class Crypto
    {
        #region Key Usage Constants (RFC 4120 Section 7.5.1)

        public const int KU_PA_ENC_TS = 1;           // PA-ENC-TIMESTAMP
        public const int KU_TICKET = 2;              // Ticket (for TGS)
        public const int KU_AS_REP_ENCPART = 3;      // AS-REP EncPart
        public const int KU_TGS_REQ_AUTH = 7;        // TGS-REQ Authenticator
        public const int KU_TGS_REQ_AUTHDATA = 8;    // TGS-REQ AuthData subkey
        public const int KU_TGS_REP_ENCPART = 8;     // TGS-REP EncPart (session key)
        public const int KU_TGS_REP_ENCPART_SUB = 9; // TGS-REP EncPart (subkey)
        public const int KU_AP_REQ_AUTH = 11;        // AP-REQ Authenticator
        public const int KU_AP_REP_ENCPART = 12;     // AP-REP EncPart
        public const int KU_KRB_CRED_ENCPART = 14;   // KRB-CRED EncPart
        public const int KU_KRB_SAFE_CKSUM = 15;     // KRB-SAFE checksum

        #endregion

        #region High-Level Decrypt/Encrypt Methods

        /// <summary>
        /// Decrypt Kerberos ciphertext using the appropriate algorithm
        /// </summary>
        /// <param name="key">Session or service key</param>
        /// <param name="ciphertext">Encrypted data (includes HMAC)</param>
        /// <param name="etype">Encryption type</param>
        /// <param name="keyUsage">Key usage number</param>
        /// <returns>Decrypted plaintext</returns>
        public static byte[] Decrypt(byte[] key, byte[] ciphertext, Interop.KERB_ETYPE etype, int keyUsage)
        {
            switch (etype)
            {
                case Interop.KERB_ETYPE.aes256_cts_hmac_sha1:
                case Interop.KERB_ETYPE.aes128_cts_hmac_sha1:
                    return DecryptAesCts(key, ciphertext, keyUsage);

                case Interop.KERB_ETYPE.rc4_hmac:
                    return DecryptRc4Hmac(key, ciphertext, keyUsage);

                default:
                    throw new NotSupportedException($"Encryption type {etype} not supported");
            }
        }

        /// <summary>
        /// Encrypt plaintext using the appropriate Kerberos algorithm
        /// </summary>
        public static byte[] Encrypt(byte[] key, byte[] plaintext, Interop.KERB_ETYPE etype, int keyUsage)
        {
            switch (etype)
            {
                case Interop.KERB_ETYPE.aes256_cts_hmac_sha1:
                case Interop.KERB_ETYPE.aes128_cts_hmac_sha1:
                    return EncryptAesCts(key, plaintext, keyUsage);

                case Interop.KERB_ETYPE.rc4_hmac:
                    return EncryptRc4Hmac(key, plaintext, keyUsage);

                default:
                    throw new NotSupportedException($"Encryption type {etype} not supported");
            }
        }

        #endregion

        #region NFold Algorithm (RFC 3961 Section 5.1)

        /// <summary>
        /// RFC 3961 n-fold algorithm - takes input bytes and "stretches" them to output size
        /// Implementation based on MIT Kerberos / impacket
        /// </summary>
        public static byte[] NFold(byte[] input, int outputBytes)
        {
            int inputLen = input.Length;
            int lcm = Lcm(inputLen, outputBytes);

            // Build the concatenated rotated string
            byte[] bigStr = new byte[lcm];
            for (int i = 0; i < lcm / inputLen; i++)
            {
                byte[] rotated = RotateRight(input, 13 * i);
                Buffer.BlockCopy(rotated, 0, bigStr, i * inputLen, inputLen);
            }

            // Split into slices and add them with one's complement addition
            byte[] result = new byte[outputBytes];
            for (int p = 0; p < lcm; p += outputBytes)
            {
                byte[] slice = new byte[outputBytes];
                Buffer.BlockCopy(bigStr, p, slice, 0, outputBytes);
                result = AddOnesComplement(result, slice);
            }

            return result;
        }

        private static byte[] RotateRight(byte[] input, int nbits)
        {
            if (nbits == 0)
                return (byte[])input.Clone();

            int len = input.Length;
            int nbyteShift = (nbits / 8) % len;
            int remainBits = nbits % 8;

            byte[] result = new byte[len];
            for (int i = 0; i < len; i++)
            {
                int highIdx = (i - nbyteShift + len) % len;
                int lowIdx = (i - nbyteShift - 1 + len) % len;

                int highByte = input[highIdx];
                int lowByte = input[lowIdx];

                result[i] = (byte)((highByte >> remainBits) | ((lowByte << (8 - remainBits)) & 0xFF));
            }

            return result;
        }

        private static byte[] AddOnesComplement(byte[] a, byte[] b)
        {
            int n = a.Length;
            int[] v = new int[n];

            for (int i = 0; i < n; i++)
                v[i] = a[i] + b[i];

            bool hasCarry;
            do
            {
                hasCarry = false;
                int[] newV = new int[n];
                for (int i = 0; i < n; i++)
                {
                    int carryFrom = (i - n + 1 + n) % n;
                    newV[i] = (v[carryFrom] >> 8) + (v[i] & 0xFF);
                    if (newV[i] > 0xFF)
                        hasCarry = true;
                }
                v = newV;
            } while (hasCarry);

            byte[] result = new byte[n];
            for (int i = 0; i < n; i++)
                result[i] = (byte)v[i];

            return result;
        }

        private static int Gcd(int a, int b)
        {
            while (b != 0) { int t = b; b = a % b; a = t; }
            return a;
        }

        private static int Lcm(int a, int b) => (a * b) / Gcd(a, b);

        #endregion

        #region Key Derivation (RFC 3961 Section 5.1)

        /// <summary>
        /// Derive a key using RFC 3961 DK function
        /// DK(Key, Constant) = random-to-key(DR(Key, Constant))
        /// </summary>
        public static byte[] DeriveKey(byte[] baseKey, int usage, byte derivationConstant)
        {
            // Build constant: usage (4 bytes big-endian) + derivation byte
            byte[] constant = new byte[5];
            constant[0] = (byte)((usage >> 24) & 0xFF);
            constant[1] = (byte)((usage >> 16) & 0xFF);
            constant[2] = (byte)((usage >> 8) & 0xFF);
            constant[3] = (byte)(usage & 0xFF);
            constant[4] = derivationConstant;

            int blockSize = 16;
            int keyBytes = baseKey.Length;

            // n-fold the constant to block size
            byte[] folded = NFold(constant, blockSize);

            // RFC 3961: Use ECB mode, NOT CBC!
            // K1 = E(baseKey, n-fold(constant))
            // K2 = E(baseKey, K1)
            // ...
            using var aes = Aes.Create();
            aes.Key = baseKey;
            aes.Mode = CipherMode.ECB;  // IMPORTANT: ECB, not CBC!
            aes.Padding = PaddingMode.None;

            byte[] keyMaterial = new byte[keyBytes];
            byte[] currentBlock = folded;
            int offset = 0;

            using var encryptor = aes.CreateEncryptor();
            while (offset < keyBytes)
            {
                // Encrypt current block
                byte[] encrypted = encryptor.TransformFinalBlock(currentBlock, 0, blockSize);

                int toCopy = Math.Min(blockSize, keyBytes - offset);
                Buffer.BlockCopy(encrypted, 0, keyMaterial, offset, toCopy);

                currentBlock = encrypted;
                offset += blockSize;
            }

            return keyMaterial;
        }

        public static byte[] DeriveKe(byte[] baseKey, int usage) => DeriveKey(baseKey, usage, 0xAA);
        public static byte[] DeriveKi(byte[] baseKey, int usage) => DeriveKey(baseKey, usage, 0x55);
        public static byte[] DeriveKc(byte[] baseKey, int usage) => DeriveKey(baseKey, usage, 0x99);

        #endregion

        #region AES-CTS Decryption

        public static byte[] DecryptAesCts(byte[] key, byte[] ciphertext, int keyUsage)
        {
            byte[] ke = DeriveKe(key, keyUsage);
            byte[] ki = DeriveKi(key, keyUsage);

            int hmacLen = 12;
            byte[] encData = new byte[ciphertext.Length - hmacLen];
            byte[] receivedHmac = new byte[hmacLen];
            Buffer.BlockCopy(ciphertext, 0, encData, 0, encData.Length);
            Buffer.BlockCopy(ciphertext, encData.Length, receivedHmac, 0, hmacLen);

            byte[] decrypted = AesCtsDecrypt(ke, encData);

            using var hmac = new HMACSHA1(ki);
            byte[] computedHmac = hmac.ComputeHash(decrypted);
            byte[] truncatedHmac = new byte[hmacLen];
            Buffer.BlockCopy(computedHmac, 0, truncatedHmac, 0, hmacLen);

            if (!truncatedHmac.SequenceEqual(receivedHmac))
                throw new CryptographicException("HMAC verification failed");

            byte[] plaintext = new byte[decrypted.Length - 16];
            Buffer.BlockCopy(decrypted, 16, plaintext, 0, plaintext.Length);
            return plaintext;
        }

        private static byte[] AesCtsDecrypt(byte[] key, byte[] ciphertext)
        {
            if (ciphertext.Length < 16)
                throw new ArgumentException("Ciphertext too short");

            if (ciphertext.Length == 16)
            {
                using var aes = Aes.Create();
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using var dec = aes.CreateDecryptor();
                return dec.TransformFinalBlock(ciphertext, 0, 16);
            }

            int numBlocks = (ciphertext.Length + 15) / 16;
            int lastBlockSize = ciphertext.Length % 16;
            if (lastBlockSize == 0) lastBlockSize = 16;

            byte[] plaintext = new byte[ciphertext.Length];

            using var aesEcb = Aes.Create();
            aesEcb.Key = key;
            aesEcb.Mode = CipherMode.ECB;
            aesEcb.Padding = PaddingMode.None;

            if (numBlocks == 2)
            {
                byte[] c1 = new byte[16];
                byte[] c2 = new byte[lastBlockSize];
                Buffer.BlockCopy(ciphertext, 0, c1, 0, 16);
                Buffer.BlockCopy(ciphertext, 16, c2, 0, lastBlockSize);

                using var dec = aesEcb.CreateDecryptor();
                byte[] d1 = dec.TransformFinalBlock(c1, 0, 16);

                byte[] p2 = new byte[lastBlockSize];
                for (int i = 0; i < lastBlockSize; i++)
                    p2[i] = (byte)(d1[i] ^ c2[i]);

                byte[] c2Padded = new byte[16];
                Buffer.BlockCopy(c2, 0, c2Padded, 0, lastBlockSize);
                Buffer.BlockCopy(d1, lastBlockSize, c2Padded, lastBlockSize, 16 - lastBlockSize);

                byte[] p1 = dec.TransformFinalBlock(c2Padded, 0, 16);

                Buffer.BlockCopy(p1, 0, plaintext, 0, 16);
                Buffer.BlockCopy(p2, 0, plaintext, 16, lastBlockSize);
            }
            else
            {
                byte[] iv = new byte[16];
                int cbcLen = (numBlocks - 2) * 16;

                if (cbcLen > 0)
                {
                    using var aesCbc = Aes.Create();
                    aesCbc.Key = key;
                    aesCbc.Mode = CipherMode.CBC;
                    aesCbc.IV = iv;
                    aesCbc.Padding = PaddingMode.None;
                    using var cbcDec = aesCbc.CreateDecryptor();
                    byte[] cbcPlain = cbcDec.TransformFinalBlock(ciphertext, 0, cbcLen);
                    Buffer.BlockCopy(cbcPlain, 0, plaintext, 0, cbcLen);
                    Buffer.BlockCopy(ciphertext, cbcLen - 16, iv, 0, 16);
                }

                byte[] cn1 = new byte[16];
                byte[] cn = new byte[lastBlockSize];
                Buffer.BlockCopy(ciphertext, cbcLen, cn1, 0, 16);
                Buffer.BlockCopy(ciphertext, cbcLen + 16, cn, 0, lastBlockSize);

                using var ecbDec = aesEcb.CreateDecryptor();
                byte[] dn1 = ecbDec.TransformFinalBlock(cn1, 0, 16);

                for (int i = 0; i < lastBlockSize; i++)
                    plaintext[cbcLen + 16 + i] = (byte)(dn1[i] ^ cn[i]);

                byte[] cnPadded = new byte[16];
                Buffer.BlockCopy(cn, 0, cnPadded, 0, lastBlockSize);
                Buffer.BlockCopy(dn1, lastBlockSize, cnPadded, lastBlockSize, 16 - lastBlockSize);

                byte[] pn1 = ecbDec.TransformFinalBlock(cnPadded, 0, 16);

                for (int i = 0; i < 16; i++)
                    plaintext[cbcLen + i] = (byte)(pn1[i] ^ iv[i]);
            }

            return plaintext;
        }

        #endregion

        #region AES-CTS Encryption

        /// <summary>
        /// Encrypt using AES-CTS-HMAC-SHA1-96
        /// </summary>
        public static byte[] EncryptAesCts(byte[] key, byte[] plaintext, int keyUsage)
        {
            byte[] ke = DeriveKe(key, keyUsage);
            byte[] ki = DeriveKi(key, keyUsage);

            // Generate 16-byte random confounder
            byte[] confounder = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(confounder);
            }

            // Combine confounder + plaintext
            byte[] toEncrypt = new byte[confounder.Length + plaintext.Length];
            Buffer.BlockCopy(confounder, 0, toEncrypt, 0, confounder.Length);
            Buffer.BlockCopy(plaintext, 0, toEncrypt, confounder.Length, plaintext.Length);

            // Compute HMAC-SHA1-96 over (confounder + plaintext)
            using var hmac = new HMACSHA1(ki);
            byte[] fullHmac = hmac.ComputeHash(toEncrypt);
            byte[] truncatedHmac = new byte[12];
            Buffer.BlockCopy(fullHmac, 0, truncatedHmac, 0, 12);

            // Encrypt using AES-CTS
            byte[] encrypted = AesCtsEncrypt(ke, toEncrypt);

            // Return: encrypted | HMAC
            byte[] result = new byte[encrypted.Length + 12];
            Buffer.BlockCopy(encrypted, 0, result, 0, encrypted.Length);
            Buffer.BlockCopy(truncatedHmac, 0, result, encrypted.Length, 12);

            return result;
        }

        private static byte[] AesCtsEncrypt(byte[] key, byte[] plaintext)
        {
            // Pad to at least 16 bytes
            int padLen = (16 - (plaintext.Length % 16)) % 16;
            if (plaintext.Length < 16) padLen = 16 - plaintext.Length;

            byte[] padded = new byte[plaintext.Length + padLen];
            Buffer.BlockCopy(plaintext, 0, padded, 0, plaintext.Length);

            if (padded.Length == 16)
            {
                using var aes = Aes.Create();
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using var enc = aes.CreateEncryptor();
                return enc.TransformFinalBlock(padded, 0, 16);
            }

            // Multi-block CBC encryption
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.IV = new byte[16];
                aes.Padding = PaddingMode.None;

                using var enc = aes.CreateEncryptor();
                byte[] encrypted = enc.TransformFinalBlock(padded, 0, padded.Length);

                // CTS: swap last two cipher blocks and truncate
                int fullBlocks = plaintext.Length / 16;
                int lastBlockSize = plaintext.Length % 16;
                if (lastBlockSize == 0) { lastBlockSize = 16; fullBlocks--; }

                byte[] result = new byte[plaintext.Length];

                // Copy all but last two blocks
                int copyLen = Math.Max(0, (fullBlocks - 1) * 16);
                if (copyLen > 0)
                    Buffer.BlockCopy(encrypted, 0, result, 0, copyLen);

                // Swap: Cn-1 becomes last, Cn (truncated) becomes second-to-last
                int offset = copyLen;
                Buffer.BlockCopy(encrypted, encrypted.Length - 16, result, offset, Math.Min(16, plaintext.Length - offset));
                if (offset + 16 < plaintext.Length)
                    Buffer.BlockCopy(encrypted, encrypted.Length - 32, result, offset + 16, lastBlockSize);

                return result;
            }
        }

        #endregion

        #region RC4-HMAC Encryption/Decryption

        /// <summary>
        /// Decrypt RC4-HMAC ciphertext (etype 23)
        /// </summary>
        public static byte[] DecryptRc4Hmac(byte[] key, byte[] ciphertext, int keyUsage)
        {
            // RC4-HMAC structure: Checksum (16) | Encrypted(Confounder (8) | Plaintext)
            if (ciphertext.Length < 24)
                throw new CryptographicException("Ciphertext too short for RC4-HMAC");

            byte[] checksum = new byte[16];
            byte[] encData = new byte[ciphertext.Length - 16];
            Buffer.BlockCopy(ciphertext, 0, checksum, 0, 16);
            Buffer.BlockCopy(ciphertext, 16, encData, 0, encData.Length);

            // Derive K1 = HMAC-MD5(key, usage)
            byte[] usageBytes = BitConverter.GetBytes(keyUsage);
            if (!BitConverter.IsLittleEndian) Array.Reverse(usageBytes);

            byte[] k1;
            using (var hmac = new HMACMD5(key))
            {
                k1 = hmac.ComputeHash(usageBytes);
            }

            // Derive K2 = HMAC-MD5(K1, checksum)
            byte[] k2;
            using (var hmac = new HMACMD5(k1))
            {
                k2 = hmac.ComputeHash(checksum);
            }

            // Decrypt with RC4
            byte[] decrypted = RC4(k2, encData);

            // Verify checksum = HMAC-MD5(K1, decrypted)
            byte[] expectedChecksum;
            using (var hmac = new HMACMD5(k1))
            {
                expectedChecksum = hmac.ComputeHash(decrypted);
            }

            if (!checksum.SequenceEqual(expectedChecksum))
                throw new CryptographicException("RC4-HMAC checksum verification failed");

            // Remove 8-byte confounder
            byte[] plaintext = new byte[decrypted.Length - 8];
            Buffer.BlockCopy(decrypted, 8, plaintext, 0, plaintext.Length);

            return plaintext;
        }

        /// <summary>
        /// Encrypt using RC4-HMAC (etype 23)
        /// </summary>
        public static byte[] EncryptRc4Hmac(byte[] key, byte[] plaintext, int keyUsage)
        {
            // Generate 8-byte random confounder
            byte[] confounder = new byte[8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(confounder);
            }

            // Combine confounder + plaintext
            byte[] toEncrypt = new byte[8 + plaintext.Length];
            Buffer.BlockCopy(confounder, 0, toEncrypt, 0, 8);
            Buffer.BlockCopy(plaintext, 0, toEncrypt, 8, plaintext.Length);

            // Derive K1 = HMAC-MD5(key, usage)
            byte[] usageBytes = BitConverter.GetBytes(keyUsage);
            if (!BitConverter.IsLittleEndian) Array.Reverse(usageBytes);

            byte[] k1;
            using (var hmac = new HMACMD5(key))
            {
                k1 = hmac.ComputeHash(usageBytes);
            }

            // Compute checksum = HMAC-MD5(K1, toEncrypt)
            byte[] checksum;
            using (var hmac = new HMACMD5(k1))
            {
                checksum = hmac.ComputeHash(toEncrypt);
            }

            // Derive K2 = HMAC-MD5(K1, checksum)
            byte[] k2;
            using (var hmac = new HMACMD5(k1))
            {
                k2 = hmac.ComputeHash(checksum);
            }

            // Encrypt with RC4
            byte[] encrypted = RC4(k2, toEncrypt);

            // Return: checksum | encrypted
            byte[] result = new byte[16 + encrypted.Length];
            Buffer.BlockCopy(checksum, 0, result, 0, 16);
            Buffer.BlockCopy(encrypted, 0, result, 16, encrypted.Length);

            return result;
        }

        /// <summary>
        /// RC4 (ARC4) stream cipher
        /// </summary>
        private static byte[] RC4(byte[] key, byte[] data)
        {
            byte[] s = new byte[256];
            byte[] result = new byte[data.Length];

            // KSA (Key Scheduling Algorithm)
            for (int i = 0; i < 256; i++) s[i] = (byte)i;

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) & 0xFF;
                (s[i], s[j]) = (s[j], s[i]);
            }

            // PRGA (Pseudo-Random Generation Algorithm)
            int x = 0, y = 0;
            for (int i = 0; i < data.Length; i++)
            {
                x = (x + 1) & 0xFF;
                y = (y + s[x]) & 0xFF;
                (s[x], s[y]) = (s[y], s[x]);
                result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) & 0xFF]);
            }

            return result;
        }

        #endregion

        #region OctetString2Key (RFC 4556)

        public static byte[] OctetString2Key(byte[] dhSharedSecret, byte[] clientNonce, byte[] serverNonce, int keySize)
        {
            int totalLen = dhSharedSecret.Length;
            if (clientNonce != null) totalLen += clientNonce.Length;
            if (serverNonce != null) totalLen += serverNonce.Length;

            byte[] combined = new byte[totalLen];
            int offset = 0;

            Buffer.BlockCopy(dhSharedSecret, 0, combined, offset, dhSharedSecret.Length);
            offset += dhSharedSecret.Length;

            if (clientNonce != null)
            {
                Buffer.BlockCopy(clientNonce, 0, combined, offset, clientNonce.Length);
                offset += clientNonce.Length;
            }

            if (serverNonce != null)
                Buffer.BlockCopy(serverNonce, 0, combined, offset, serverNonce.Length);

            var output = new List<byte>();
            byte counter = 0;

            using var sha1 = SHA1.Create();
            while (output.Count < keySize)
            {
                byte[] toHash = new byte[1 + combined.Length];
                toHash[0] = counter;
                Buffer.BlockCopy(combined, 0, toHash, 1, combined.Length);

                byte[] digest = sha1.ComputeHash(toHash);
                int needed = keySize - output.Count;
                output.AddRange(needed >= digest.Length ? digest : digest.Take(needed));
                counter++;
            }

            return output.ToArray();
        }

        #endregion

        #region Utility Methods

        public static string ToHex(byte[] data) => BitConverter.ToString(data).Replace("-", "");

        public static byte[] FromHex(string hex)
        {
            hex = hex.Replace(" ", "").Replace("-", "");
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        #endregion
    }
}