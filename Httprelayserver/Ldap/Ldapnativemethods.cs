using System.Runtime.InteropServices;

namespace HttpLdapRelay
{
    /// <summary>
    /// Native LDAP methods for relay operations
    /// Utilise wldap32.dll de Windows
    /// 
    /// IMPORTANT: Les signatures P/Invoke pour wldap32.dll sont différentes
    /// de celles d'OpenLDAP. Cette version est spécifique à Windows.
    /// </summary>
    public class LdapNativeMethods
    {
        // =============== CONSTANTS ===============

        public const int LDAP_SUCCESS = 0x00;
        public const int LDAP_OPT_PROTOCOL_VERSION = 0x11;
        public const int LDAP_OPT_REFERRALS = 0x08;
        public const int LDAP_OPT_SSL = 0x0a;
        public const int LDAP_OPT_SIGN = 0x95;
        public const int LDAP_OPT_ENCRYPT = 0x96;
        public const int LDAP_OPT_TCP_KEEPALIVE = 0x40;
        public const int LDAP_OPT_AREC_EXCLUSIVE = 0x98;

        // LDAP version
        public const int LDAP_VERSION3 = 3;

        // LDAP Error codes
        public const int LDAP_OPERATIONS_ERROR = 0x01;
        public const int LDAP_PROTOCOL_ERROR = 0x02;
        public const int LDAP_TIMELIMIT_EXCEEDED = 0x03;
        public const int LDAP_AUTH_METHOD_NOT_SUPPORTED = 0x07;
        public const int LDAP_STRONG_AUTH_REQUIRED = 0x08;
        public const int LDAP_SASL_BIND_IN_PROGRESS = 0x0E; // 14 - Continue needed
        public const int LDAP_INVALID_CREDENTIALS = 0x31;
        public const int LDAP_INSUFFICIENT_ACCESS = 0x32;
        public const int LDAP_UNWILLING_TO_PERFORM = 0x35;
        public const int LDAP_SERVER_DOWN = 0x51;
        public const int LDAP_LOCAL_ERROR = 0x52;
        public const int LDAP_ENCODING_ERROR = 0x53;
        public const int LDAP_DECODING_ERROR = 0x54;
        public const int LDAP_TIMEOUT = 0x55;
        public const int LDAP_AUTH_UNKNOWN = 0x56;
        public const int LDAP_FILTER_ERROR = 0x57;
        public const int LDAP_USER_CANCELLED = 0x58;
        public const int LDAP_PARAM_ERROR = 0x59;
        public const int LDAP_NO_MEMORY = 0x5A;
        public const int LDAP_CONNECT_ERROR = 0x5B;
        public const int LDAP_NOT_SUPPORTED = 0x5C;

        // LDAP Scope
        public const int LDAP_SCOPE_BASE = 0x00;
        public const int LDAP_SCOPE_ONELEVEL = 0x01;
        public const int LDAP_SCOPE_SUBTREE = 0x02;

        // =============== STRUCTURES ===============

        /// <summary>
        /// BER value structure for LDAP
        /// Structure Windows: LDAP_BERVAL
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct LDAP_BERVAL
        {
            public uint bv_len;
            public IntPtr bv_val;
        }

        /// <summary>
        /// Timeout structure - l_timeval pour Windows
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct LDAP_TIMEVAL
        {
            public int tv_sec;
            public int tv_usec;
        }

        // =============== LDAP FUNCTIONS ===============

        /// <summary>
        /// Initialize LDAP connection
        /// </summary>
        [DllImport("wldap32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr ldap_init(
            [MarshalAs(UnmanagedType.LPWStr)] string hostName,
            int portNumber
        );

        /// <summary>
        /// Initialize LDAP connection with SSL
        /// </summary>
        [DllImport("wldap32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr ldap_sslinit(
            [MarshalAs(UnmanagedType.LPWStr)] string hostName,
            int portNumber,
            int secure
        );

        /// <summary>
        /// Set LDAP option (int value)
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern int ldap_set_option(
            IntPtr ld,
            int option,
            ref int value
        );

        /// <summary>
        /// Set LDAP option (pointer version)
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true, EntryPoint = "ldap_set_option")]
        public static extern int ldap_set_option_ptr(
            IntPtr ld,
            int option,
            IntPtr value
        );

        /// <summary>
        /// Get LDAP option
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern int ldap_get_option(
            IntPtr ld,
            int option,
            out int value
        );

        /// <summary>
        /// Connect to LDAP server (establishes the TCP connection)
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern int ldap_connect(
            IntPtr ld,
            IntPtr timeout  // Can be NULL
        );

        /// <summary>
        /// SASL bind synchronous - Version avec tous les pointeurs IntPtr
        /// C'est la version la plus flexible pour éviter les problèmes de marshalling
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern int ldap_sasl_bind_s(
            IntPtr ld,
            IntPtr dn,              // NULL ou pointeur vers string ANSI
            IntPtr mechanism,       // Pointeur vers string ANSI "GSS-SPNEGO" ou "GSSAPI"
            IntPtr cred,            // Pointeur vers LDAP_BERVAL
            IntPtr serverctrls,     // NULL
            IntPtr clientctrls,     // NULL
            out IntPtr servercredp  // Pointeur vers LDAP_BERVAL*
        );

        /// <summary>
        /// Simple bind (pour test de connexion)
        /// </summary>
        [DllImport("wldap32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int ldap_simple_bind_s(
            IntPtr ld,
            [MarshalAs(UnmanagedType.LPWStr)] string dn,
            [MarshalAs(UnmanagedType.LPWStr)] string password
        );

        /// <summary>
        /// Unbind and close connection
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern int ldap_unbind_s(IntPtr ld);

        /// <summary>
        /// Unbind (simple version)
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern int ldap_unbind(IntPtr ld);

        /// <summary>
        /// Search LDAP directory
        /// </summary>
        [DllImport("wldap32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int ldap_search_ext_s(
            IntPtr ld,
            [MarshalAs(UnmanagedType.LPWStr)] string basedn,
            int scope,
            [MarshalAs(UnmanagedType.LPWStr)] string filter,
            IntPtr attrs,
            int attrsonly,
            IntPtr serverctrls,
            IntPtr clientctrls,
            IntPtr timeout,
            int sizelimit,
            out IntPtr result
        );

        /// <summary>
        /// Simple search
        /// </summary>
        [DllImport("wldap32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int ldap_search_s(
            IntPtr ld,
            [MarshalAs(UnmanagedType.LPWStr)] string basedn,
            int scope,
            [MarshalAs(UnmanagedType.LPWStr)] string filter,
            IntPtr attrs,
            int attrsonly,
            out IntPtr result
        );

        /// <summary>
        /// Count entries in result
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern int ldap_count_entries(
            IntPtr ld,
            IntPtr result
        );

        /// <summary>
        /// Get first entry from search result
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern IntPtr ldap_first_entry(
            IntPtr ld,
            IntPtr result
        );

        /// <summary>
        /// Get next entry from search result
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern IntPtr ldap_next_entry(
            IntPtr ld,
            IntPtr entry
        );

        /// <summary>
        /// Get distinguished name of entry
        /// </summary>
        [DllImport("wldap32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr ldap_get_dn(
            IntPtr ld,
            IntPtr entry
        );

        /// <summary>
        /// Free LDAP message
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern int ldap_msgfree(IntPtr msg);

        /// <summary>
        /// Free memory allocated by LDAP
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern void ldap_memfree(IntPtr ptr);

        /// <summary>
        /// Get last error
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern int LdapGetLastError();

        /// <summary>
        /// Get error string
        /// </summary>
        [DllImport("wldap32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr ldap_err2string(int err);

        // =============== BER FUNCTIONS ===============

        /// <summary>
        /// Free berval structure allocated by LDAP
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern void ber_bvfree(IntPtr bv);

        /// <summary>
        /// Free array of berval structures
        /// </summary>
        [DllImport("wldap32.dll", SetLastError = true)]
        public static extern void ber_bvecfree(IntPtr bvec);

        // =============== HELPER METHODS ===============

        /// <summary>
        /// Crée une structure LDAP_BERVAL en mémoire non managée
        /// </summary>
        public static IntPtr CreateBerval(byte[] data)
        {
            if (data == null || data.Length == 0)
                return IntPtr.Zero;

            // Allouer la structure LDAP_BERVAL
            int bervalSize = Marshal.SizeOf<LDAP_BERVAL>();
            IntPtr bervalPtr = Marshal.AllocHGlobal(bervalSize);

            // Allouer le buffer pour les données
            IntPtr dataPtr = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, dataPtr, data.Length);

            // Remplir la structure
            var berval = new LDAP_BERVAL
            {
                bv_len = (uint)data.Length,
                bv_val = dataPtr
            };

            // Copier la structure vers le pointeur
            Marshal.StructureToPtr(berval, bervalPtr, false);

            return bervalPtr;
        }

        /// <summary>
        /// Libère une structure LDAP_BERVAL créée avec CreateBerval
        /// </summary>
        public static void FreeBerval(IntPtr bervalPtr)
        {
            if (bervalPtr != IntPtr.Zero)
            {
                try
                {
                    var berval = Marshal.PtrToStructure<LDAP_BERVAL>(bervalPtr);
                    if (berval.bv_val != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(berval.bv_val);
                    }
                }
                catch { }
                Marshal.FreeHGlobal(bervalPtr);
            }
        }

        /// <summary>
        /// Extrait les données d'une structure LDAP_BERVAL
        /// </summary>
        public static byte[] ExtractBervalData(IntPtr bervalPtr)
        {
            if (bervalPtr == IntPtr.Zero)
                return null;

            try
            {
                var berval = Marshal.PtrToStructure<LDAP_BERVAL>(bervalPtr);

                if (berval.bv_len == 0 || berval.bv_val == IntPtr.Zero)
                    return null;

                byte[] data = new byte[berval.bv_len];
                Marshal.Copy(berval.bv_val, data, 0, (int)berval.bv_len);

                return data;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Get human-readable LDAP error message
        /// </summary>
        public static string GetLdapError(int errorCode)
        {
            try
            {
                IntPtr errorPtr = ldap_err2string(errorCode);
                if (errorPtr != IntPtr.Zero)
                {
                    string errorMessage = Marshal.PtrToStringUni(errorPtr);
                    if (!string.IsNullOrEmpty(errorMessage))
                    {
                        return $"{errorMessage} (0x{errorCode:X2})";
                    }
                }
            }
            catch { }

            // Messages d'erreur personnalisés pour les codes courants
            return errorCode switch
            {
                LDAP_SUCCESS => "Success (0x00)",
                LDAP_OPERATIONS_ERROR => "Operations Error (0x01)",
                LDAP_PROTOCOL_ERROR => "Protocol Error (0x02)",
                LDAP_TIMELIMIT_EXCEEDED => "Time Limit Exceeded (0x03)",
                LDAP_AUTH_METHOD_NOT_SUPPORTED => "Auth Method Not Supported (0x07)",
                LDAP_STRONG_AUTH_REQUIRED => "Strong Auth Required (0x08)",
                LDAP_SASL_BIND_IN_PROGRESS => "SASL Bind In Progress (0x0E)",
                LDAP_INVALID_CREDENTIALS => "Invalid Credentials (0x31)",
                LDAP_INSUFFICIENT_ACCESS => "Insufficient Access (0x32)",
                LDAP_UNWILLING_TO_PERFORM => "Unwilling To Perform (0x35)",
                LDAP_SERVER_DOWN => "Server Down (0x51)",
                LDAP_LOCAL_ERROR => "Local Error (0x52)",
                LDAP_ENCODING_ERROR => "Encoding Error (0x53)",
                LDAP_DECODING_ERROR => "Decoding Error (0x54)",
                LDAP_TIMEOUT => "Timeout (0x55)",
                LDAP_AUTH_UNKNOWN => "Auth Unknown (0x56)",
                LDAP_FILTER_ERROR => "Filter Error (0x57)",
                LDAP_USER_CANCELLED => "User Cancelled (0x58)",
                LDAP_PARAM_ERROR => "Parameter Error (0x59)",
                LDAP_NO_MEMORY => "No Memory (0x5A)",
                LDAP_CONNECT_ERROR => "Connect Error (0x5B)",
                LDAP_NOT_SUPPORTED => "Not Supported (0x5C)",
                _ => $"Unknown LDAP error (0x{errorCode:X2})"
            };
        }

        /// <summary>
        /// Check if LDAP result indicates success
        /// </summary>
        public static bool IsSuccess(int result)
        {
            return result == LDAP_SUCCESS;
        }

        /// <summary>
        /// Check if LDAP result indicates SASL bind should continue
        /// </summary>
        public static bool IsSaslContinue(int result)
        {
            return result == LDAP_SASL_BIND_IN_PROGRESS;
        }
    }
}