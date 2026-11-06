// Interop.cs - Kerberos constants and types
// Adapted from Rubeus (GhostPack) - BSD 3-Clause License

using System;

namespace HttpLdapRelay.Kerberos
{
    public class Interop
    {
        // Kerberos encryption types
        public enum KERB_ETYPE : int
        {
            des_cbc_crc = 1,
            des_cbc_md4 = 2,
            des_cbc_md5 = 3,
            des3_cbc_md5 = 5,
            des3_cbc_sha1 = 7,
            dsaWithSHA1_CmsOID = 9,
            md5WithRSAEncryption_CmsOID = 10,
            sha1WithRSAEncryption_CmsOID = 11,
            rc2CBC_EnvOID = 12,
            rsaEncryption_EnvOID = 13,
            rsaES_OAEP_ENV_OID = 14,
            des_ede3_cbc_Env_OID = 15,
            des3_cbc_sha1_kd = 16,
            aes128_cts_hmac_sha1 = 17,
            aes256_cts_hmac_sha1 = 18,
            aes128_cts_hmac_sha256_128 = 19,
            aes256_cts_hmac_sha384_192 = 20,
            rc4_hmac = 23,
            rc4_hmac_exp = 24,
            subkey_keymaterial = 65,
            old_exp = -135
        }

        // Kerberos checksum types
        public enum KERB_CHECKSUM_ALGORITHM
        {
            KERB_CHECKSUM_HMAC_SHA1_96_AES128 = 15,
            KERB_CHECKSUM_HMAC_SHA1_96_AES256 = 16,
            KERB_CHECKSUM_HMAC_MD5 = -138,
            HMAC_SHA1_96_AES128 = 0x0F,
            HMAC_SHA1_96_AES256 = 0x10
        }

        // Kerberos error codes
        public enum KERBEROS_ERROR : uint
        {
            KDC_ERR_NONE = 0,
            KDC_ERR_NAME_EXP = 1,
            KDC_ERR_SERVICE_EXP = 2,
            KDC_ERR_BAD_PVNO = 3,
            KDC_ERR_C_OLD_MAST_KVNO = 4,
            KDC_ERR_S_OLD_MAST_KVNO = 5,
            KDC_ERR_C_PRINCIPAL_UNKNOWN = 6,
            KDC_ERR_S_PRINCIPAL_UNKNOWN = 7,
            KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8,
            KDC_ERR_NULL_KEY = 9,
            KDC_ERR_CANNOT_POSTDATE = 10,
            KDC_ERR_NEVER_VALID = 11,
            KDC_ERR_POLICY = 12,
            KDC_ERR_BADOPTION = 13,
            KDC_ERR_ETYPE_NOTSUPP = 14,
            KDC_ERR_SUMTYPE_NOSUPP = 15,
            KDC_ERR_PADATA_TYPE_NOSUPP = 16,
            KDC_ERR_TRTYPE_NO_SUPP = 17,
            KDC_ERR_CLIENT_REVOKED = 18,
            KDC_ERR_SERVICE_REVOKED = 19,
            KDC_ERR_TGT_REVOKED = 20,
            KDC_ERR_CLIENT_NOTYET = 21,
            KDC_ERR_SERVICE_NOTYET = 22,
            KDC_ERR_KEY_EXPIRED = 23,
            KDC_ERR_PREAUTH_FAILED = 24,
            KDC_ERR_PREAUTH_REQUIRED = 25,
            KDC_ERR_SERVER_NOMATCH = 26,
            KDC_ERR_MUST_USE_USER2USER = 27,
            KDC_ERR_PATH_NOT_ACCEPTED = 28,
            KDC_ERR_SVC_UNAVAILABLE = 29,
            KRB_AP_ERR_BAD_INTEGRITY = 31,
            KRB_AP_ERR_TKT_EXPIRED = 32,
            KRB_AP_ERR_TKT_NYV = 33,
            KRB_AP_ERR_REPEAT = 34,
            KRB_AP_ERR_NOT_US = 35,
            KRB_AP_ERR_BADMATCH = 36,
            KRB_AP_ERR_SKEW = 37,
            KRB_AP_ERR_BADADDR = 38,
            KRB_AP_ERR_BADVERSION = 39,
            KRB_AP_ERR_MSG_TYPE = 40,
            KRB_AP_ERR_MODIFIED = 41,
            KRB_AP_ERR_BADORDER = 42,
            KRB_AP_ERR_BADKEYVER = 44,
            KRB_AP_ERR_NOKEY = 45,
            KRB_AP_ERR_MUT_FAIL = 46,
            KRB_AP_ERR_BADDIRECTION = 47,
            KRB_AP_ERR_METHOD = 48,
            KRB_AP_ERR_BADSEQ = 49,
            KRB_AP_ERR_INAPP_CKSUM = 50,
            KRB_AP_PATH_NOT_ACCEPTED = 51,
            KRB_ERR_RESPONSE_TOO_BIG = 52,
            KRB_ERR_GENERIC = 60,
            KRB_ERR_FIELD_TOOLONG = 61,
            KDC_ERR_CLIENT_NOT_TRUSTED = 62,
            KDC_ERR_KDC_NOT_TRUSTED = 63,
            KDC_ERR_INVALID_SIG = 64,
            KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED = 65,
            KDC_ERR_CERTIFICATE_MISMATCH = 66,
            KRB_AP_ERR_NO_TGT = 67,
            KDC_ERR_WRONG_REALM = 68,
            KRB_AP_ERR_USER_TO_USER_REQUIRED = 69,
            KDC_ERR_CANT_VERIFY_CERTIFICATE = 70,
            KDC_ERR_INVALID_CERTIFICATE = 71,
            KDC_ERR_REVOKED_CERTIFICATE = 72,
            KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73,
            KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74,
            KDC_ERR_CLIENT_NAME_MISMATCH = 75,
            KDC_ERR_KDC_NAME_MISMATCH = 76,
            KDC_ERR_INCONSISTENT_KEY_PURPOSE = 77,
            KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED = 78,
            KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED = 79,
            KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED = 80,
            KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED = 81
        }

        // KDC Options flags
        [Flags]
        public enum KdcOptions : uint
        {
            VALIDATE = 0x00000001,
            RENEW = 0x00000002,
            UNUSED29 = 0x00000004,
            ENCTKTINSKEY = 0x00000008,
            RENEWABLEOK = 0x00000010,
            DISABLETRANSITEDCHECK = 0x00000020,
            UNUSED16 = 0x0000FFC0,
            CANONICALIZE = 0x00010000,
            CNAMEINADDLTKT = 0x00020000,
            OK_AS_DELEGATE = 0x00040000,
            UNUSED12 = 0x00080000,
            OPTHARDWAREAUTH = 0x00100000,
            PREAUTHENT = 0x00200000,
            INITIAL = 0x00400000,
            RENEWABLE = 0x00800000,
            UNUSED7 = 0x01000000,
            POSTDATED = 0x02000000,
            ALLOWPOSTDATE = 0x04000000,
            PROXY = 0x08000000,
            PROXIABLE = 0x10000000,
            FORWARDED = 0x20000000,
            FORWARDABLE = 0x40000000,
            RESERVED = 0x80000000
        }

        // PA-DATA types
        public enum PADATA_TYPE : int
        {
            PA_TGS_REQ = 1,
            PA_ENC_TIMESTAMP = 2,
            PA_PW_SALT = 3,
            PA_ENC_UNIX_TIME = 5,
            PA_SANDIA_SECUREID = 6,
            PA_SESAME = 7,
            PA_OSF_DCE = 8,
            PA_CYBERSAFE_SECUREID = 9,
            PA_AFS3_SALT = 10,
            PA_ETYPE_INFO = 11,
            PA_SAM_CHALLENGE = 12,
            PA_SAM_RESPONSE = 13,
            PA_PK_AS_REQ_19 = 14,
            PA_PK_AS_REP_19 = 15,
            PA_PK_AS_REQ = 16,
            PA_PK_AS_REP = 17,
            PA_ETYPE_INFO2 = 19,
            PA_SVR_REFERRAL_INFO = 20,
            PA_USE_SPECIFIED_KVNO = 20,
            PA_SAM_REDIRECT = 21,
            PA_GET_FROM_TYPED_DATA = 22,
            PA_SAM_ETYPE_INFO = 23,
            PA_ALT_PRINC = 24,
            PA_SAM_CHALLENGE2 = 30,
            PA_SAM_RESPONSE2 = 31,
            PA_EXTRA_TGT = 41,
            TD_PKINIT_CMS_CERTIFICATES = 101,
            TD_KRB_PRINCIPAL = 102,
            TD_KRB_REALM = 103,
            TD_TRUSTED_CERTIFIERS = 104,
            TD_CERTIFICATE_INDEX = 105,
            TD_APP_DEFINED_ERROR = 106,
            TD_REQ_NONCE = 107,
            TD_REQ_SEQ = 108,
            PA_PAC_REQUEST = 128,
            PA_FOR_USER = 129,
            PA_FX_COOKIE = 133,
            PA_FX_FAST = 136,
            PA_FX_ERROR = 137,
            PA_ENCRYPTED_CHALLENGE = 138,
            PA_SUPPORTED_ENCTYPES = 165,
            PA_PAC_OPTIONS = 167
        }

        // Principal name types
        public enum PRINCIPAL_TYPE : int
        {
            NT_UNKNOWN = 0,
            NT_PRINCIPAL = 1,
            NT_SRV_INST = 2,
            NT_SRV_HST = 3,
            NT_SRV_XHST = 4,
            NT_UID = 5,
            NT_X500_PRINCIPAL = 6,
            NT_SMTP_NAME = 7,
            NT_ENTERPRISE = 10
        }

        // Message types
        public const int AS_REQ = 10;
        public const int AS_REP = 11;
        public const int TGS_REQ = 12;
        public const int TGS_REP = 13;
        public const int AP_REQ = 14;
        public const int AP_REP = 15;
        public const int KRB_ERROR = 30;
    }
}
