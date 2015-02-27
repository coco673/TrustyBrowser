#!/usr/bin/env python
# encoding: utf-8


class CipherSuiteCriticity(object):

    """ Dictionnaire répertoriant les codes des suites chiffrantes, les
    algorithmes utilisés, ainsi que leur libellé complet """
    cipherSuitesAlgos = {
        0x000000: ["NULL", "NULL", "NULL", "NULL",
                   "TLS_NULL_WITH_NULL_NULL"],
        0x000001: ["RSA", "RSA", "NULL", "MD5",
                   "TLS_RSA_WITH_NULL_MD5"],
        0x000002: ["RSA", "RSA", "NULL", "SHA",
                   "TLS_RSA_WITH_NULL_SHA"],
        0x000003: ["RSA_EXPORT", "RSA_EXPORT", "RC4_40", "MD5",
                   "TLS_RSA_EXPORT_WITH_RC4_40_MD5"],
        0x000004: ["RSA", "RSA", "RC4_128", "MD5",
                   "TLS_RSA_WITH_RC4_128_MD5"],
        0x000005: ["RSA", "RSA", "RC4_128", "SHA",
                   "TLS_RSA_WITH_RC4_128_SHA"],
        0x000006: ["RSA_EXPORT", "RSA_EXPORT", "RC2_CBC_40", "MD5",
                   "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"],
        0x000007: ["RSA", "RSA", "IDEA_CBC", "SHA",
                   "TLS_RSA_WITH_IDEA_CBC_SHA"],
        0x000008: ["RSA_EXPORT", "RSA_EXPORT", "DES40_CBC", "SHA",
                   "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"],
        0x000009: ["RSA", "RSA", "DES_CBC", "SHA",
                   "TLS_RSA_WITH_DES_CBC_SHA"],
        0x00000A: ["RSA", "RSA", "3DES_EDE_CBC", "SHA",
                   "TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
        0x00000B: ["DH", "DSS", "DES40_CBC", "SHA",
                   "TLS_DH_DSS_WITH_DES40_CBC_SHA"],
        0x00000C: ["DH", "DSS", "DES_CBC", "SHA",
                   "TLS_DH_DSS_WITH_DES_CBC_SHA"],
        0x00000D: ["DH", "DSS", "3DES_EDE_CBC", "SHA",
                   "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"],
        0x00000E: ["DH", "RSA", "DES40_CBC", "SHA",
                   "TLS_DH_RSA_WITH_DES40_CBC_SHA"],
        0x00000F: ["DH", "RSA", "DES_CBC", "SHA",
                   "TLS_DH_RSA_WITH_DES_CBC_SHA"],
        0x000010: ["DH", "RSA", "3DES_EDE_CBC", "SHA",
                   "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"],
        0x000011: ["DHE", "DSS", "DES40_CBC", "SHA",
                   "TLS_DHE_DSS_WITH_DES40_CBC_SHA"],
        0x000012: ["DHE", "DSS", "DES_CBC", "SHA",
                   "TLS_DHE_DSS_WITH_DES_CBC_SHA"],
        0x000013: ["DHE", "DSS", "3DES_EDE_CBC", "SHA",
                   "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"],
        0x000014: ["DHE", "RSA", "DES40_CBC", "SHA",
                   "TLS_DHE_RSA_WITH_DES40_CBC_SHA"],
        0x000015: ["DHE", "RSA", "DES_CBC", "SHA",
                   "TLS_DHE_RSA_WITH_DES_CBC_SHA"],
        0x000016: ["DHE", "RSA", "3DES_EDE_CBC", "SHA",
                   "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"],
        0x000017: ["DH", "Anon", "RC4_40", "MD5",
                   "TLS_DH_Anon_WITH_RC4_40_MD5"],
        0x000018: ["DH", "Anon", "RC4_128", "MD5",
                   "TLS_DH_Anon_WITH_RC4_128_MD5"],
        0x000019: ["DH", "Anon", "DES40_CBC", "SHA",
                   "TLS_DH_Anon_WITH_DES40_CBC_SHA"],
        0x00001A: ["DH", "Anon", "DES_CBC", "SHA",
                   "TLS_DH_Anon_WITH_DES_CBC_SHA"],
        0x00001B: ["DH", "Anon", "3DES_EDE_CBC", "SHA",
                   "TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA"],
        0x00001C: ["FORTEZZA", "KEA", "NULL", "SHA",
                   "SSL_FORTEZZA_KEA_WITH_NULL_SHA"],
        0x00001D: ["FORTEZZA", "KEA", "FORTEZZA_CBC", "SHA",
                   "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"],
        0x00001E: ["KRB5", "KRB5", "DES_CBC", "SHA",
                   "TLS_KRB5_WITH_DES_CBC_SHA"],
        0x00001F: ["KRB5", "KRB5", "3DES_EDE_CBC", "SHA",
                   "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"],
        0x000020: ["KRB5", "KRB5", "RC4_128", "SHA",
                   "TLS_KRB5_WITH_RC4_128_SHA"],
        0x000021: ["KRB5", "KRB5", "IDEA_CBC", "SHA",
                   "TLS_KRB5_WITH_IDEA_CBC_SHA"],
        0x000022: ["KRB5", "KRB5", "DES_CBC", "MD5",
                   "TLS_KRB5_WITH_DES_CBC_MD5"],
        0x000023: ["KRB5", "KRB5", "3DES_EDE_CBC", "MD5",
                   "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"],
        0x000024: ["KRB5", "KRB5", "RC4_128", "MD5",
                   "TLS_KRB5_WITH_RC4_128_MD5"],
        0x000025: ["KRB5", "KRB5", "IDEA_CBC", "MD5",
                   "TLS_KRB5_WITH_IDEA_CBC_MD5"],
        0x000026: ["KRB5_EXPORT", "KRB5_EXPORT", "DES_CBC_40", "SHA",
                   "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"],
        0x000027: ["KRB5_EXPORT", "KRB5_EXPORT", "RC2_CBC_40", "SHA",
                   "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"],
        0x000028: ["KRB5_EXPORT", "KRB5_EXPORT", "RC4_40", "SHA",
                   "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"],
        0x000029: ["KRB5_EXPORT", "KRB5_EXPORT", "DES_CBC_40", "MD5",
                   "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"],
        0x00002A: ["KRB5_EXPORT", "KRB5_EXPORT", "RC2_CBC_40", "MD5",
                   "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"],
        0x00002B: ["KRB5_EXPORT", "KRB5_EXPORT", "RC4_40", "MD5",
                   "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"],
        0x00002C: ["PSK", "PSK", "NULL", "SHA",
                   "TLS_PSK_WITH_NULL_SHA"],
        0x00002D: ["DHE", "PSK", "NULL", "SHA",
                   "TLS_DHE_PSK_WITH_NULL_SHA"],
        0x00002E: ["RSA", "PSK", "NULL", "SHA",
                   "TLS_RSA_PSK_WITH_NULL_SHA"],
        0x00002F: ["RSA", "RSA", "AES_128_CBC", "SHA",
                   "TLS_RSA_WITH_AES_128_CBC_SHA"],
        0x000030: ["DH", "DSS", "AES_128_CBC", "SHA",
                   "TLS_DH_DSS_WITH_AES_128_CBC_SHA"],
        0x000031: ["DH", "RSA", "AES_128_CBC", "SHA",
                   "TLS_DH_RSA_WITH_AES_128_CBC_SHA"],
        0x000032: ["DHE", "DSS", "AES_128_CBC", "SHA",
                   "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"],
        0x000033: ["DHE", "RSA", "AES_128_CBC", "SHA",
                   "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"],
        0x000034: ["DH", "Anon", "AES_128_CBC", "SHA",
                   "TLS_DH_Anon_WITH_AES_128_CBC_SHA"],
        0x000035: ["RSA", "RSA", "AES_256_CBC", "SHA",
                   "TLS_RSA_WITH_AES_256_CBC_SHA"],
        0x000036: ["DH", "DSS", "AES_256_CBC", "SHA",
                   "TLS_DH_DSS_WITH_AES_256_CBC_SHA"],
        0x000037: ["DH", "RSA", "AES_256_CBC", "SHA",
                   "TLS_DH_RSA_WITH_AES_256_CBC_SHA"],
        0x000038: ["DHE", "DSS", "AES_256_CBC", "SHA",
                   "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"],
        0x000039: ["DHE", "RSA", "AES_256_CBC", "SHA",
                   "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"],
        0x00003A: ["DH", "Anon", "AES_256_CBC", "SHA",
                   "TLS_DH_Anon_WITH_AES_256_CBC_SHA"],
        0x00003B: ["RSA", "RSA", "NULL", "SHA256",
                   "TLS_RSA_WITH_NULL_SHA256"],
        0x00003C: ["RSA", "RSA", "AES_128_CBC", "SHA256",
                   "TLS_RSA_WITH_AES_128_CBC_SHA256"],
        0x00003D: ["RSA", "RSA", "AES_256_CBC", "SHA256",
                   "TLS_RSA_WITH_AES_256_CBC_SHA256"],
        0x00003E: ["DH", "DSS", "AES_128_CBC", "SHA256",
                   "TLS_DH_DSSWITH__AES_128_CBC_SHA256"],
        0x00003F: ["DH", "RSA", "AES_128_CBC", "SHA256",
                   "TLS_DH_RSAWITH__AES_128_CBC_SHA256"],
        0x000040: ["DHE", "DSS", "AES_128_CBC", "SHA256",
                   "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"],
        0x000041: ["RSA", "RSA", "CAMELLIA_128_CBC", "SHA",
                   "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"],
        0x000042: ["DH", "DSS", "CAMELLIA_128_CBC", "SHA",
                   "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"],
        0x000043: ["DH", "RSA", "CAMELLIA_128_CBC", "SHA",
                   "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"],
        0x000044: ["DHE", "DSS", "CAMELLIA_128_CBC", "SHA",
                   "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"],
        0x000045: ["DHE", "RSA", "CAMELLIA_128_CBC", "SHA",
                   "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"],
        0x000046: ["DH", "Anon", "CAMELLIA_128_CBC", "SHA",
                   "TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA"],
        0x000047: ["ECDH", "ECDSA", "NULL", "SHA",
                   "TLS_ECDH_ECDSA_WITH_NULL_SHA"],
        0x000048: ["ECDH", "ECDSA", "RC4_128", "SHA",
                   "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"],
        0x000049: ["ECDH", "ECDSA", "DES_CBC", "SHA",
                   "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA"],
        0x00004A: ["ECDH", "ECDSA", "3DES_EDE_CBC", "SHA",
                   "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"],
        0x00004B: ["ECDH", "ECDSA", "AES_128_CBC", "SHA",
                   "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"],
        0x00004C: ["ECDH", "ECDSA", "AES_256_CBC", "SHA",
                   "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"],
        0x000060: ["RSA_EXPORT 1024", "RSA_EXPORT 1024", "RC4_56", "MD5",
                   "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"],
        0x000061: ["RSA_EXPORT 1024", "RSA_EXPORT 1024", "RC2_CBC_56", "MD5",
                   "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"],
        0x000062: ["RSA_EXPORT 1024", "RSA_EXPORT 1024", "DES_CBC", "SHA",
                   "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"],
        0x000063: ["DHE", "DSS", "DES_CBC", "SHA",
                   "TLS_DHE_DSS_WITH_DES_CBC_SHA"],
        0x000064: ["RSA_EXPORT 1024", "RSA_EXPORT 1024", "RC4_56", "SHA",
                   "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"],
        0x000065: ["DHE", "DSS", "RC4_56", "SHA",
                   "TLS_DHE_DSS_WITH_RC4_56_SHA"],
        0x000066: ["DHE", "DSS", "RC4_128", "SHA",
                   "TLS_DHE_DSS_WITH_RC4_128_SHA"],
        0x000067: ["DHE", "RSA", "AES_128_CBC", "SHA256",
                   "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"],
        0x000068: ["DH", "DSS", "AES_256_CBC", "SHA256",
                   "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"],
        0x000069: ["DH", "RSA", "AES_256_CBC", "SHA256",
                   "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"],
        0x00006A: ["DHE", "DSS", "AES_256_CBC", "SHA256",
                   "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"],
        0x00006B: ["DHE", "RSA", "AES_256_CBC", "SHA256",
                   "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"],
        0x00006C: ["DH", "Anon", "AES_128_CBC", "SHA256",
                   "TLS_DH_Anon_WITH_AES_128_CBC_SHA256"],
        0x00006D: ["DH", "Anon", "AES_256_CBC", "SHA256",
                   "TLS_DH_Anon_WITH_AES_256_CBC_SHA256"],
        0x000080: ["VKO GOST R 34.10-94", "VKO GOST R 34.10-94", "GOST28147",
                   "GOST28147",
                   "TLS_GOSTR341094_WITH_28147_CNT_IMIT"],
        0x000081: ["VKO GOST R 34.10-2001", "VKO GOST R 34.10-2001",
                   "GOST28147", "GOST28147",
                   "TLS_GOSTR341001_WITH_28147_CNT_IMIT"],
        0x000082: ["VKO GOST R 34.10-94", "VKO GOST R 34.10-94", "NULL",
                   "GOSTR3411", "TLS_GOSTR341094_WITH_NULL_GOSTR3411"],
        0x000083: ["VKO GOST R 34.10-2001", "VKO GOST R 34.10-2001", "NULL",
                   "GOSTR3411", "TLS_GOSTR341001_WITH_NULL_GOSTR3411"],
        0x000084: ["RSA", "RSA", "CAMELLIA_256_CBC", "SHA",
                   "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"],
        0x000085: ["DH", "DSS", "CAMELLIA_256_CBC", "SHA",
                   "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"],
        0x000086: ["DH", "RSA", "CAMELLIA_256_CBC", "SHA",
                   "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"],
        0x000087: ["DHE", "DSS", "CAMELLIA_256_CBC", "SHA",
                   "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"],
        0x000088: ["DHE", "RSA", "CAMELLIA_256_CBC", "SHA",
                   "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"],
        0x000089: ["DH", "Anon", "CAMELLIA_256_CBC", "SHA",
                   "TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA"],
        0x00008A: ["PSK", "PSK", "RC4_128", "SHA",
                   "TLS_PSK_WITH_RC4_128_SHA"],
        0x00008B: ["PSK", "PSK", "3DES_EDE_CBC", "SHA",
                   "TLS_PSK_WITH_3DES_EDE_CBC_SHA"],
        0x00008C: ["PSK", "PSK", "AES_128_CBC", "SHA",
                   "TLS_PSK_WITH_AES_128_CBC_SHA"],
        0x00008D: ["PSK", "PSK", "AES_256_CBC", "SHA",
                   "TLS_PSK_WITH_AES_256_CBC_SHA"],
        0x00008E: ["DHE", "PSK", "RC4_128", "SHA",
                   "TLS_DHE_PSK_WITH_RC4_128_SHA"],
        0x00008F: ["DHE", "PSK", "3DES_EDE_CBC", "SHA",
                   "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"],
        0x000090: ["DHE", "PSK", "AES_128_CBC", "SHA",
                   "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"],
        0x000091: ["DHE", "PSK", "AES_256_CBC", "SHA",
                   "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"],
        0x000092: ["RSA", "PSK", "RC4_128", "SHA",
                   "TLS_RSA_PSK_WITH_RC4_128_SHA"],
        0x000093: ["RSA", "PSK", "3DES_EDE_CBC", "SHA",
                   "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"],
        0x000094: ["RSA", "PSK", "AES_128_CBC", "SHA",
                   "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"],
        0x000095: ["RSA", "PSK", "AES_256_CBC", "SHA",
                   "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"],
        0x000096: ["RSA", "RSA", "SEED_CBC", "SHA",
                   "TLS_RSA_WITH_SEED_CBC_SHA"],
        0x000097: ["DH", "DSS", "SEED_CBC", "SHA",
                   "TLS_DH_DSS_WITH_SEED_CBC_SHA"],
        0x000098: ["DH", "RSA", "SEED_CBC", "SHA",
                   "TLS_DH_RSA_WITH_SEED_CBC_SHA"],
        0x000099: ["DHE", "DSS", "SEED_CBC", "SHA",
                   "TLS_DHE_DSS_WITH_SEED_CBC_SHA"],
        0x00009A: ["DHE", "RSA", "SEED_CBC", "SHA",
                   "TLS_DHE_RSA_WITH_SEED_CBC_SHA"],
        0x00009B: ["DH", "Anon", "SEED_CBC", "SHA",
                   "TLS_DH_Anon_WITH_SEED_CBC_SHA"],
        0x00009C: ["RSA", "RSA", "AES_128_GCM", "SHA256",
                   "TLS_RSA_WITH_AES_128_GCM_SHA256"],
        0x00009D: ["RSA", "RSA", "AES_256_GCM", "SHA384",
                   "TLS_RSA_WITH_AES_256_GCM_SHA384"],
        0x00009E: ["DHE", "RSA", "AES_128_GCM", "SHA256",
                   "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"],
        0x00009F: ["DHE", "RSA", "AES_256_GCM", "SHA384",
                   "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"],
        0x0000A0: ["DH", "RSA", "AES_128_GCM", "SHA256",
                   "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"],
        0x0000A1: ["DH", "RSA", "AES_256_GCM", "SHA384",
                   "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"],
        0x0000A2: ["DHE", "DSS", "AES_128_GCM", "SHA256",
                   "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"],
        0x0000A3: ["DHE", "DSS", "AES_256_GCM", "SHA384",
                   "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"],
        0x0000A4: ["DH", "DSS", "AES_128_GCM", "SHA256",
                   "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"],
        0x0000A5: ["DH", "DSS", "AES_256_GCM", "SHA384",
                   "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"],
        0x0000A6: ["DH", "Anon", "AES_128_GCM", "SHA256",
                   "TLS_DH_Anon_WITH_AES_128_GCM_SHA256"],
        0x0000A7: ["DH", "Anon", "AES_256_GCM", "SHA384",
                   "TLS_DH_Anon_WITH_AES_256_GCM_SHA384"],
        0x0000A8: ["PSK", "PSK", "AES_128_GCM", "SHA256",
                   "TLS_PSK_WITH_AES_128_GCM_SHA256"],
        0x0000A9: ["PSK", "PSK", "AES_256_GCM", "SHA384",
                   "TLS_PSK_WITH_AES_256_GCM_SHA384"],
        0x0000AA: ["DHE", "PSK", "AES_128_GCM", "SHA256",
                   "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"],
        0x0000AB: ["DHE", "PSK", "AES_256_GCM", "SHA384",
                   "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"],
        0x0000AC: ["RSA", "PSK", "AES_128_GCM", "SHA256",
                   "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"],
        0x0000AD: ["RSA", "PSK", "AES_256_GCM", "SHA384",
                   "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"],
        0x0000AE: ["PSK", "PSK", "AES_128_CBC", "SHA256",
                   "TLS_PSK_WITH_AES_128_CBC_SHA256"],
        0x0000AF: ["PSK", "PSK", "AES_256_CBC", "SHA384",
                   "TLS_PSK_WITH_AES_256_CBC_SHA384"],
        0x0000B0: ["PSK", "PSK", "NULL", "SHA256",
                   "TLS_PSK_WITH_NULL_SHA256"],
        0x0000B1: ["PSK", "PSK", "NULL", "SHA384",
                   "TLS_PSK_WITH_NULL_SHA384"],
        0x0000B2: ["DHE", "PSK", "AES_128_CBC", "SHA256",
                   "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"],
        0x0000B3: ["DHE", "PSK", "AES_256_CBC", "SHA384",
                   "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"],
        0x0000B4: ["DHE", "PSK", "NULL", "SHA256",
                   "TLS_DHE_PSK_WITH_NULL_SHA256"],
        0x0000B5: ["DHE", "PSK", "NULL", "SHA384",
                   "TLS_DHE_PSK_WITH_NULL_SHA384"],
        0x0000B6: ["RSA", "PSK", "AES_128_CBC", "SHA256",
                   "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"],
        0x0000B7: ["RSA", "PSK", "AES_256_CBC", "SHA384",
                   "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"],
        0x0000B8: ["RSA", "PSK", "NULL", "SHA256",
                   "TLS_RSA_PSK_WITH_NULL_SHA256"],
        0x0000B9: ["RSA", "PSK", "NULL", "SHA384",
                   "TLS_RSA_PSK_WITH_NULL_SHA384"],
        0x00C001: ["ECDH", "ECDSA", "NULL", "SHA",
                   "TLS_ECDH_ECDSA_WITH_NULL_SHA"],
        0x00C002: ["ECDH", "ECDSA", "RC4_128", "SHA",
                   "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"],
        0x00C003: ["ECDH", "ECDSA", "3DES_EDE_CBC", "SHA",
                   "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"],
        0x00C004: ["ECDH", "ECDSA", "AES_128_CBC", "SHA",
                   "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"],
        0x00C005: ["ECDH", "ECDSA", "AES_256_CBC", "SHA",
                   "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"],
        0x00C006: ["ECDHE", "ECDSA", "NULL", "SHA",
                   "TLS_ECDHE_ECDSA_WITH_NULL_SHA"],
        0x00C007: ["ECDHE", "ECDSA", "RC4_128", "SHA",
                   "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"],
        0x00C008: ["ECDHE", "ECDSA", "3DES_EDE_CBC", "SHA",
                   "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"],
        0x00C009: ["ECDHE", "ECDSA", "AES_128_CBC", "SHA",
                   "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"],
        0x00C00A: ["ECDHE", "ECDSA", "AES_256_CBC", "SHA",
                   "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"],
        0x00C00B: ["ECDH", "RSA", "NULL", "SHA",
                   "TLS_ECDH_RSA_WITH_NULL_SHA"],
        0x00C00C: ["ECDH", "RSA", "RC4_128", "SHA",
                   "TLS_ECDH_RSA_WITH_RC4_128_SHA"],
        0x00C00D: ["ECDH", "RSA", "3DES_EDE_CBC", "SHA",
                   "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"],
        0x00C00E: ["ECDH", "RSA", "AES_128_CBC", "SHA",
                   "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"],
        0x00C00F: ["ECDH", "RSA", "AES_256_CBC", "SHA",
                   "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"],
        0x00C010: ["ECDHE", "RSA", "NULL", "SHA",
                   "TLS_ECDHE_RSA_WITH_NULL_SHA"],
        0x00C011: ["ECDHE", "RSA", "RC4_128", "SHA",
                   "TLS_ECDHE_RSA_WITH_RC4_128_SHA"],
        0x00C012: ["ECDHE", "RSA", "3DES_EDE_CBC", "SHA",
                   "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"],
        0x00C013: ["ECDHE", "RSA", "AES_128_CBC", "SHA",
                   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"],
        0x00C014: ["ECDHE", "RSA", "AES_256_CBC", "SHA",
                   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"],
        0x00C015: ["ECDH", "Anon", "NULL", "SHA",
                   "TLS_ECDH_Anon_WITH_NULL_SHA"],
        0x00C016: ["ECDH", "Anon", "RC4_128", "SHA",
                   "TLS_ECDH_Anon_WITH_RC4_128_SHA"],
        0x00C017: ["ECDH", "Anon", "3DES_EDE_CBC", "SHA",
                   "TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA"],
        0x00C018: ["ECDH", "Anon", "AES_128_CBC", "SHA",
                   "TLS_ECDH_Anon_WITH_AES_128_CBC_SHA"],
        0x00C019: ["ECDH", "Anon", "AES_256_CBC", "SHA",
                   "TLS_ECDH_Anon_WITH_AES_256_CBC_SHA"],
        0x00C01A: ["SRP", "SHA", "3DES_EDE_CBC", "SHA",
                   "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"],
        0x00C01B: ["SRP", "SHA", "3DES_EDE_CBC", "SHA",
                   "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"],
        0x00C01C: ["SRP", "SHA", "3DES_EDE_CBC", "SHA",
                   "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"],
        0x00C01D: ["SRP", "SHA", "AES_128_CBC", "SHA",
                   "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"],
        0x00C01E: ["SRP", "SHA", "AES_128_CBC", "SHA",
                   "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"],
        0x00C01F: ["SRP", "SHA", "AES_128_CBC", "SHA",
                   "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"],
        0x00C020: ["SRP", "SHA", "AES_256_CBC", "SHA",
                   "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"],
        0x00C021: ["SRP", "SHA", "AES_256_CBC", "SHA",
                   "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"],
        0x00C022: ["SRP", "SHA", "AES_256_CBC", "SHA",
                   "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"],
        0x00C023: ["ECDHE", "ECDSA", "AES_128_CBC", "SHA256",
                   "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"],
        0x00C024: ["ECDHE", "ECDSA", "AES_256_CBC", "SHA384",
                   "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"],
        0x00C025: ["ECDH", "ECDSA", "AES_128_CBC", "SHA256",
                   "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"],
        0x00C026: ["ECDH", "ECDSA", "AES_256_CBC", "SHA384",
                   "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"],
        0x00C027: ["ECDHE", "RSA", "AES_128_CBC", "SHA256",
                   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"],
        0x00C028: ["ECDHE", "RSA", "AES_256_CBC", "SHA384",
                   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"],
        0x00C029: ["ECDH", "RSA", "AES_128_CBC", "SHA256",
                   "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"],
        0x00C02A: ["ECDH", "RSA", "AES_256_CBC", "SHA384",
                   "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"],
        0x00C02B: ["ECDHE", "ECDSA", "AES_128_GCM", "SHA256",
                   "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"],
        0x00C02C: ["ECDHE", "ECDSA", "AES_256_GCM", "SHA384",
                   "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"],
        0x00C02D: ["ECDH", "ECDSA", "AES_128_GCM", "SHA256",
                   "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"],
        0x00C02E: ["ECDH", "ECDSA", "AES_256_GCM", "SHA384",
                   "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"],
        0x00C02F: ["ECDHE", "RSA", "AES_128_GCM", "SHA256",
                   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
        0x00C030: ["ECDHE", "RSA", "AES_256_GCM", "SHA384",
                   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
        0x00C031: ["ECDH", "RSA", "AES_128_GCM", "SHA256",
                   "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"],
        0x00C032: ["ECDH", "RSA", "AES_256_GCM", "SHA384",
                   "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"],
        0x00C033: ["ECDHE", "PSK", "RC4_128", "SHA",
                   "TLS_ECDHE_PSK_WITH_RC4_128_SHA"],
        0x00C034: ["ECDHE", "PSK", "3DES_EDE_CBC", "SHA",
                   "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"],
        0x00C035: ["ECDHE", "PSK", "AES_128_CBC", "SHA",
                   "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"],
        0x00C036: ["ECDHE", "PSK", "AES_256_CBC", "SHA",
                   "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"],
        0x00C037: ["ECDHE", "PSK", "AES_128_CBC", "SHA256",
                   "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"],
        0x00C038: ["ECDHE", "PSK", "AES_256_CBC", "SHA384",
                   "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"],
        0x00C039: ["ECDHE", "PSK", "NULL", "SHA",
                   "TLS_ECDHE_PSK_WITH_NULL_SHA"],
        0x00C03A: ["ECDHE", "PSK", "NULL", "SHA256",
                   "TLS_ECDHE_PSK_WITH_NULL_SHA256"],
        0x00C03B: ["ECDHE", "PSK", "NULL", "SHA384",
                   "TLS_ECDHE_PSK_WITH_NULL_SHA384"],
        0x00FEFE: ["RSA_FIPS", "RSA_FIPS", "DES_CBC", "SHA",
                   "SSL_RSA_FIPS_WITH_DES_CBC_SHA"],
        0x00FEFF: ["RSA_FIPS", "RSA_FIPS", "3DES_EDE_CBC", "SHA",
                   "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"],
        0x00FFE0: ["RSA_FIPS", "RSA_FIPS", "3DES_EDE_CBC", "SHA",
                   "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"],
        0x00FFE1: ["RSA_FIPS", "RSA_FIPS", "DES_CBC", "SHA",
                   "SSL_RSA_FIPS_WITH_DES_CBC_SHA"],
        0x010080: ["RSA", "RSA", "RC4_128", "MD5",
                   "SSL2_RSA_WITH_RC4_128_MD5"],
        0x020080: ["RSA", "RSA", "RC4_128_EXPORT40", "MD5",
                   "SSL2_RSA_WITH_RC4_128_EXPORT40_MD5"],
        0x030080: ["RSA", "RSA", "RC2_CBC_128_CBC", "MD5",
                   "SSL2_RSA_WITH_RC2_CBC_128_CBC_MD5"],
        0x040080: ["RSA", "RSA", "RC2_CBC_128_CBC", "MD5",
                   "SSL2_RSA_WITH_RC2_CBC_128_CBC_MD5"],
        0x050080: ["RSA", "RSA", "IDEA_128_CBC", "MD5",
                   "SSL2_RSA_WITH_IDEA_128_CBC_MD5"],
        0x060040: ["RSA", "RSA", "DES_64_CBC", "MD5",
                   "SSL2_RSA_WITH_DES_64_CBC_MD5"],
        0x0700C0: ["RSA", "RSA", "DES_192_EDE3_CBC", "MD5",
                   "SSL2_RSA_WITH_DES_192_EDE3_CBC_MD5"],
        0x080080: ["RSA", "RSA", "RC4_64", "MD5",
                   "SSL2_RSA_WITH_RC4_64_MD5"],
        # 0x800001: ["PCT", "", "", "", "PCT_SSL_CERT_TYPE"],
        # 0x800003: ["PCT", "", "", "", "PCT_SSL_CERT_TYPE"],
        # 0x810001: ["PCT", "", "", "", "PCT_SSL_HASH_TYPE"],
        # 0x810003: ["PCT", "", "", "", "PCT_SSL_HASH_TYPE"],
        # 0x820001: ["PCT", "", "", "", "PCT_SSL_EXCH_TYPE"],
        # 0x830004: ["PCT", "", "", "", "PCT_SSL_CIPHER_TYPE_1ST_HALF"],
        # 0x842840: ["PCT1_MAC_BITS 128", "PCT", "", "",
        #             "PCT_SSL_CIPHER_TYPE_2ND_HAFF"],
        # 0x848040: ["PCT1_MAC_BITS 128", "PCT", "", "",
        #             "PCT_SSL_CIPHER_TYPE_2ND_HAFF"],
        # 0X8f8001: ["PCT1_VERSION_1", "PCT", "", "", "PCT_SSL_COMPAT"]
    }

    """ Constante décrivant des vulnérabilités communes. """
    NO_SERVICE = "Ne fournit aucun service"
    FEW_BIT_KEY = "La taille de clef insuffisante par rapport aux standards de\
    l'ANSSI"
    WEAK = "Cryptographiquement faible"
    NO_AUTH = "Données échangées chiffrées mais non authentifiées \
    (Man-In-The-Middle possible)"
    ALMOST_WEAK = "Considéré comme sûr, mais des attaques théoriques existent"
    POTENTIALLY_WEAK = "Sujet à des attaques par Brute-Force si la clef pré-\
            partagée n'est pas assez complexe"
    OBSOLETE = "Obsolète"

    """ Liste de dictionnaires répertoriant (selon leur objectif) : les
    algorithmes, leur niveaux de sécurité, une description et les
    vulnérabilités associés. """
    properties = [
        # Algorithmes d'échange de clef : (niveau de sécurité, détails)
        {
            "NULL": (
                5,
                [NO_SERVICE]
            ),
            "RSA": (
                0,
                ["Système à clef publique"]
            ),
            "RSA_EXPORT": (
                0,
                ["Système à clef publique conforme aux lois d'exportation des \
                États-Unis"]
            ),
            "DH": (
                0,
                ["Diffie-Hellman standard"]
            ),
            "DHE": (
                0,
                ["Diffie-Hellman éphémère"]
            ),
            "ECDH": (
                0,
                ["Diffie-Hellman standard par courbes elliptiques"]
            ),
            "ECDHE": (
                0,
                ["Diffie-Hellman éphémère par courbes elliptiques"]
            ),
            "FORTEZZA": (
                2,
                ["Système implémentant des algorithmes cryptographique de la \
                 NIST/NSA"]
            ),
            "KRB5": (
                0,
                ["Kerberos"]
            ),
            "KRB5_EXPORT": (
                0,
                ["Kerberos conforme aux lois d'exportation des États-Unis"]
            ),
            "PSK": (
                2,
                ["Système à clef pré-partagée",
                 POTENTIALLY_WEAK]
            ),
            "RSA_EXPORT 1024": (
                3,
                ["Système à clef publique conforme aux lois d'exportation des \
                 États-Unis",
                 FEW_BIT_KEY]
            ),
            "VKO GOST R 34.10-94": (
                2,
                ["Standard gouvernemental Russe",
                 WEAK]
            ),
            "VKO GOST R 34.10-2001": (
                0,
                ["Standard gouvernemental Russe"]
            ),
            "SRP": (
                0,
                ["Secure Remote Password, protocole d'authentification \
                 asymétrique"]
            ),
            "RSA_FIPS": (
                3,
                ["Système utilisé par SSLv3",
                 OBSOLETE]
            ),
            # "PCT": (
            #    2,
            #    []
            # ),
            # "PCT1_MAC_BITS 128": (
            #    2,
            #    []
            # )
        },

        # Protocoles d'authentification : (niveau de sécurité, détails)
        {
            "NULL": (
                5,
                [NO_SERVICE]
            ),
            "RSA": (
                0,
                ["Système à clef publique"]
            ),
            "RSA_EXPORT": (
                0,
                ["Système à clef publique conforme aux lois d'exportation des \
                 États-Unis"]
            ),
            "DSS": (
                0,
                ["Digital Signature Standard"]
            ),
            "Anon": (
                5,
                [NO_AUTH]
            ),
            "KEA": (
                2,
                ["Keyphrase Extraction Algorithm"]
            ),
            "KRB5": (
                0,
                ["Kerberos"]
            ),
            "KRB5_EXPORT": (
                0,
                ["Kerberos conforme aux lois d'exportation des États-Unis"]
            ),
            "PSK": (
                2,
                ["Système à clef pré-partagée",
                 POTENTIALLY_WEAK]
            ),
            "ECDSA": (
                0,
                ["Digital Signature Algorithm par courbes elliptiques"]
            ),
            "RSA_EXPORT 1024": (
                3,
                ["Système à clef publique conforme aux lois d'exportation des \
                 États-Unis",
                 FEW_BIT_KEY]
            ),
            "VKO GOST R 34.10-94": (
                3,
                ["Standard gouvernemental Russe",
                 WEAK]
            ),
            "VKO GOST R 34.10-2001": (
                0,
                ["Standard gouvernemental Russe"]
            ),
            "SHA": (
                2,
                ["Secure Hash Algorithm, standard publié par le NIST",
                 ALMOST_WEAK]
            ),
            "RSA_FIPS": (
                2,
                ["Système utilisé par SSLv3",
                 OBSOLETE]
            ),
            # "PCT": (
            #    2,
            #    []
            # )
        },

        # Algorithmes de chiffrement : (niveau de sécurité, détails)
        {
            "NULL": (
                5,
                [NO_SERVICE]
            ),
            "RC4_40": (
                5,
                ["Chiffrement à flot avec une clef de 40 bits",
                 FEW_BIT_KEY, WEAK, OBSOLETE + " (RFC 7465)"]
            ),
            "RC4_56": (
                5,
                ["Chiffrement à flot avec une clef de 56 bits",
                 FEW_BIT_KEY, WEAK, OBSOLETE + " (RFC 7465)"]
            ),
            "RC4_64": (
                5,
                ["Chiffrement à flot avec une clef de 64 bits",
                 FEW_BIT_KEY, WEAK, OBSOLETE + " (RFC 7465)"]
            ),
            "RC4_128": (
                5,
                ["Chiffrement à flot avec une clef de 128 bits",
                 WEAK, OBSOLETE + " (RFC 7465)"]
            ),
            "RC4_128_EXPORT40": (
                5,
                ["Chiffrement à flot avec une clef de 128 bits, conforme aux \
                 lois d'exportation des États-Unis",
                 FEW_BIT_KEY, WEAK]
            ),
            "RC2_CBC_40": (
                5,
                ["Chiffrement par bloc de 64 bits avec une clef de 40 bits",
                 FEW_BIT_KEY, WEAK]
            ),
            "RC2_CBC_56": (
                5,
                ["Chiffrement par bloc de 64 bits avec une clef de 56 bits",
                 FEW_BIT_KEY, WEAK]
            ),
            "RC2_CBC_128_CBC": (
                5,
                ["Chiffrement par bloc de 64 bits avec une clef de 128 bits",
                 WEAK]
            ),
            "IDEA_CBC": (
                2,
                ["International Data Encryption Algorithm, chiffrement par \
                 bloc de 64 bits avec une clef de 128 bits",
                 FEW_BIT_KEY, WEAK + "(sous certaines conditions)"]
            ),
            "IDEA_128_CBC": (
                0,
                ["International Data Encryption Algorithm, chiffrement par \
                 bloc de 128 bits avec une clef de 128 bits"]
            ),
            "DES_CBC": (
                3,
                ["Data Encryption Standard, chiffrement par blocs de 64 bits \
                 avec une clef de 56 bits",
                 FEW_BIT_KEY, WEAK + " (attaques par Brute-Force)"]
            ),
            "DES_CBC_40": (
                3,
                ["Variante de DES opérant sur des blocs de 40 bits",
                 FEW_BIT_KEY, WEAK]
            ),
            "DES40_CBC": (
                3,
                ["Variante internationale de DES employant une clef secrète \
                 pré-traitée pour fournir 40 bits efficaces",
                 WEAK]
            ),
            "DES_64_CBC": (
                3,
                ["Variante de DES avec une clef de 64 bits",
                 FEW_BIT_KEY, WEAK]
            ),
            "DES_192_EDE3_CBC": (
                2,
                [""]
            ),
            "3DES_EDE_CBC": (
                0,
                ["Variante de DES plus sûre"]
            ),
            "FORTEZZA_CBC": (
                0,
                ["Système implémentant des algorithmes cryptographique de la \
                 NIST/NSA"]
            ),
            "AES_128_CBC": (
                0,
                ["Advanced Encryption Standard, chiffrement par blocs de 128 \
                 bits avec une clef de 128 bits"]
            ),
            "AES_256_CBC": (
                0,
                ["Advanced Encryption Standard, chiffrement par blocs de 128 \
                 bits avec une clef de 256 bits"]
            ),
            "AES_128_GCM": (
                0,
                ["Advanced Encryption Standard, chiffrement par blocs de 128 \
                 bits avec une clef de 128 bits"]
            ),
            "AES_256_GCM": (
                0,
                ["Advanced Encryption Standard, chiffrement par blocs de 128 \
                 bits avec une clef de 256 bits"]
            ),
            "CAMELLIA_128_CBC": (
                0,
                ["Chiffrement par blocs de 128 bits avec une clef de 128 bits"]
            ),
            "CAMELLIA_256_CBC": (
                0,
                ["Chiffrement par blocs de 128 bits avec une clef de 256 bits"]
            ),
            "GOST28147": (
                0,
                ["Chiffrement par bloc de 64 bits avec une clef de 256 bits \
                 (standard Russe)"]
            ),
            "SEED_CBC": (
                0,
                ["Chiffrement par bloc de 128 bits avec une clef de 128 bits \
                 (standard Coréen)"]
            )
        },

        # Code MAC : (niveau de sécurité, détails)
        {
            "NULL": (
                5,
                [NO_SERVICE]
            ),
            "MD5": (
                5,
                ["Message Digest 5, produit une empreinte de 128 bits",
                 OBSOLETE]
            ),
            "SHA": (
                2,
                ["Secure Hash Algorithm, standard publié par le NIST, produit \
                 une empreinte de 160 bits",
                 ALMOST_WEAK]
            ),
            "SHA256": (
                0,
                ["Secure Hash Algorithm, standard publié par le NIST, produit \
                 une empreinte de 256 bits"]
            ),
            "SHA384": (
                0,
                ["Secure Hash Algorithm, standard publié par le NIST, produit \
                 une empreinte de 384 bits"]
            ),
            "GOST28147": (
                2,
                ["Standard Russe, produit une empreinte de 256 bits",
                 ALMOST_WEAK]
            ),
            "GOSTR3411": (
                2,
                ["Standard Russe, produit une empreinte de 256 ou 512 bits"]
            )
        }
    ]
