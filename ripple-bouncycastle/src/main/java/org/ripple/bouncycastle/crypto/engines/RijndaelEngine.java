package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * an implementation of rijndael, based on the documentation and reference implementation
 * by paulo barreto, vincent rijmen, for v2.0 august '99.
 * <p>
 * note: this implementation is based on information prior to final nist publication.
 */
public class rijndaelengine
    implements blockcipher
{
    private static final int maxrounds = 14;

    private static final int maxkc = (256/4);

    private static final byte[] logtable = {
        (byte)0,    (byte)0,    (byte)25,   (byte)1,    (byte)50,   (byte)2,    (byte)26,   (byte)198,
        (byte)75,   (byte)199,  (byte)27,   (byte)104,  (byte)51,   (byte)238,  (byte)223,  (byte)3,
        (byte)100,  (byte)4,    (byte)224,  (byte)14,   (byte)52,   (byte)141,  (byte)129,  (byte)239,
        (byte)76,   (byte)113,  (byte)8,    (byte)200,  (byte)248,  (byte)105,  (byte)28,   (byte)193,
        (byte)125,  (byte)194,  (byte)29,   (byte)181,  (byte)249,  (byte)185,  (byte)39,   (byte)106,
        (byte)77,   (byte)228,  (byte)166,  (byte)114,  (byte)154,  (byte)201,  (byte)9,    (byte)120,
        (byte)101,  (byte)47,   (byte)138,  (byte)5,    (byte)33,   (byte)15,   (byte)225,  (byte)36,
        (byte)18,   (byte)240,  (byte)130,  (byte)69,   (byte)53,   (byte)147,  (byte)218,  (byte)142,
        (byte)150,  (byte)143,  (byte)219,  (byte)189,  (byte)54,   (byte)208,  (byte)206,  (byte)148,
        (byte)19,   (byte)92,   (byte)210,  (byte)241,  (byte)64,   (byte)70,   (byte)131,  (byte)56,
        (byte)102,  (byte)221,  (byte)253,  (byte)48,   (byte)191,  (byte)6,    (byte)139,  (byte)98,
        (byte)179,  (byte)37,   (byte)226,  (byte)152,  (byte)34,   (byte)136,  (byte)145,  (byte)16,
        (byte)126,  (byte)110,  (byte)72,   (byte)195,  (byte)163,  (byte)182,  (byte)30,   (byte)66,
        (byte)58,   (byte)107,  (byte)40,   (byte)84,   (byte)250,  (byte)133,  (byte)61,   (byte)186,
        (byte)43,   (byte)121,  (byte)10,   (byte)21,   (byte)155,  (byte)159,  (byte)94,   (byte)202,
        (byte)78,   (byte)212,  (byte)172,  (byte)229,  (byte)243,  (byte)115,  (byte)167,  (byte)87,
        (byte)175,  (byte)88,   (byte)168,  (byte)80,   (byte)244,  (byte)234,  (byte)214,  (byte)116,
        (byte)79,   (byte)174,  (byte)233,  (byte)213,  (byte)231,  (byte)230,  (byte)173,  (byte)232,
        (byte)44,   (byte)215,  (byte)117,  (byte)122,  (byte)235,  (byte)22,   (byte)11,   (byte)245,
        (byte)89,   (byte)203,  (byte)95,   (byte)176,  (byte)156,  (byte)169,  (byte)81,   (byte)160,
        (byte)127,  (byte)12,   (byte)246,  (byte)111,  (byte)23,   (byte)196,  (byte)73,   (byte)236,
        (byte)216,  (byte)67,   (byte)31,   (byte)45,   (byte)164,  (byte)118,  (byte)123,  (byte)183,
        (byte)204,  (byte)187,  (byte)62,   (byte)90,   (byte)251,  (byte)96,   (byte)177,  (byte)134,
        (byte)59,   (byte)82,   (byte)161,  (byte)108,  (byte)170,  (byte)85,   (byte)41,   (byte)157,
        (byte)151,  (byte)178,  (byte)135,  (byte)144,  (byte)97,   (byte)190,  (byte)220,  (byte)252,
        (byte)188,  (byte)149,  (byte)207,  (byte)205,  (byte)55,   (byte)63,   (byte)91,   (byte)209,
        (byte)83,   (byte)57,   (byte)132,  (byte)60,   (byte)65,   (byte)162,  (byte)109,  (byte)71,
        (byte)20,   (byte)42,   (byte)158,  (byte)93,   (byte)86,   (byte)242,  (byte)211,  (byte)171,
        (byte)68,   (byte)17,   (byte)146,  (byte)217,  (byte)35,   (byte)32,   (byte)46,   (byte)137,
        (byte)180,  (byte)124,  (byte)184,  (byte)38,   (byte)119,  (byte)153,  (byte)227,  (byte)165,
        (byte)103,  (byte)74,   (byte)237,  (byte)222,  (byte)197,  (byte)49,   (byte)254,  (byte)24,
        (byte)13,   (byte)99,   (byte)140,  (byte)128,  (byte)192,  (byte)247,  (byte)112,  (byte)7
    };

    private static final byte[] alogtable = {
          (byte)0,   (byte)3,   (byte)5,  (byte)15,  (byte)17,  (byte)51,  (byte)85, (byte)255,  (byte)26,  (byte)46, (byte)114, (byte)150, (byte)161, (byte)248,  (byte)19,  (byte)53,
         (byte)95, (byte)225,  (byte)56,  (byte)72, (byte)216, (byte)115, (byte)149, (byte)164, (byte)247,   (byte)2,   (byte)6,  (byte)10,  (byte)30,  (byte)34, (byte)102, (byte)170,
        (byte)229,  (byte)52,  (byte)92, (byte)228,  (byte)55,  (byte)89, (byte)235,  (byte)38, (byte)106, (byte)190, (byte)217, (byte)112, (byte)144, (byte)171, (byte)230,  (byte)49,
         (byte)83, (byte)245,   (byte)4,  (byte)12,  (byte)20,  (byte)60,  (byte)68, (byte)204,  (byte)79, (byte)209, (byte)104, (byte)184, (byte)211, (byte)110, (byte)178, (byte)205,
         (byte)76, (byte)212, (byte)103, (byte)169, (byte)224,  (byte)59,  (byte)77, (byte)215,  (byte)98, (byte)166, (byte)241,   (byte)8,  (byte)24,  (byte)40, (byte)120, (byte)136,
        (byte)131, (byte)158, (byte)185, (byte)208, (byte)107, (byte)189, (byte)220, (byte)127, (byte)129, (byte)152, (byte)179, (byte)206,  (byte)73, (byte)219, (byte)118, (byte)154,
        (byte)181, (byte)196,  (byte)87, (byte)249,  (byte)16,  (byte)48,  (byte)80, (byte)240,  (byte)11,  (byte)29,  (byte)39, (byte)105, (byte)187, (byte)214,  (byte)97, (byte)163,
        (byte)254,  (byte)25,  (byte)43, (byte)125, (byte)135, (byte)146, (byte)173, (byte)236,  (byte)47, (byte)113, (byte)147, (byte)174, (byte)233,  (byte)32,  (byte)96, (byte)160,
        (byte)251,  (byte)22,  (byte)58,  (byte)78, (byte)210, (byte)109, (byte)183, (byte)194,  (byte)93, (byte)231,  (byte)50,  (byte)86, (byte)250,  (byte)21,  (byte)63,  (byte)65,
        (byte)195,  (byte)94, (byte)226,  (byte)61,  (byte)71, (byte)201,  (byte)64, (byte)192,  (byte)91, (byte)237,  (byte)44, (byte)116, (byte)156, (byte)191, (byte)218, (byte)117,
        (byte)159, (byte)186, (byte)213, (byte)100, (byte)172, (byte)239,  (byte)42, (byte)126, (byte)130, (byte)157, (byte)188, (byte)223, (byte)122, (byte)142, (byte)137, (byte)128,
        (byte)155, (byte)182, (byte)193,  (byte)88, (byte)232,  (byte)35, (byte)101, (byte)175, (byte)234,  (byte)37, (byte)111, (byte)177, (byte)200,  (byte)67, (byte)197,  (byte)84,
        (byte)252,  (byte)31,  (byte)33,  (byte)99, (byte)165, (byte)244,   (byte)7,   (byte)9,  (byte)27,  (byte)45, (byte)119, (byte)153, (byte)176, (byte)203,  (byte)70, (byte)202,
         (byte)69, (byte)207,  (byte)74, (byte)222, (byte)121, (byte)139, (byte)134, (byte)145, (byte)168, (byte)227,  (byte)62,  (byte)66, (byte)198,  (byte)81, (byte)243,  (byte)14,
         (byte)18,  (byte)54,  (byte)90, (byte)238,  (byte)41, (byte)123, (byte)141, (byte)140, (byte)143, (byte)138, (byte)133, (byte)148, (byte)167, (byte)242,  (byte)13,  (byte)23,
         (byte)57,  (byte)75, (byte)221, (byte)124, (byte)132, (byte)151, (byte)162, (byte)253,  (byte)28,  (byte)36, (byte)108, (byte)180, (byte)199,  (byte)82, (byte)246,   (byte)1,
          (byte)3,   (byte)5,  (byte)15,  (byte)17,  (byte)51,  (byte)85, (byte)255,  (byte)26,  (byte)46, (byte)114, (byte)150, (byte)161, (byte)248,  (byte)19,  (byte)53,
         (byte)95, (byte)225,  (byte)56,  (byte)72, (byte)216, (byte)115, (byte)149, (byte)164, (byte)247,   (byte)2,   (byte)6,  (byte)10,  (byte)30,  (byte)34, (byte)102, (byte)170,
        (byte)229,  (byte)52,  (byte)92, (byte)228,  (byte)55,  (byte)89, (byte)235,  (byte)38, (byte)106, (byte)190, (byte)217, (byte)112, (byte)144, (byte)171, (byte)230,  (byte)49,
         (byte)83, (byte)245,   (byte)4,  (byte)12,  (byte)20,  (byte)60,  (byte)68, (byte)204,  (byte)79, (byte)209, (byte)104, (byte)184, (byte)211, (byte)110, (byte)178, (byte)205,
         (byte)76, (byte)212, (byte)103, (byte)169, (byte)224,  (byte)59,  (byte)77, (byte)215,  (byte)98, (byte)166, (byte)241,   (byte)8,  (byte)24,  (byte)40, (byte)120, (byte)136,
        (byte)131, (byte)158, (byte)185, (byte)208, (byte)107, (byte)189, (byte)220, (byte)127, (byte)129, (byte)152, (byte)179, (byte)206,  (byte)73, (byte)219, (byte)118, (byte)154,
        (byte)181, (byte)196,  (byte)87, (byte)249,  (byte)16,  (byte)48,  (byte)80, (byte)240,  (byte)11,  (byte)29,  (byte)39, (byte)105, (byte)187, (byte)214,  (byte)97, (byte)163,
        (byte)254,  (byte)25,  (byte)43, (byte)125, (byte)135, (byte)146, (byte)173, (byte)236,  (byte)47, (byte)113, (byte)147, (byte)174, (byte)233,  (byte)32,  (byte)96, (byte)160,
        (byte)251,  (byte)22,  (byte)58,  (byte)78, (byte)210, (byte)109, (byte)183, (byte)194,  (byte)93, (byte)231,  (byte)50,  (byte)86, (byte)250,  (byte)21,  (byte)63,  (byte)65,
        (byte)195,  (byte)94, (byte)226,  (byte)61,  (byte)71, (byte)201,  (byte)64, (byte)192,  (byte)91, (byte)237,  (byte)44, (byte)116, (byte)156, (byte)191, (byte)218, (byte)117,
        (byte)159, (byte)186, (byte)213, (byte)100, (byte)172, (byte)239,  (byte)42, (byte)126, (byte)130, (byte)157, (byte)188, (byte)223, (byte)122, (byte)142, (byte)137, (byte)128,
        (byte)155, (byte)182, (byte)193,  (byte)88, (byte)232,  (byte)35, (byte)101, (byte)175, (byte)234,  (byte)37, (byte)111, (byte)177, (byte)200,  (byte)67, (byte)197,  (byte)84,
        (byte)252,  (byte)31,  (byte)33,  (byte)99, (byte)165, (byte)244,   (byte)7,   (byte)9,  (byte)27,  (byte)45, (byte)119, (byte)153, (byte)176, (byte)203,  (byte)70, (byte)202,
         (byte)69, (byte)207,  (byte)74, (byte)222, (byte)121, (byte)139, (byte)134, (byte)145, (byte)168, (byte)227,  (byte)62,  (byte)66, (byte)198,  (byte)81, (byte)243,  (byte)14,
         (byte)18,  (byte)54,  (byte)90, (byte)238,  (byte)41, (byte)123, (byte)141, (byte)140, (byte)143, (byte)138, (byte)133, (byte)148, (byte)167, (byte)242,  (byte)13,  (byte)23,
         (byte)57,  (byte)75, (byte)221, (byte)124, (byte)132, (byte)151, (byte)162, (byte)253,  (byte)28,  (byte)36, (byte)108, (byte)180, (byte)199,  (byte)82, (byte)246,   (byte)1,
        };

    private static final byte[] s = {
         (byte)99, (byte)124, (byte)119, (byte)123, (byte)242, (byte)107, (byte)111, (byte)197,  (byte)48,   (byte)1, (byte)103,  (byte)43, (byte)254, (byte)215, (byte)171, (byte)118,
        (byte)202, (byte)130, (byte)201, (byte)125, (byte)250,  (byte)89,  (byte)71, (byte)240, (byte)173, (byte)212, (byte)162, (byte)175, (byte)156, (byte)164, (byte)114, (byte)192,
        (byte)183, (byte)253, (byte)147,  (byte)38,  (byte)54,  (byte)63, (byte)247, (byte)204,  (byte)52, (byte)165, (byte)229, (byte)241, (byte)113, (byte)216,  (byte)49,  (byte)21,
          (byte)4, (byte)199,  (byte)35, (byte)195,  (byte)24, (byte)150,   (byte)5, (byte)154,   (byte)7,  (byte)18, (byte)128, (byte)226, (byte)235,  (byte)39, (byte)178, (byte)117,
          (byte)9, (byte)131,  (byte)44,  (byte)26,  (byte)27, (byte)110,  (byte)90, (byte)160,  (byte)82,  (byte)59, (byte)214, (byte)179,  (byte)41, (byte)227,  (byte)47, (byte)132,
         (byte)83, (byte)209,   (byte)0, (byte)237,  (byte)32, (byte)252, (byte)177,  (byte)91, (byte)106, (byte)203, (byte)190,  (byte)57,  (byte)74,  (byte)76,  (byte)88, (byte)207,
        (byte)208, (byte)239, (byte)170, (byte)251,  (byte)67,  (byte)77,  (byte)51, (byte)133,  (byte)69, (byte)249,   (byte)2, (byte)127,  (byte)80,  (byte)60, (byte)159, (byte)168,
         (byte)81, (byte)163,  (byte)64, (byte)143, (byte)146, (byte)157,  (byte)56, (byte)245, (byte)188, (byte)182, (byte)218,  (byte)33,  (byte)16, (byte)255, (byte)243, (byte)210,
        (byte)205,  (byte)12,  (byte)19, (byte)236,  (byte)95, (byte)151,  (byte)68,  (byte)23, (byte)196, (byte)167, (byte)126,  (byte)61, (byte)100,  (byte)93,  (byte)25, (byte)115,
         (byte)96, (byte)129,  (byte)79, (byte)220,  (byte)34,  (byte)42, (byte)144, (byte)136,  (byte)70, (byte)238, (byte)184,  (byte)20, (byte)222,  (byte)94,  (byte)11, (byte)219,
        (byte)224,  (byte)50,  (byte)58,  (byte)10,  (byte)73,   (byte)6,  (byte)36,  (byte)92, (byte)194, (byte)211, (byte)172,  (byte)98, (byte)145, (byte)149, (byte)228, (byte)121,
        (byte)231, (byte)200,  (byte)55, (byte)109, (byte)141, (byte)213,  (byte)78, (byte)169, (byte)108,  (byte)86, (byte)244, (byte)234, (byte)101, (byte)122, (byte)174,   (byte)8,
        (byte)186, (byte)120,  (byte)37,  (byte)46,  (byte)28, (byte)166, (byte)180, (byte)198, (byte)232, (byte)221, (byte)116,  (byte)31,  (byte)75, (byte)189, (byte)139, (byte)138,
        (byte)112,  (byte)62, (byte)181, (byte)102,  (byte)72,   (byte)3, (byte)246,  (byte)14,  (byte)97,  (byte)53,  (byte)87, (byte)185, (byte)134, (byte)193,  (byte)29, (byte)158,
        (byte)225, (byte)248, (byte)152,  (byte)17, (byte)105, (byte)217, (byte)142, (byte)148, (byte)155,  (byte)30, (byte)135, (byte)233, (byte)206,  (byte)85,  (byte)40, (byte)223,
        (byte)140, (byte)161, (byte)137,  (byte)13, (byte)191, (byte)230,  (byte)66, (byte)104,  (byte)65, (byte)153,  (byte)45,  (byte)15, (byte)176,  (byte)84, (byte)187,  (byte)22,
    };

    private static final byte[] si = {
         (byte)82,   (byte)9, (byte)106, (byte)213,  (byte)48,  (byte)54, (byte)165,  (byte)56, (byte)191,  (byte)64, (byte)163, (byte)158, (byte)129, (byte)243, (byte)215, (byte)251,
        (byte)124, (byte)227,  (byte)57, (byte)130, (byte)155,  (byte)47, (byte)255, (byte)135,  (byte)52, (byte)142,  (byte)67,  (byte)68, (byte)196, (byte)222, (byte)233, (byte)203,
         (byte)84, (byte)123, (byte)148,  (byte)50, (byte)166, (byte)194,  (byte)35,  (byte)61, (byte)238,  (byte)76, (byte)149,  (byte)11,  (byte)66, (byte)250, (byte)195,  (byte)78,
          (byte)8,  (byte)46, (byte)161, (byte)102,  (byte)40, (byte)217,  (byte)36, (byte)178, (byte)118,  (byte)91, (byte)162,  (byte)73, (byte)109, (byte)139, (byte)209,  (byte)37,
        (byte)114, (byte)248, (byte)246, (byte)100, (byte)134, (byte)104, (byte)152,  (byte)22, (byte)212, (byte)164,  (byte)92, (byte)204,  (byte)93, (byte)101, (byte)182, (byte)146,
        (byte)108, (byte)112,  (byte)72,  (byte)80, (byte)253, (byte)237, (byte)185, (byte)218,  (byte)94,  (byte)21,  (byte)70,  (byte)87, (byte)167, (byte)141, (byte)157, (byte)132,
        (byte)144, (byte)216, (byte)171,   (byte)0, (byte)140, (byte)188, (byte)211,  (byte)10, (byte)247, (byte)228,  (byte)88,   (byte)5, (byte)184, (byte)179,  (byte)69,   (byte)6,
        (byte)208,  (byte)44,  (byte)30, (byte)143, (byte)202,  (byte)63,  (byte)15,   (byte)2, (byte)193, (byte)175, (byte)189,   (byte)3,   (byte)1,  (byte)19, (byte)138, (byte)107,
         (byte)58, (byte)145,  (byte)17,  (byte)65,  (byte)79, (byte)103, (byte)220, (byte)234, (byte)151, (byte)242, (byte)207, (byte)206, (byte)240, (byte)180, (byte)230, (byte)115,
        (byte)150, (byte)172, (byte)116,  (byte)34, (byte)231, (byte)173,  (byte)53, (byte)133, (byte)226, (byte)249,  (byte)55, (byte)232,  (byte)28, (byte)117, (byte)223, (byte)110,
         (byte)71, (byte)241,  (byte)26, (byte)113,  (byte)29,  (byte)41, (byte)197, (byte)137, (byte)111, (byte)183,  (byte)98,  (byte)14, (byte)170,  (byte)24, (byte)190,  (byte)27,
        (byte)252,  (byte)86,  (byte)62,  (byte)75, (byte)198, (byte)210, (byte)121,  (byte)32, (byte)154, (byte)219, (byte)192, (byte)254, (byte)120, (byte)205,  (byte)90, (byte)244,
         (byte)31, (byte)221, (byte)168,  (byte)51, (byte)136,   (byte)7, (byte)199,  (byte)49, (byte)177,  (byte)18,  (byte)16,  (byte)89,  (byte)39, (byte)128, (byte)236,  (byte)95,
         (byte)96,  (byte)81, (byte)127, (byte)169,  (byte)25, (byte)181,  (byte)74,  (byte)13,  (byte)45, (byte)229, (byte)122, (byte)159, (byte)147, (byte)201, (byte)156, (byte)239,
        (byte)160, (byte)224,  (byte)59,  (byte)77, (byte)174,  (byte)42, (byte)245, (byte)176, (byte)200, (byte)235, (byte)187,  (byte)60, (byte)131,  (byte)83, (byte)153,  (byte)97,
         (byte)23,  (byte)43,   (byte)4, (byte)126, (byte)186, (byte)119, (byte)214,  (byte)38, (byte)225, (byte)105,  (byte)20,  (byte)99,  (byte)85,  (byte)33,  (byte)12, (byte)125,
        };

    private static final int[] rcon = {
          0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91 };

    static byte[][] shifts0 =
    {
       { 0, 8, 16, 24 },
       { 0, 8, 16, 24 },
       { 0, 8, 16, 24 },
       { 0, 8, 16, 32 },
       { 0, 8, 24, 32 }
    };

    static byte[][] shifts1 =
    {
       { 0, 24, 16, 8 },
       { 0, 32, 24, 16 },
       { 0, 40, 32, 24 },
       { 0, 48, 40, 24 },
       { 0, 56, 40, 32 }
    };

    /**
     * multiply two elements of gf(2^m)
     * needed for mixcolumn and invmixcolumn
     */
    private byte mul0x2(
        int b)
    {
        if (b != 0)
        {
            return alogtable[25 + (logtable[b] & 0xff)];
        }
        else
        {
            return 0;
        }
    }

    private byte mul0x3(
        int b)
    {
        if (b != 0)
        {
            return alogtable[1 + (logtable[b] & 0xff)];
        }
        else
        {
            return 0;
        }
    }

    private byte mul0x9(
        int b)
    {
        if (b >= 0)
        {
            return alogtable[199 + b];
        }
        else
        {
            return 0;
        }
    }

    private byte mul0xb(
        int b)
    {
        if (b >= 0)
        {
            return alogtable[104 + b];
        }
        else
        {
            return 0;
        }
    }

    private byte mul0xd(
        int b)
    {
        if (b >= 0)
        {
            return alogtable[238 + b];
        }
        else
        {
            return 0;
        }
    }

    private byte mul0xe(
        int b)
    {
        if (b >= 0)
        {
            return alogtable[223 + b];
        }
        else
        {
            return 0;
        }
    }

    /**
     * xor corresponding text input and round key input bytes
     */
    private void keyaddition(
        long[] rk)
    {
        a0 ^= rk[0];
        a1 ^= rk[1];
        a2 ^= rk[2];
        a3 ^= rk[3];
    }

    private long shift(
        long    r,
        int     shift)
    {
        return (((r >>> shift) | (r << (bc - shift)))) & bc_mask;
    }

    /**
     * row 0 remains unchanged
     * the other three rows are shifted a variable amount
     */
    private void shiftrow(
        byte[]      shiftssc)
    {
        a1 = shift(a1, shiftssc[1]);
        a2 = shift(a2, shiftssc[2]);
        a3 = shift(a3, shiftssc[3]);
    }

    private long applys(
        long    r,
        byte[]  box)
    {
        long    res = 0;

        for (int j = 0; j < bc; j += 8)
        {
            res |= (long)(box[(int)((r >> j) & 0xff)] & 0xff) << j;
        }

        return res;
    }

    /**
     * replace every byte of the input by the byte at that place
     * in the nonlinear s-box
     */
    private void substitution(
        byte[]      box)
    {
        a0 = applys(a0, box);
        a1 = applys(a1, box);
        a2 = applys(a2, box);
        a3 = applys(a3, box);
    }

    /**
     * mix the bytes of every column in a linear way
     */
    private void mixcolumn()
    {
        long r0, r1, r2, r3;

        r0 = r1 = r2 = r3 = 0;

        for (int j = 0; j < bc; j += 8)
        {
            int a0 = (int)((a0 >> j) & 0xff);
            int a1 = (int)((a1 >> j) & 0xff);
            int a2 = (int)((a2 >> j) & 0xff);
            int a3 = (int)((a3 >> j) & 0xff);

            r0 |= (long)((mul0x2(a0) ^ mul0x3(a1) ^ a2 ^ a3) & 0xff) << j;

            r1 |= (long)((mul0x2(a1) ^ mul0x3(a2) ^ a3 ^ a0) & 0xff) << j;

            r2 |= (long)((mul0x2(a2) ^ mul0x3(a3) ^ a0 ^ a1) & 0xff) << j;

            r3 |= (long)((mul0x2(a3) ^ mul0x3(a0) ^ a1 ^ a2) & 0xff) << j;
        }

        a0 = r0;
        a1 = r1;
        a2 = r2;
        a3 = r3;
    }

    /**
     * mix the bytes of every column in a linear way
     * this is the opposite operation of mixcolumn
     */
    private void invmixcolumn()
    {
        long r0, r1, r2, r3;

        r0 = r1 = r2 = r3 = 0;
        for (int j = 0; j < bc; j += 8)
        {
            int a0 = (int)((a0 >> j) & 0xff);
            int a1 = (int)((a1 >> j) & 0xff);
            int a2 = (int)((a2 >> j) & 0xff);
            int a3 = (int)((a3 >> j) & 0xff);

            //
            // pre-lookup the log table
            //
            a0 = (a0 != 0) ? (logtable[a0 & 0xff] & 0xff) : -1;
            a1 = (a1 != 0) ? (logtable[a1 & 0xff] & 0xff) : -1;
            a2 = (a2 != 0) ? (logtable[a2 & 0xff] & 0xff) : -1;
            a3 = (a3 != 0) ? (logtable[a3 & 0xff] & 0xff) : -1;

            r0 |= (long)((mul0xe(a0) ^ mul0xb(a1) ^ mul0xd(a2) ^ mul0x9(a3)) & 0xff) << j;

            r1 |= (long)((mul0xe(a1) ^ mul0xb(a2) ^ mul0xd(a3) ^ mul0x9(a0)) & 0xff) << j;

            r2 |= (long)((mul0xe(a2) ^ mul0xb(a3) ^ mul0xd(a0) ^ mul0x9(a1)) & 0xff) << j;

            r3 |= (long)((mul0xe(a3) ^ mul0xb(a0) ^ mul0xd(a1) ^ mul0x9(a2)) & 0xff) << j;
        }

        a0 = r0;
        a1 = r1;
        a2 = r2;
        a3 = r3;
    }

    /**
     * calculate the necessary round keys
     * the number of calculations depends on keybits and blockbits
     */
    private long[][] generateworkingkey(
        byte[]      key)
    {
        int         kc;
        int         t, rconpointer = 0;
        int         keybits = key.length * 8;
        byte[][]    tk = new byte[4][maxkc];
        long[][]    w = new long[maxrounds+1][4];

        switch (keybits)
        {
        case 128:
            kc = 4;
            break;
        case 160:
            kc = 5;
            break;
        case 192:
            kc = 6;
            break;
        case 224:
            kc = 7;
            break;
        case 256:
            kc = 8;
            break;
        default :
            throw new illegalargumentexception("key length not 128/160/192/224/256 bits.");
        }

        if (keybits >= blockbits)
        {
            rounds = kc + 6;
        }
        else
        {
            rounds = (bc / 8) + 6;
        }

        //
        // copy the key into the processing area
        //
        int index = 0;

        for (int i = 0; i < key.length; i++)
        {
            tk[i % 4][i / 4] = key[index++];
        }

        t = 0;

        //
        // copy values into round key array
        //
        for (int j = 0; (j < kc) && (t < (rounds+1)*(bc / 8)); j++, t++)
        {
            for (int i = 0; i < 4; i++)
            {
                w[t / (bc / 8)][i] |= (long)(tk[i][j] & 0xff) << ((t * 8) % bc);
            }
        }

        //
        // while not enough round key material calculated
        // calculate new values
        //
        while (t < (rounds+1)*(bc/8))
        {
            for (int i = 0; i < 4; i++)
            {
                tk[i][0] ^= s[tk[(i+1)%4][kc-1] & 0xff];
            }
            tk[0][0] ^= rcon[rconpointer++];

            if (kc <= 6)
            {
                for (int j = 1; j < kc; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        tk[i][j] ^= tk[i][j-1];
                    }
                }
            }
            else
            {
                for (int j = 1; j < 4; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        tk[i][j] ^= tk[i][j-1];
                    }
                }
                for (int i = 0; i < 4; i++)
                {
                    tk[i][4] ^= s[tk[i][3] & 0xff];
                }
                for (int j = 5; j < kc; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        tk[i][j] ^= tk[i][j-1];
                    }
                }
            }

            //
            // copy values into round key array
            //
            for (int j = 0; (j < kc) && (t < (rounds+1)*(bc/8)); j++, t++)
            {
                for (int i = 0; i < 4; i++)
                {
                    w[t / (bc/8)][i] |= (long)(tk[i][j] & 0xff) << ((t * 8) % (bc));
                }
            }
        }

        return w;
    }

    private int         bc;
    private long        bc_mask;
    private int         rounds;
    private int         blockbits;
    private long[][]    workingkey;
    private long        a0, a1, a2, a3;
    private boolean     forencryption;
    private byte[]      shifts0sc;
    private byte[]      shifts1sc;

    /**
     * default constructor - 128 bit block size.
     */
    public rijndaelengine()
    {
        this(128);
    }

    /**
     * basic constructor - set the cipher up for a given blocksize
     *
     * @param blockbits the blocksize in bits, must be 128, 192, or 256.
     */
    public rijndaelengine(
        int blockbits)
    {
        switch (blockbits)
        {
        case 128:
            bc = 32;
            bc_mask = 0xffffffffl;
            shifts0sc = shifts0[0];
            shifts1sc = shifts1[0];
            break;
        case 160:
            bc = 40;
            bc_mask = 0xffffffffffl;
            shifts0sc = shifts0[1];
            shifts1sc = shifts1[1];
            break;
        case 192:
            bc = 48;
            bc_mask = 0xffffffffffffl;
            shifts0sc = shifts0[2];
            shifts1sc = shifts1[2];
            break;
        case 224:
            bc = 56;
            bc_mask = 0xffffffffffffffl;
            shifts0sc = shifts0[3];
            shifts1sc = shifts1[3];
            break;
        case 256:
            bc = 64;
            bc_mask = 0xffffffffffffffffl;
            shifts0sc = shifts0[4];
            shifts1sc = shifts1[4];
            break;
        default:
            throw new illegalargumentexception("unknown blocksize to rijndael");
        }

        this.blockbits = blockbits;
    }

    /**
     * initialise a rijndael cipher.
     *
     * @param forencryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean           forencryption,
        cipherparameters  params)
    {
        if (params instanceof keyparameter)
        {
            workingkey = generateworkingkey(((keyparameter)params).getkey());
            this.forencryption = forencryption;
            return;
        }

        throw new illegalargumentexception("invalid parameter passed to rijndael init - " + params.getclass().getname());
    }

    public string getalgorithmname()
    {
        return "rijndael";
    }

    public int getblocksize()
    {
        return bc / 2;
    }

    public int processblock(
        byte[] in,
        int inoff,
        byte[] out,
        int outoff)
    {
        if (workingkey == null)
        {
            throw new illegalstateexception("rijndael engine not initialised");
        }

        if ((inoff + (bc / 2)) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + (bc / 2)) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }

        if (forencryption)
        {
            unpackblock(in, inoff);
            encryptblock(workingkey);
            packblock(out, outoff);
        }
        else
        {
            unpackblock(in, inoff);
            decryptblock(workingkey);
            packblock(out, outoff);
        }

        return bc / 2;
    }

    public void reset()
    {
    }

    private void unpackblock(
        byte[]      bytes,
        int         off)
    {
        int     index = off;

        a0 = (bytes[index++] & 0xff);
        a1 = (bytes[index++] & 0xff);
        a2 = (bytes[index++] & 0xff);
        a3 = (bytes[index++] & 0xff);

        for (int j = 8; j != bc; j += 8)
        {
            a0 |= (long)(bytes[index++] & 0xff) << j;
            a1 |= (long)(bytes[index++] & 0xff) << j;
            a2 |= (long)(bytes[index++] & 0xff) << j;
            a3 |= (long)(bytes[index++] & 0xff) << j;
        }
    }

    private void packblock(
        byte[]      bytes,
        int         off)
    {
        int     index = off;

        for (int j = 0; j != bc; j += 8)
        {
            bytes[index++] = (byte)(a0 >> j);
            bytes[index++] = (byte)(a1 >> j);
            bytes[index++] = (byte)(a2 >> j);
            bytes[index++] = (byte)(a3 >> j);
        }
    }

    private void encryptblock(
        long[][] rk)
    {
        int r;

        //
        // begin with a key addition
        //
        keyaddition(rk[0]);

        //
        // rounds-1 ordinary rounds
        //
        for (r = 1; r < rounds; r++)
        {
            substitution(s);
            shiftrow(shifts0sc);
            mixcolumn();
            keyaddition(rk[r]);
        }

        //
        // last round is special: there is no mixcolumn
        //
        substitution(s);
        shiftrow(shifts0sc);
        keyaddition(rk[rounds]);
    }

    private void decryptblock(
        long[][] rk)
    {
        int r;

        // to decrypt: apply the inverse operations of the encrypt routine,
        //             in opposite order
        //
        // (keyaddition is an involution: it 's equal to its inverse)
        // (the inverse of substitution with table s is substitution with the inverse table of s)
        // (the inverse of shiftrow is shiftrow over a suitable distance)
        //

        // first the special round:
        //   without invmixcolumn
        //   with extra keyaddition
        //
        keyaddition(rk[rounds]);
        substitution(si);
        shiftrow(shifts1sc);

        //
        // rounds-1 ordinary rounds
        //
        for (r = rounds-1; r > 0; r--)
        {
            keyaddition(rk[r]);
            invmixcolumn();
            substitution(si);
            shiftrow(shifts1sc);
        }

        //
        // end with the extra key addition
        //
        keyaddition(rk[0]);
    }
}
