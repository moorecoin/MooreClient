package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * an implementation of the aes (rijndael), from fips-197.
 * <p>
 * for further details see: <a href="http://csrc.nist.gov/encryption/aes/">http://csrc.nist.gov/encryption/aes/</a>.
 *
 * this implementation is based on optimizations from dr. brian gladman's paper and c code at
 * <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
 *
 * there are three levels of tradeoff of speed vs memory
 * because java has no preprocessor, they are written as three separate classes from which to choose
 *
 * the fastest uses 8kbytes of static tables to precompute round calculations, 4 256 word tables for encryption
 * and 4 for decryption.
 *
 * the middle performance version uses only one 256 word table for each, for a total of 2kbytes,
 * adding 12 rotate operations per round to compute the values contained in the other tables from
 * the contents of the first.
 *
 * the slowest version uses no static tables at all and computes the values in each round.
 * <p>
 * this file contains the middle performance version with 2kbytes of static tables for round precomputation.
 *
 */
public class aesengine
    implements blockcipher
{
    // the s box
    private static final byte[] s = {
        (byte)99, (byte)124, (byte)119, (byte)123, (byte)242, (byte)107, (byte)111, (byte)197,
        (byte)48,   (byte)1, (byte)103,  (byte)43, (byte)254, (byte)215, (byte)171, (byte)118,
        (byte)202, (byte)130, (byte)201, (byte)125, (byte)250,  (byte)89,  (byte)71, (byte)240,
        (byte)173, (byte)212, (byte)162, (byte)175, (byte)156, (byte)164, (byte)114, (byte)192,
        (byte)183, (byte)253, (byte)147,  (byte)38,  (byte)54,  (byte)63, (byte)247, (byte)204,
        (byte)52, (byte)165, (byte)229, (byte)241, (byte)113, (byte)216,  (byte)49,  (byte)21,
        (byte)4, (byte)199,  (byte)35, (byte)195,  (byte)24, (byte)150,   (byte)5, (byte)154,
        (byte)7,  (byte)18, (byte)128, (byte)226, (byte)235,  (byte)39, (byte)178, (byte)117,
        (byte)9, (byte)131,  (byte)44,  (byte)26,  (byte)27, (byte)110,  (byte)90, (byte)160,
        (byte)82,  (byte)59, (byte)214, (byte)179,  (byte)41, (byte)227,  (byte)47, (byte)132,
        (byte)83, (byte)209,   (byte)0, (byte)237,  (byte)32, (byte)252, (byte)177,  (byte)91,
        (byte)106, (byte)203, (byte)190,  (byte)57,  (byte)74,  (byte)76,  (byte)88, (byte)207,
        (byte)208, (byte)239, (byte)170, (byte)251,  (byte)67,  (byte)77,  (byte)51, (byte)133,
        (byte)69, (byte)249,   (byte)2, (byte)127,  (byte)80,  (byte)60, (byte)159, (byte)168,
        (byte)81, (byte)163,  (byte)64, (byte)143, (byte)146, (byte)157,  (byte)56, (byte)245,
        (byte)188, (byte)182, (byte)218,  (byte)33,  (byte)16, (byte)255, (byte)243, (byte)210,
        (byte)205,  (byte)12,  (byte)19, (byte)236,  (byte)95, (byte)151,  (byte)68,  (byte)23,
        (byte)196, (byte)167, (byte)126,  (byte)61, (byte)100,  (byte)93,  (byte)25, (byte)115,
        (byte)96, (byte)129,  (byte)79, (byte)220,  (byte)34,  (byte)42, (byte)144, (byte)136,
        (byte)70, (byte)238, (byte)184,  (byte)20, (byte)222,  (byte)94,  (byte)11, (byte)219,
        (byte)224,  (byte)50,  (byte)58,  (byte)10,  (byte)73,   (byte)6,  (byte)36,  (byte)92,
        (byte)194, (byte)211, (byte)172,  (byte)98, (byte)145, (byte)149, (byte)228, (byte)121,
        (byte)231, (byte)200,  (byte)55, (byte)109, (byte)141, (byte)213,  (byte)78, (byte)169,
        (byte)108,  (byte)86, (byte)244, (byte)234, (byte)101, (byte)122, (byte)174,   (byte)8,
        (byte)186, (byte)120,  (byte)37,  (byte)46,  (byte)28, (byte)166, (byte)180, (byte)198,
        (byte)232, (byte)221, (byte)116,  (byte)31,  (byte)75, (byte)189, (byte)139, (byte)138,
        (byte)112,  (byte)62, (byte)181, (byte)102,  (byte)72,   (byte)3, (byte)246,  (byte)14,
        (byte)97,  (byte)53,  (byte)87, (byte)185, (byte)134, (byte)193,  (byte)29, (byte)158,
        (byte)225, (byte)248, (byte)152,  (byte)17, (byte)105, (byte)217, (byte)142, (byte)148,
        (byte)155,  (byte)30, (byte)135, (byte)233, (byte)206,  (byte)85,  (byte)40, (byte)223,
        (byte)140, (byte)161, (byte)137,  (byte)13, (byte)191, (byte)230,  (byte)66, (byte)104,
        (byte)65, (byte)153,  (byte)45,  (byte)15, (byte)176,  (byte)84, (byte)187,  (byte)22,
    };

    // the inverse s-box
    private static final byte[] si = {
        (byte)82,   (byte)9, (byte)106, (byte)213,  (byte)48,  (byte)54, (byte)165,  (byte)56,
        (byte)191,  (byte)64, (byte)163, (byte)158, (byte)129, (byte)243, (byte)215, (byte)251,
        (byte)124, (byte)227,  (byte)57, (byte)130, (byte)155,  (byte)47, (byte)255, (byte)135,
        (byte)52, (byte)142,  (byte)67,  (byte)68, (byte)196, (byte)222, (byte)233, (byte)203,
        (byte)84, (byte)123, (byte)148,  (byte)50, (byte)166, (byte)194,  (byte)35,  (byte)61,
        (byte)238,  (byte)76, (byte)149,  (byte)11,  (byte)66, (byte)250, (byte)195,  (byte)78,
        (byte)8,  (byte)46, (byte)161, (byte)102,  (byte)40, (byte)217,  (byte)36, (byte)178,
        (byte)118,  (byte)91, (byte)162,  (byte)73, (byte)109, (byte)139, (byte)209,  (byte)37,
        (byte)114, (byte)248, (byte)246, (byte)100, (byte)134, (byte)104, (byte)152,  (byte)22,
        (byte)212, (byte)164,  (byte)92, (byte)204,  (byte)93, (byte)101, (byte)182, (byte)146,
        (byte)108, (byte)112,  (byte)72,  (byte)80, (byte)253, (byte)237, (byte)185, (byte)218,
        (byte)94,  (byte)21,  (byte)70,  (byte)87, (byte)167, (byte)141, (byte)157, (byte)132,
        (byte)144, (byte)216, (byte)171,   (byte)0, (byte)140, (byte)188, (byte)211,  (byte)10,
        (byte)247, (byte)228,  (byte)88,   (byte)5, (byte)184, (byte)179,  (byte)69,   (byte)6,
        (byte)208,  (byte)44,  (byte)30, (byte)143, (byte)202,  (byte)63,  (byte)15,   (byte)2,
        (byte)193, (byte)175, (byte)189,   (byte)3,   (byte)1,  (byte)19, (byte)138, (byte)107,
        (byte)58, (byte)145,  (byte)17,  (byte)65,  (byte)79, (byte)103, (byte)220, (byte)234,
        (byte)151, (byte)242, (byte)207, (byte)206, (byte)240, (byte)180, (byte)230, (byte)115,
        (byte)150, (byte)172, (byte)116,  (byte)34, (byte)231, (byte)173,  (byte)53, (byte)133,
        (byte)226, (byte)249,  (byte)55, (byte)232,  (byte)28, (byte)117, (byte)223, (byte)110,
        (byte)71, (byte)241,  (byte)26, (byte)113,  (byte)29,  (byte)41, (byte)197, (byte)137,
        (byte)111, (byte)183,  (byte)98,  (byte)14, (byte)170,  (byte)24, (byte)190,  (byte)27,
        (byte)252,  (byte)86,  (byte)62,  (byte)75, (byte)198, (byte)210, (byte)121,  (byte)32,
        (byte)154, (byte)219, (byte)192, (byte)254, (byte)120, (byte)205,  (byte)90, (byte)244,
        (byte)31, (byte)221, (byte)168,  (byte)51, (byte)136,   (byte)7, (byte)199,  (byte)49,
        (byte)177,  (byte)18,  (byte)16,  (byte)89,  (byte)39, (byte)128, (byte)236,  (byte)95,
        (byte)96,  (byte)81, (byte)127, (byte)169,  (byte)25, (byte)181,  (byte)74,  (byte)13,
        (byte)45, (byte)229, (byte)122, (byte)159, (byte)147, (byte)201, (byte)156, (byte)239,
        (byte)160, (byte)224,  (byte)59,  (byte)77, (byte)174,  (byte)42, (byte)245, (byte)176,
        (byte)200, (byte)235, (byte)187,  (byte)60, (byte)131,  (byte)83, (byte)153,  (byte)97,
        (byte)23,  (byte)43,   (byte)4, (byte)126, (byte)186, (byte)119, (byte)214,  (byte)38,
        (byte)225, (byte)105,  (byte)20,  (byte)99,  (byte)85,  (byte)33,  (byte)12, (byte)125,
        };

    // vector used in calculating key schedule (powers of x in gf(256))
    private static final int[] rcon = {
         0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
         0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91 };

    // precomputation tables of calculations for rounds
    private static final int[] t0 =
    {
     0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0x0df2f2ff, 
     0xbd6b6bd6, 0xb16f6fde, 0x54c5c591, 0x50303060, 0x03010102, 
     0xa96767ce, 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 
     0x9a7676ec, 0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa, 
     0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb, 0xecadad41, 
     0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453, 
     0x967272e4, 0x5bc0c09b, 0xc2b7b775, 0x1cfdfde1, 0xae93933d, 
     0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83, 
     0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9, 0x937171e2, 
     0x73d8d8ab, 0x53313162, 0x3f15152a, 0x0c040408, 0x52c7c795, 
     0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637, 0x0f05050a, 
     0xb59a9a2f, 0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df, 
     0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea, 0x1b090912, 
     0x9e83831d, 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc, 
     0xee5a5ab4, 0xfba0a05b, 0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 
     0xceb3b37d, 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413, 
     0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040, 
     0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6, 0xbe6a6ad4, 0x46cbcb8d, 
     0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0, 
     0x4acfcf85, 0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed, 
     0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511, 0xcf45458a, 
     0x10f9f9e9, 0x06020204, 0x817f7ffe, 0xf05050a0, 0x443c3c78, 
     0xba9f9f25, 0xe3a8a84b, 0xf35151a2, 0xfea3a35d, 0xc0404080, 
     0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1, 
     0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020, 
     0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18, 
     0x35131326, 0x2fececc3, 0xe15f5fbe, 0xa2979735, 0xcc444488, 
     0x3917172e, 0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a, 
     0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6, 0xa06060c0, 
     0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54, 
     0xab90903b, 0x8388880b, 0xca46468c, 0x29eeeec7, 0xd3b8b86b, 
     0x3c141428, 0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad, 
     0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, 0xdb494992, 
     0x0a06060c, 0x6c242448, 0xe45c5cb8, 0x5dc2c29f, 0x6ed3d3bd, 
     0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531, 0x37e4e4d3, 
     0x8b7979f2, 0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda, 
     0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949, 0xb46c6cd8, 
     0xfa5656ac, 0x07f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4, 
     0xe9aeae47, 0x18080810, 0xd5baba6f, 0x887878f0, 0x6f25254a, 
     0x722e2e5c, 0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697, 
     0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e, 0xdd4b4b96, 
     0xdcbdbd61, 0x868b8b0d, 0x858a8a0f, 0x907070e0, 0x423e3e7c, 
     0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x05030306, 0x01f6f6f7, 
     0x120e0e1c, 0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969, 
     0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27, 0x38e1e1d9, 
     0x13f8f8eb, 0xb398982b, 0x33111122, 0xbb6969d2, 0x70d9d9a9, 
     0x898e8e07, 0xa7949433, 0xb69b9b2d, 0x221e1e3c, 0x92878715, 
     0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5, 
     0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65, 
     0x31e6e6d7, 0xc6424284, 0xb86868d0, 0xc3414182, 0xb0999929, 
     0x772d2d5a, 0x110f0f1e, 0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 
     0x3a16162c};

private static final int[] tinv0 =
    {
     0x50a7f451, 0x5365417e, 0xc3a4171a, 0x965e273a, 0xcb6bab3b, 
     0xf1459d1f, 0xab58faac, 0x9303e34b, 0x55fa3020, 0xf66d76ad, 
     0x9176cc88, 0x254c02f5, 0xfcd7e54f, 0xd7cb2ac5, 0x80443526, 
     0x8fa362b5, 0x495ab1de, 0x671bba25, 0x980eea45, 0xe1c0fe5d, 
     0x02752fc3, 0x12f04c81, 0xa397468d, 0xc6f9d36b, 0xe75f8f03, 
     0x959c9215, 0xeb7a6dbf, 0xda595295, 0x2d83bed4, 0xd3217458, 
     0x2969e049, 0x44c8c98e, 0x6a89c275, 0x78798ef4, 0x6b3e5899, 
     0xdd71b927, 0xb64fe1be, 0x17ad88f0, 0x66ac20c9, 0xb43ace7d, 
     0x184adf63, 0x82311ae5, 0x60335197, 0x457f5362, 0xe07764b1, 
     0x84ae6bbb, 0x1ca081fe, 0x942b08f9, 0x58684870, 0x19fd458f, 
     0x876cde94, 0xb7f87b52, 0x23d373ab, 0xe2024b72, 0x578f1fe3, 
     0x2aab5566, 0x0728ebb2, 0x03c2b52f, 0x9a7bc586, 0xa50837d3, 
     0xf2872830, 0xb2a5bf23, 0xba6a0302, 0x5c8216ed, 0x2b1ccf8a, 
     0x92b479a7, 0xf0f207f3, 0xa1e2694e, 0xcdf4da65, 0xd5be0506, 
     0x1f6234d1, 0x8afea6c4, 0x9d532e34, 0xa055f3a2, 0x32e18a05, 
     0x75ebf6a4, 0x39ec830b, 0xaaef6040, 0x069f715e, 0x51106ebd, 
     0xf98a213e, 0x3d06dd96, 0xae053edd, 0x46bde64d, 0xb58d5491, 
     0x055dc471, 0x6fd40604, 0xff155060, 0x24fb9819, 0x97e9bdd6, 
     0xcc434089, 0x779ed967, 0xbd42e8b0, 0x888b8907, 0x385b19e7, 
     0xdbeec879, 0x470a7ca1, 0xe90f427c, 0xc91e84f8, 0x00000000, 
     0x83868009, 0x48ed2b32, 0xac70111e, 0x4e725a6c, 0xfbff0efd, 
     0x5638850f, 0x1ed5ae3d, 0x27392d36, 0x64d90f0a, 0x21a65c68, 
     0xd1545b9b, 0x3a2e3624, 0xb1670a0c, 0x0fe75793, 0xd296eeb4, 
     0x9e919b1b, 0x4fc5c080, 0xa220dc61, 0x694b775a, 0x161a121c, 
     0x0aba93e2, 0xe52aa0c0, 0x43e0223c, 0x1d171b12, 0x0b0d090e, 
     0xadc78bf2, 0xb9a8b62d, 0xc8a91e14, 0x8519f157, 0x4c0775af, 
     0xbbdd99ee, 0xfd607fa3, 0x9f2601f7, 0xbcf5725c, 0xc53b6644, 
     0x347efb5b, 0x7629438b, 0xdcc623cb, 0x68fcedb6, 0x63f1e4b8, 
     0xcadc31d7, 0x10856342, 0x40229713, 0x2011c684, 0x7d244a85, 
     0xf83dbbd2, 0x1132f9ae, 0x6da129c7, 0x4b2f9e1d, 0xf330b2dc, 
     0xec52860d, 0xd0e3c177, 0x6c16b32b, 0x99b970a9, 0xfa489411, 
     0x2264e947, 0xc48cfca8, 0x1a3ff0a0, 0xd82c7d56, 0xef903322, 
     0xc74e4987, 0xc1d138d9, 0xfea2ca8c, 0x360bd498, 0xcf81f5a6, 
     0x28de7aa5, 0x268eb7da, 0xa4bfad3f, 0xe49d3a2c, 0x0d927850, 
     0x9bcc5f6a, 0x62467e54, 0xc2138df6, 0xe8b8d890, 0x5ef7392e, 
     0xf5afc382, 0xbe805d9f, 0x7c93d069, 0xa92dd56f, 0xb31225cf, 
     0x3b99acc8, 0xa77d1810, 0x6e639ce8, 0x7bbb3bdb, 0x097826cd, 
     0xf418596e, 0x01b79aec, 0xa89a4f83, 0x656e95e6, 0x7ee6ffaa, 
     0x08cfbc21, 0xe6e815ef, 0xd99be7ba, 0xce366f4a, 0xd4099fea, 
     0xd67cb029, 0xafb2a431, 0x31233f2a, 0x3094a5c6, 0xc066a235, 
     0x37bc4e74, 0xa6ca82fc, 0xb0d090e0, 0x15d8a733, 0x4a9804f1, 
     0xf7daec41, 0x0e50cd7f, 0x2ff69117, 0x8dd64d76, 0x4db0ef43, 
     0x544daacc, 0xdf0496e4, 0xe3b5d19e, 0x1b886a4c, 0xb81f2cc1, 
     0x7f516546, 0x04ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb, 
     0x5a1d67b3, 0x52d2db92, 0x335610e9, 0x1347d66d, 0x8c61d79a, 
     0x7a0ca137, 0x8e14f859, 0x893c13eb, 0xee27a9ce, 0x35c961b7, 
     0xede51ce1, 0x3cb1477a, 0x59dfd29c, 0x3f73f255, 0x79ce1418, 
     0xbf37c773, 0xeacdf753, 0x5baafd5f, 0x146f3ddf, 0x86db4478, 
     0x81f3afca, 0x3ec468b9, 0x2c342438, 0x5f40a3c2, 0x72c31d16, 
     0x0c25e2bc, 0x8b493c28, 0x41950dff, 0x7101a839, 0xdeb30c08, 
     0x9ce4b4d8, 0x90c15664, 0x6184cb7b, 0x70b632d5, 0x745c6c48, 
     0x4257b8d0};

    private static int shift(int r, int shift)
    {
        return (r >>> shift) | (r << -shift);
    }

    /* multiply four bytes in gf(2^8) by 'x' {02} in parallel */

    private static final int m1 = 0x80808080;
    private static final int m2 = 0x7f7f7f7f;
    private static final int m3 = 0x0000001b;

    private static int ffmulx(int x)
    {
        return (((x & m2) << 1) ^ (((x & m1) >>> 7) * m3));
    }

    /* 
       the following defines provide alternative definitions of ffmulx that might
       give improved performance if a fast 32-bit multiply is not available.
       
       private int ffmulx(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); } 
       private static final int  m4 = 0x1b1b1b1b;
       private int ffmulx(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); } 

    */

    private static int inv_mcol(int x)
    {
        int f2 = ffmulx(x);
        int f4 = ffmulx(f2);
        int f8 = ffmulx(f4);
        int f9 = x ^ f8;
        
        return f2 ^ f4 ^ f8 ^ shift(f2 ^ f9, 8) ^ shift(f4 ^ f9, 16) ^ shift(f9, 24);
    }

    private static int subword(int x)
    {
        return (s[x&255]&255 | ((s[(x>>8)&255]&255)<<8) | ((s[(x>>16)&255]&255)<<16) | s[(x>>24)&255]<<24);
    }

    /**
     * calculate the necessary round keys
     * the number of calculations depends on key size and block size
     * aes specified a fixed block size of 128 bits and key sizes 128/192/256 bits
     * this code is written assuming those are the only possible values
     */
    private int[][] generateworkingkey(
                                    byte[] key,
                                    boolean forencryption)
    {
        int         kc = key.length / 4;  // key length in words
        int         t;
        
        if (((kc != 4) && (kc != 6) && (kc != 8)) || ((kc * 4) != key.length))
        {
            throw new illegalargumentexception("key length not 128/192/256 bits.");
        }

        rounds = kc + 6;  // this is not always true for the generalized rijndael that allows larger block sizes
        int[][] w = new int[rounds+1][4];   // 4 words in a block
        
        //
        // copy the key into the round key array
        //
        
        t = 0;
        int i = 0;
        while (i < key.length)
            {
                w[t >> 2][t & 3] = (key[i]&0xff) | ((key[i+1]&0xff) << 8) | ((key[i+2]&0xff) << 16) | (key[i+3] << 24);
                i+=4;
                t++;
            }
        
        //
        // while not enough round key material calculated
        // calculate new values
        //
        int k = (rounds + 1) << 2;
        for (i = kc; (i < k); i++)
            {
                int temp = w[(i-1)>>2][(i-1)&3];
                if ((i % kc) == 0)
                {
                    temp = subword(shift(temp, 8)) ^ rcon[(i / kc)-1];
                }
                else if ((kc > 6) && ((i % kc) == 4))
                {
                    temp = subword(temp);
                }
                
                w[i>>2][i&3] = w[(i - kc)>>2][(i-kc)&3] ^ temp;
            }

        if (!forencryption)
        {
            for (int j = 1; j < rounds; j++)
            {
                for (i = 0; i < 4; i++)
                {
                    w[j][i] = inv_mcol(w[j][i]);
                }
            }
        }

        return w;
    }

    private int         rounds;
    private int[][]     workingkey = null;
    private int         c0, c1, c2, c3;
    private boolean     forencryption;

    private static final int block_size = 16;

    /**
     * default constructor - 128 bit block size.
     */
    public aesengine()
    {
    }

    /**
     * initialise an aes cipher.
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
            workingkey = generateworkingkey(((keyparameter)params).getkey(), forencryption);
            this.forencryption = forencryption;
            return;
        }

        throw new illegalargumentexception("invalid parameter passed to aes init - " + params.getclass().getname());
    }

    public string getalgorithmname()
    {
        return "aes";
    }

    public int getblocksize()
    {
        return block_size;
    }

    public int processblock(
        byte[] in,
        int inoff,
        byte[] out,
        int outoff)
    {
        if (workingkey == null)
        {
            throw new illegalstateexception("aes engine not initialised");
        }

        if ((inoff + (32 / 2)) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + (32 / 2)) > out.length)
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

        return block_size;
    }

    public void reset()
    {
    }

    private void unpackblock(
        byte[]      bytes,
        int         off)
    {
        int     index = off;

        c0 = (bytes[index++] & 0xff);
        c0 |= (bytes[index++] & 0xff) << 8;
        c0 |= (bytes[index++] & 0xff) << 16;
        c0 |= bytes[index++] << 24;

        c1 = (bytes[index++] & 0xff);
        c1 |= (bytes[index++] & 0xff) << 8;
        c1 |= (bytes[index++] & 0xff) << 16;
        c1 |= bytes[index++] << 24;

        c2 = (bytes[index++] & 0xff);
        c2 |= (bytes[index++] & 0xff) << 8;
        c2 |= (bytes[index++] & 0xff) << 16;
        c2 |= bytes[index++] << 24;

        c3 = (bytes[index++] & 0xff);
        c3 |= (bytes[index++] & 0xff) << 8;
        c3 |= (bytes[index++] & 0xff) << 16;
        c3 |= bytes[index++] << 24;
    }

    private void packblock(
        byte[]      bytes,
        int         off)
    {
        int     index = off;

        bytes[index++] = (byte)c0;
        bytes[index++] = (byte)(c0 >> 8);
        bytes[index++] = (byte)(c0 >> 16);
        bytes[index++] = (byte)(c0 >> 24);

        bytes[index++] = (byte)c1;
        bytes[index++] = (byte)(c1 >> 8);
        bytes[index++] = (byte)(c1 >> 16);
        bytes[index++] = (byte)(c1 >> 24);

        bytes[index++] = (byte)c2;
        bytes[index++] = (byte)(c2 >> 8);
        bytes[index++] = (byte)(c2 >> 16);
        bytes[index++] = (byte)(c2 >> 24);

        bytes[index++] = (byte)c3;
        bytes[index++] = (byte)(c3 >> 8);
        bytes[index++] = (byte)(c3 >> 16);
        bytes[index++] = (byte)(c3 >> 24);
    }


    private void encryptblock(int[][] kw)
    {
        int r, r0, r1, r2, r3;

        c0 ^= kw[0][0];
        c1 ^= kw[0][1];
        c2 ^= kw[0][2];
        c3 ^= kw[0][3];

        r = 1;

        while (r < rounds - 1)
        {
            r0 = t0[c0&255] ^ shift(t0[(c1>>8)&255], 24) ^ shift(t0[(c2>>16)&255],16) ^ shift(t0[(c3>>24)&255],8) ^ kw[r][0];
            r1 = t0[c1&255] ^ shift(t0[(c2>>8)&255], 24) ^ shift(t0[(c3>>16)&255], 16) ^ shift(t0[(c0>>24)&255], 8) ^ kw[r][1];
            r2 = t0[c2&255] ^ shift(t0[(c3>>8)&255], 24) ^ shift(t0[(c0>>16)&255], 16) ^ shift(t0[(c1>>24)&255], 8) ^ kw[r][2];
            r3 = t0[c3&255] ^ shift(t0[(c0>>8)&255], 24) ^ shift(t0[(c1>>16)&255], 16) ^ shift(t0[(c2>>24)&255], 8) ^ kw[r++][3];
            c0 = t0[r0&255] ^ shift(t0[(r1>>8)&255], 24) ^ shift(t0[(r2>>16)&255], 16) ^ shift(t0[(r3>>24)&255], 8) ^ kw[r][0];
            c1 = t0[r1&255] ^ shift(t0[(r2>>8)&255], 24) ^ shift(t0[(r3>>16)&255], 16) ^ shift(t0[(r0>>24)&255], 8) ^ kw[r][1];
            c2 = t0[r2&255] ^ shift(t0[(r3>>8)&255], 24) ^ shift(t0[(r0>>16)&255], 16) ^ shift(t0[(r1>>24)&255], 8) ^ kw[r][2];
            c3 = t0[r3&255] ^ shift(t0[(r0>>8)&255], 24) ^ shift(t0[(r1>>16)&255], 16) ^ shift(t0[(r2>>24)&255], 8) ^ kw[r++][3];
        }

        r0 = t0[c0&255] ^ shift(t0[(c1>>8)&255], 24) ^ shift(t0[(c2>>16)&255], 16) ^ shift(t0[(c3>>24)&255], 8) ^ kw[r][0];
        r1 = t0[c1&255] ^ shift(t0[(c2>>8)&255], 24) ^ shift(t0[(c3>>16)&255], 16) ^ shift(t0[(c0>>24)&255], 8) ^ kw[r][1];
        r2 = t0[c2&255] ^ shift(t0[(c3>>8)&255], 24) ^ shift(t0[(c0>>16)&255], 16) ^ shift(t0[(c1>>24)&255], 8) ^ kw[r][2];
        r3 = t0[c3&255] ^ shift(t0[(c0>>8)&255], 24) ^ shift(t0[(c1>>16)&255], 16) ^ shift(t0[(c2>>24)&255], 8) ^ kw[r++][3];

        // the final round's table is a simple function of s so we don't use a whole other four tables for it

        c0 = (s[r0&255]&255) ^ ((s[(r1>>8)&255]&255)<<8) ^ ((s[(r2>>16)&255]&255)<<16) ^ (s[(r3>>24)&255]<<24) ^ kw[r][0];
        c1 = (s[r1&255]&255) ^ ((s[(r2>>8)&255]&255)<<8) ^ ((s[(r3>>16)&255]&255)<<16) ^ (s[(r0>>24)&255]<<24) ^ kw[r][1];
        c2 = (s[r2&255]&255) ^ ((s[(r3>>8)&255]&255)<<8) ^ ((s[(r0>>16)&255]&255)<<16) ^ (s[(r1>>24)&255]<<24) ^ kw[r][2];
        c3 = (s[r3&255]&255) ^ ((s[(r0>>8)&255]&255)<<8) ^ ((s[(r1>>16)&255]&255)<<16) ^ (s[(r2>>24)&255]<<24) ^ kw[r][3];

    }

    private void decryptblock(int[][] kw)
    {
        int r, r0, r1, r2, r3;

        c0 ^= kw[rounds][0];
        c1 ^= kw[rounds][1];
        c2 ^= kw[rounds][2];
        c3 ^= kw[rounds][3];

        r = rounds-1;

        while (r>1)
        {
            r0 = tinv0[c0&255] ^ shift(tinv0[(c3>>8)&255], 24) ^ shift(tinv0[(c2>>16)&255], 16) ^ shift(tinv0[(c1>>24)&255], 8) ^ kw[r][0];
            r1 = tinv0[c1&255] ^ shift(tinv0[(c0>>8)&255], 24) ^ shift(tinv0[(c3>>16)&255], 16) ^ shift(tinv0[(c2>>24)&255], 8) ^ kw[r][1];
            r2 = tinv0[c2&255] ^ shift(tinv0[(c1>>8)&255], 24) ^ shift(tinv0[(c0>>16)&255], 16) ^ shift(tinv0[(c3>>24)&255], 8) ^ kw[r][2];
            r3 = tinv0[c3&255] ^ shift(tinv0[(c2>>8)&255], 24) ^ shift(tinv0[(c1>>16)&255], 16) ^ shift(tinv0[(c0>>24)&255], 8) ^ kw[r--][3];
            c0 = tinv0[r0&255] ^ shift(tinv0[(r3>>8)&255], 24) ^ shift(tinv0[(r2>>16)&255], 16) ^ shift(tinv0[(r1>>24)&255], 8) ^ kw[r][0];
            c1 = tinv0[r1&255] ^ shift(tinv0[(r0>>8)&255], 24) ^ shift(tinv0[(r3>>16)&255], 16) ^ shift(tinv0[(r2>>24)&255], 8) ^ kw[r][1];
            c2 = tinv0[r2&255] ^ shift(tinv0[(r1>>8)&255], 24) ^ shift(tinv0[(r0>>16)&255], 16) ^ shift(tinv0[(r3>>24)&255], 8) ^ kw[r][2];
            c3 = tinv0[r3&255] ^ shift(tinv0[(r2>>8)&255], 24) ^ shift(tinv0[(r1>>16)&255], 16) ^ shift(tinv0[(r0>>24)&255], 8) ^ kw[r--][3];
        }

        r0 = tinv0[c0&255] ^ shift(tinv0[(c3>>8)&255], 24) ^ shift(tinv0[(c2>>16)&255], 16) ^ shift(tinv0[(c1>>24)&255], 8) ^ kw[r][0];
        r1 = tinv0[c1&255] ^ shift(tinv0[(c0>>8)&255], 24) ^ shift(tinv0[(c3>>16)&255], 16) ^ shift(tinv0[(c2>>24)&255], 8) ^ kw[r][1];
        r2 = tinv0[c2&255] ^ shift(tinv0[(c1>>8)&255], 24) ^ shift(tinv0[(c0>>16)&255], 16) ^ shift(tinv0[(c3>>24)&255], 8) ^ kw[r][2];
        r3 = tinv0[c3&255] ^ shift(tinv0[(c2>>8)&255], 24) ^ shift(tinv0[(c1>>16)&255], 16) ^ shift(tinv0[(c0>>24)&255], 8) ^ kw[r][3];
        
        // the final round's table is a simple function of si so we don't use a whole other four tables for it

        c0 = (si[r0&255]&255) ^ ((si[(r3>>8)&255]&255)<<8) ^ ((si[(r2>>16)&255]&255)<<16) ^ (si[(r1>>24)&255]<<24) ^ kw[0][0];
        c1 = (si[r1&255]&255) ^ ((si[(r0>>8)&255]&255)<<8) ^ ((si[(r3>>16)&255]&255)<<16) ^ (si[(r2>>24)&255]<<24) ^ kw[0][1];
        c2 = (si[r2&255]&255) ^ ((si[(r1>>8)&255]&255)<<8) ^ ((si[(r0>>16)&255]&255)<<16) ^ (si[(r3>>24)&255]<<24) ^ kw[0][2];
        c3 = (si[r3&255]&255) ^ ((si[(r2>>8)&255]&255)<<8) ^ ((si[(r1>>16)&255]&255)<<16) ^ (si[(r0>>24)&255]<<24) ^ kw[0][3];
    }
}
