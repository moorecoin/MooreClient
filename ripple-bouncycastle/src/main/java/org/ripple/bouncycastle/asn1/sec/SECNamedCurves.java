package org.ripple.bouncycastle.asn1.sec;

import java.math.biginteger;
import java.util.enumeration;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.asn1.x9.x9ecparametersholder;
import org.ripple.bouncycastle.math.ec.ecconstants;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;
import org.ripple.bouncycastle.util.strings;
import org.ripple.bouncycastle.util.encoders.hex;

public class secnamedcurves
{
    private static biginteger fromhex(
        string hex)
    {
        return new biginteger(1, hex.decode(hex));
    }

    /*
     * secp112r1
     */
    static x9ecparametersholder secp112r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = (2^128 - 3) / 76439
            biginteger p = fromhex("db7c2abf62e35e668076bead208b");
            biginteger a = fromhex("db7c2abf62e35e668076bead2088");
            biginteger b = fromhex("659ef8ba043916eede8911702b22");
            byte[] s = hex.decode("00f50b028e4d696e676875615175290472783fb1");
            biginteger n = fromhex("db7c2abf62e35e7628dfac6561c5");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("02"
            //+ "09487239995a5ee76b55f9c2f098"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "09487239995a5ee76b55f9c2f098"
                + "a89ce5af8724c0a23e0e0ff77500"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp112r2
     */
    static x9ecparametersholder secp112r2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = (2^128 - 3) / 76439
            biginteger p = fromhex("db7c2abf62e35e668076bead208b");
            biginteger a = fromhex("6127c24c05f38a0aaaf65c0ef02c");
            biginteger b = fromhex("51def1815db5ed74fcc34c85d709");
            byte[] s = hex.decode("002757a1114d696e6768756151755316c05e0bd4");
            biginteger n = fromhex("36df0aafd8b8d7597ca10520d04b");
            biginteger h = biginteger.valueof(4);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "4ba30ab5e892b4e1649dd0928643"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "4ba30ab5e892b4e1649dd0928643"
                + "adcd46f5882e3747def36e956e97"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp128r1
     */
    static x9ecparametersholder secp128r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^128 - 2^97 - 1
            biginteger p = fromhex("fffffffdffffffffffffffffffffffff");
            biginteger a = fromhex("fffffffdfffffffffffffffffffffffc");
            biginteger b = fromhex("e87579c11079f43dd824993c2cee5ed3");
            byte[] s = hex.decode("000e0d4d696e6768756151750cc03a4473d03679");
            biginteger n = fromhex("fffffffe0000000075a30d1b9038a115");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "161ff7528b899b2d0c28607ca52c5b86"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "161ff7528b899b2d0c28607ca52c5b86"
                + "cf5ac8395bafeb13c02da292dded7a83"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp128r2
     */
    static x9ecparametersholder secp128r2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^128 - 2^97 - 1
            biginteger p = fromhex("fffffffdffffffffffffffffffffffff");
            biginteger a = fromhex("d6031998d1b3bbfebf59cc9bbff9aee1");
            biginteger b = fromhex("5eeefca380d02919dc2c6558bb6d8a5d");
            byte[] s = hex.decode("004d696e67687561517512d8f03431fce63b88f4");
            biginteger n = fromhex("3fffffff7fffffffbe0024720613b5a3");
            biginteger h = biginteger.valueof(4);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("02"
            //+ "7b6aa5d85e572983e6fb32a7cdebc140"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "7b6aa5d85e572983e6fb32a7cdebc140"
                + "27b6916a894d3aee7106fe805fc34b44"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp160k1
     */
    static x9ecparametersholder secp160k1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
            biginteger p = fromhex("fffffffffffffffffffffffffffffffeffffac73");
            biginteger a = ecconstants.zero;
            biginteger b = biginteger.valueof(7);
            byte[] s = null;
            biginteger n = fromhex("0100000000000000000001b8fa16dfab9aca16b6b3");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
//            ecpoint g = curve.decodepoint(hex.decode("02"
//                + "3b4c382ce37aa192a4019e763036f4f5dd4d7ebb"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "3b4c382ce37aa192a4019e763036f4f5dd4d7ebb"
                + "938cf935318fdced6bc28286531733c3f03c4fee"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp160r1
     */
    static x9ecparametersholder secp160r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^160 - 2^31 - 1
            biginteger p = fromhex("ffffffffffffffffffffffffffffffff7fffffff");
            biginteger a = fromhex("ffffffffffffffffffffffffffffffff7ffffffc");
            biginteger b = fromhex("1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
            byte[] s = hex.decode("1053cde42c14d696e67687561517533bf3f83345");
            biginteger n = fromhex("0100000000000000000001f4c8f927aed3ca752257");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("02"
                //+ "4a96b5688ef573284664698968c38bb913cbfc82"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "4a96b5688ef573284664698968c38bb913cbfc82"
                + "23a628553168947d59dcc912042351377ac5fb32"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp160r2
     */
    static x9ecparametersholder secp160r2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
            biginteger p = fromhex("fffffffffffffffffffffffffffffffeffffac73");
            biginteger a = fromhex("fffffffffffffffffffffffffffffffeffffac70");
            biginteger b = fromhex("b4e134d3fb59eb8bab57274904664d5af50388ba");
            byte[] s = hex.decode("b99b99b099b323e02709a4d696e6768756151751");
            biginteger n = fromhex("0100000000000000000000351ee786a818f3a1a16b");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("02"
            //+ "52dcb034293a117e1f4ff11b30f7199d3144ce6d"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "52dcb034293a117e1f4ff11b30f7199d3144ce6d"
                + "feaffef2e331f296e071fa0df9982cfea7d43f2e"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp192k1
     */
    static x9ecparametersholder secp192k1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
            biginteger p = fromhex("fffffffffffffffffffffffffffffffffffffffeffffee37");
            biginteger a = ecconstants.zero;
            biginteger b = biginteger.valueof(3);
            byte[] s = null;
            biginteger n = fromhex("fffffffffffffffffffffffe26f2fc170f69466a74defd8d");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d"
                + "9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp192r1
     */
    static x9ecparametersholder secp192r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^192 - 2^64 - 1
            biginteger p = fromhex("fffffffffffffffffffffffffffffffeffffffffffffffff");
            biginteger a = fromhex("fffffffffffffffffffffffffffffffefffffffffffffffc");
            biginteger b = fromhex("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1");
            byte[] s = hex.decode("3045ae6fc8422f64ed579528d38120eae12196d5");
            biginteger n = fromhex("ffffffffffffffffffffffff99def836146bc9b1b4d22831");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"
                + "07192b95ffc8da78631011ed6b24cdd573f977a11e794811"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp224k1
     */
    static x9ecparametersholder secp224k1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1
            biginteger p = fromhex("fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d");
            biginteger a = ecconstants.zero;
            biginteger b = biginteger.valueof(5);
            byte[] s = null;
            biginteger n = fromhex("010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c"
                + "7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp224r1
     */
    static x9ecparametersholder secp224r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^224 - 2^96 + 1
            biginteger p = fromhex("ffffffffffffffffffffffffffffffff000000000000000000000001");
            biginteger a = fromhex("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe");
            biginteger b = fromhex("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4");
            byte[] s = hex.decode("bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5");
            biginteger n = fromhex("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("02"
            //+ "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"
                + "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp256k1
     */
    static x9ecparametersholder secp256k1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
            biginteger p = fromhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
            biginteger a = ecconstants.zero;
            biginteger b = biginteger.valueof(7);
            byte[] s = null;
            biginteger n = fromhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("02"
            //+ "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp256r1
     */
    static x9ecparametersholder secp256r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
            biginteger p = fromhex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
            biginteger a = fromhex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
            biginteger b = fromhex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
            byte[] s = hex.decode("c49d360886e704936a6678e1139d26b7819f7e90");
            biginteger n = fromhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp384r1
     */
    static x9ecparametersholder secp384r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^384 - 2^128 - 2^96 + 2^32 - 1
            biginteger p = fromhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff");
            biginteger a = fromhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc");
            biginteger b = fromhex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef");
            byte[] s = hex.decode("a335926aa319a27a1d00896a6773a4827acdac73");
            biginteger n = fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"
                + "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * secp521r1
     */
    static x9ecparametersholder secp521r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            // p = 2^521 - 1
            biginteger p = fromhex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            biginteger a = fromhex("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc");
            biginteger b = fromhex("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00");
            byte[] s = hex.decode("d09e8800291cb85396cc6717393284aaa0da64ba");
            biginteger n = fromhex("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409");
            biginteger h = biginteger.valueof(1);

            eccurve curve = new eccurve.fp(p, a, b);
            //ecpoint g = curve.decodepoint(hex.decode("02"
            //+ "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"
                + "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };
    
    /*
     * sect113r1
     */
    static x9ecparametersholder sect113r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 113;
            int k = 9;

            biginteger a = fromhex("003088250ca6e7c7fe649ce85820f7");
            biginteger b = fromhex("00e8bee4d3e2260744188be0e9c723");
            byte[] s = hex.decode("10e723ab14d696e6768756151756febf8fcb49a9");
            biginteger n = fromhex("0100000000000000d9ccec8a39e56f");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "009d73616f35f4ab1407d73562c10f"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "009d73616f35f4ab1407d73562c10f"
                + "00a52830277958ee84d1315ed31886"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect113r2
     */
    static x9ecparametersholder sect113r2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 113;
            int k = 9;

            biginteger a = fromhex("00689918dbec7e5a0dd6dfc0aa55c7");
            biginteger b = fromhex("0095e9a9ec9b297bd4bf36e059184f");
            byte[] s = hex.decode("10c0fb15760860def1eef4d696e676875615175d");
            biginteger n = fromhex("010000000000000108789b2496af93");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "01a57a6a7b26ca5ef52fcdb8164797"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "01a57a6a7b26ca5ef52fcdb8164797"
                + "00b3adc94ed1fe674c06e695baba1d"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect131r1
     */
    static x9ecparametersholder sect131r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 131;
            int k1 = 2;
            int k2 = 3;
            int k3 = 8;

            biginteger a = fromhex("07a11b09a76b562144418ff3ff8c2570b8");
            biginteger b = fromhex("0217c05610884b63b9c6c7291678f9d341");
            byte[] s = hex.decode("4d696e676875615175985bd3adbada21b43a97e2");
            biginteger n = fromhex("0400000000000000023123953a9464b54d");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k1, k2, k3, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "0081baf91fdf9833c40f9c181343638399"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "0081baf91fdf9833c40f9c181343638399"
                + "078c6e7ea38c001f73c8134b1b4ef9e150"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect131r2
     */
    static x9ecparametersholder sect131r2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 131;
            int k1 = 2;
            int k2 = 3;
            int k3 = 8;

            biginteger a = fromhex("03e5a88919d7cafcbf415f07c2176573b2");
            biginteger b = fromhex("04b8266a46c55657ac734ce38f018f2192");
            byte[] s = hex.decode("985bd3adbad4d696e676875615175a21b43a97e3");
            biginteger n = fromhex("0400000000000000016954a233049ba98f");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k1, k2, k3, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "0356dcd8f2f95031ad652d23951bb366a8"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "0356dcd8f2f95031ad652d23951bb366a8"
                + "0648f06d867940a5366d9e265de9eb240f"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect163k1
     */
    static x9ecparametersholder sect163k1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 163;
            int k1 = 3;
            int k2 = 6;
            int k3 = 7;

            biginteger a = biginteger.valueof(1);
            biginteger b = biginteger.valueof(1);
            byte[] s = null;
            biginteger n = fromhex("04000000000000000000020108a2e0cc0d99f8a5ef");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k1, k2, k3, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8"
                + "0289070fb05d38ff58321f2e800536d538ccdaa3d9"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect163r1
     */
    static x9ecparametersholder sect163r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 163;
            int k1 = 3;
            int k2 = 6;
            int k3 = 7;

            biginteger a = fromhex("07b6882caaefa84f9554ff8428bd88e246d2782ae2");
            biginteger b = fromhex("0713612dcddcb40aab946bda29ca91f73af958afd9");
            byte[] s = hex.decode("24b7b137c8a14d696e6768756151756fd0da2e5c");
            biginteger n = fromhex("03ffffffffffffffffffff48aab689c29ca710279b");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k1, k2, k3, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "0369979697ab43897789566789567f787a7876a654"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "0369979697ab43897789566789567f787a7876a654"
                + "00435edb42efafb2989d51fefce3c80988f41ff883"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect163r2
     */
    static x9ecparametersholder sect163r2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 163;
            int k1 = 3;
            int k2 = 6;
            int k3 = 7;

            biginteger a = biginteger.valueof(1);
            biginteger b = fromhex("020a601907b8c953ca1481eb10512f78744a3205fd");
            byte[] s = hex.decode("85e25bfe5c86226cdb12016f7553f9d0e693a268");
            biginteger n = fromhex("040000000000000000000292fe77e70c12a4234c33");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k1, k2, k3, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "03f0eba16286a2d57ea0991168d4994637e8343e36"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "03f0eba16286a2d57ea0991168d4994637e8343e36"
                + "00d51fbc6c71a0094fa2cdd545b11c5c0c797324f1"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect193r1
     */
    static x9ecparametersholder sect193r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 193;
            int k = 15;

            biginteger a = fromhex("0017858feb7a98975169e171f77b4087de098ac8a911df7b01");
            biginteger b = fromhex("00fdfb49bfe6c3a89facadaa7a1e5bbc7cc1c2e5d831478814");
            byte[] s = hex.decode("103faec74d696e676875615175777fc5b191ef30");
            biginteger n = fromhex("01000000000000000000000000c7f34a778f443acc920eba49");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "01f481bc5f0ff84a74ad6cdf6fdef4bf6179625372d8c0c5e1"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "01f481bc5f0ff84a74ad6cdf6fdef4bf6179625372d8c0c5e1"
                + "0025e399f2903712ccf3ea9e3a1ad17fb0b3201b6af7ce1b05"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect193r2
     */
    static x9ecparametersholder sect193r2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 193;
            int k = 15;

            biginteger a = fromhex("0163f35a5137c2ce3ea6ed8667190b0bc43ecd69977702709b");
            biginteger b = fromhex("00c9bb9e8927d4d64c377e2ab2856a5b16e3efb7f61d4316ae");
            byte[] s = hex.decode("10b7b4d696e676875615175137c8a16fd0da2211");
            biginteger n = fromhex("010000000000000000000000015aab561b005413ccd4ee99d5");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "00d9b67d192e0367c803f39e1a7e82ca14a651350aae617e8f"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "00d9b67d192e0367c803f39e1a7e82ca14a651350aae617e8f"
                + "01ce94335607c304ac29e7defbd9ca01f596f927224cdecf6c"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect233k1
     */
    static x9ecparametersholder sect233k1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 233;
            int k = 74;

            biginteger a = ecconstants.zero;
            biginteger b = biginteger.valueof(1);
            byte[] s = null;
            biginteger n = fromhex("8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf");
            biginteger h = biginteger.valueof(4);

            eccurve curve = new eccurve.f2m(m, k, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("02"
            //+ "017232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "017232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126"
                + "01db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect233r1
     */
    static x9ecparametersholder sect233r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 233;
            int k = 74;

            biginteger a = biginteger.valueof(1);
            biginteger b = fromhex("0066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad");
            byte[] s = hex.decode("74d59ff07f6b413d0ea14b344b20a2db049b50c3");
            biginteger n = fromhex("01000000000000000000000000000013e974e72f8a6922031d2603cfe0d7");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b"
                + "01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect239k1
     */
    static x9ecparametersholder sect239k1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 239;
            int k = 158;

            biginteger a = ecconstants.zero;
            biginteger b = biginteger.valueof(1);
            byte[] s = null;
            biginteger n = fromhex("2000000000000000000000000000005a79fec67cb6e91f1c1da800e478a5");
            biginteger h = biginteger.valueof(4);

            eccurve curve = new eccurve.f2m(m, k, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "29a0b6a887a983e9730988a68727a8b2d126c44cc2cc7b2a6555193035dc"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "29a0b6a887a983e9730988a68727a8b2d126c44cc2cc7b2a6555193035dc"
                + "76310804f12e549bdb011c103089e73510acb275fc312a5dc6b76553f0ca"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect283k1
     */
    static x9ecparametersholder sect283k1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 283;
            int k1 = 5;
            int k2 = 7;
            int k3 = 12;

            biginteger a = ecconstants.zero;
            biginteger b = biginteger.valueof(1);
            byte[] s = null;
            biginteger n = fromhex("01ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61");
            biginteger h = biginteger.valueof(4);

            eccurve curve = new eccurve.f2m(m, k1, k2, k3, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("02"
            //+ "0503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "0503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836"
                + "01ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect283r1
     */
    static x9ecparametersholder sect283r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 283;
            int k1 = 5;
            int k2 = 7;
            int k3 = 12;

            biginteger a = biginteger.valueof(1);
            biginteger b = fromhex("027b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5");
            byte[] s = hex.decode("77e2b07370eb0f832a6dd5b62dfc88cd06bb84be");
            biginteger n = fromhex("03ffffffffffffffffffffffffffffffffffef90399660fc938a90165b042a7cefadb307");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k1, k2, k3, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "05f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "05f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053"
                + "03676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect409k1
     */
    static x9ecparametersholder sect409k1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 409;
            int k = 87;

            biginteger a = ecconstants.zero;
            biginteger b = biginteger.valueof(1);
            byte[] s = null;
            biginteger n = fromhex("7ffffffffffffffffffffffffffffffffffffffffffffffffffe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcf");
            biginteger h = biginteger.valueof(4);

            eccurve curve = new eccurve.f2m(m, k, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "0060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "0060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746"
                + "01e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect409r1
     */
    static x9ecparametersholder sect409r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 409;
            int k = 87;

            biginteger a = biginteger.valueof(1);
            biginteger b = fromhex("0021a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f");
            byte[] s = hex.decode("4099b5a457f9d69f79213d094c4bcd4d4262210b");
            biginteger n = fromhex("010000000000000000000000000000000000000000000000000001e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "015d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "015d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7"
                + "0061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect571k1
     */
    static x9ecparametersholder sect571k1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 571;
            int k1 = 2;
            int k2 = 5;
            int k3 = 10;

            biginteger a = ecconstants.zero;
            biginteger b = biginteger.valueof(1);
            byte[] s = null;
            biginteger n = fromhex("020000000000000000000000000000000000000000000000000000000000000000000000131850e1f19a63e4b391a8db917f4138b630d84be5d639381e91deb45cfe778f637c1001");
            biginteger h = biginteger.valueof(4);

            eccurve curve = new eccurve.f2m(m, k1, k2, k3, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("02"
            //+ "026eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ceb08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "026eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ceb08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972"
                + "0349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772aedcb620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };

    /*
     * sect571r1
     */
    static x9ecparametersholder sect571r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            int m = 571;
            int k1 = 2;
            int k2 = 5;
            int k3 = 10;

            biginteger a = biginteger.valueof(1);
            biginteger b = fromhex("02f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a");
            byte[] s = hex.decode("2aa058f73a0e33ab486b0f610410c53a7f132310");
            biginteger n = fromhex("03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe661ce18ff55987308059b186823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47");
            biginteger h = biginteger.valueof(2);

            eccurve curve = new eccurve.f2m(m, k1, k2, k3, a, b, n, h);
            //ecpoint g = curve.decodepoint(hex.decode("03"
            //+ "0303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19"));
            ecpoint g = curve.decodepoint(hex.decode("04"
                + "0303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19"
                + "037bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b"));

            return new x9ecparameters(curve, g, n, h, s);
        }
    };


    static final hashtable objids = new hashtable();
    static final hashtable curves = new hashtable();
    static final hashtable names = new hashtable();

    static void definecurve(string name, asn1objectidentifier oid, x9ecparametersholder holder)
    {
        objids.put(name, oid);
        names.put(oid, name);
        curves.put(oid, holder);
    }

    static
    {
        definecurve("secp112r1", secobjectidentifiers.secp112r1, secp112r1);
        definecurve("secp112r2", secobjectidentifiers.secp112r2, secp112r2);
        definecurve("secp128r1", secobjectidentifiers.secp128r1, secp128r1);
        definecurve("secp128r2", secobjectidentifiers.secp128r2, secp128r2);
        definecurve("secp160k1", secobjectidentifiers.secp160k1, secp160k1);
        definecurve("secp160r1", secobjectidentifiers.secp160r1, secp160r1);
        definecurve("secp160r2", secobjectidentifiers.secp160r2, secp160r2);
        definecurve("secp192k1", secobjectidentifiers.secp192k1, secp192k1);
        definecurve("secp192r1", secobjectidentifiers.secp192r1, secp192r1);
        definecurve("secp224k1", secobjectidentifiers.secp224k1, secp224k1);
        definecurve("secp224r1", secobjectidentifiers.secp224r1, secp224r1); 
        definecurve("secp256k1", secobjectidentifiers.secp256k1, secp256k1);
        definecurve("secp256r1", secobjectidentifiers.secp256r1, secp256r1); 
        definecurve("secp384r1", secobjectidentifiers.secp384r1, secp384r1); 
        definecurve("secp521r1", secobjectidentifiers.secp521r1, secp521r1); 

        definecurve("sect113r1", secobjectidentifiers.sect113r1, sect113r1);
        definecurve("sect113r2", secobjectidentifiers.sect113r2, sect113r2);
        definecurve("sect131r1", secobjectidentifiers.sect131r1, sect131r1);
        definecurve("sect131r2", secobjectidentifiers.sect131r2, sect131r2);
        definecurve("sect163k1", secobjectidentifiers.sect163k1, sect163k1);
        definecurve("sect163r1", secobjectidentifiers.sect163r1, sect163r1);
        definecurve("sect163r2", secobjectidentifiers.sect163r2, sect163r2);
        definecurve("sect193r1", secobjectidentifiers.sect193r1, sect193r1);
        definecurve("sect193r2", secobjectidentifiers.sect193r2, sect193r2);
        definecurve("sect233k1", secobjectidentifiers.sect233k1, sect233k1);
        definecurve("sect233r1", secobjectidentifiers.sect233r1, sect233r1);
        definecurve("sect239k1", secobjectidentifiers.sect239k1, sect239k1);
        definecurve("sect283k1", secobjectidentifiers.sect283k1, sect283k1);
        definecurve("sect283r1", secobjectidentifiers.sect283r1, sect283r1);
        definecurve("sect409k1", secobjectidentifiers.sect409k1, sect409k1);
        definecurve("sect409r1", secobjectidentifiers.sect409r1, sect409r1);
        definecurve("sect571k1", secobjectidentifiers.sect571k1, sect571k1);
        definecurve("sect571r1", secobjectidentifiers.sect571r1, sect571r1); 
    }

    public static x9ecparameters getbyname(
        string name)
    {
        asn1objectidentifier oid = (asn1objectidentifier)objids.get(strings.tolowercase(name));

        if (oid != null)
        {
            return getbyoid(oid);
        }

        return null;
    }

    /**
     * return the x9ecparameters object for the named curve represented by
     * the passed in object identifier. null if the curve isn't present.
     *
     * @param oid an object identifier representing a named curve, if present.
     */
    public static x9ecparameters getbyoid(
        asn1objectidentifier oid)
    {
        x9ecparametersholder holder = (x9ecparametersholder)curves.get(oid);

        if (holder != null)
        {
            return holder.getparameters();
        }

        return null;
    }

    /**
     * return the object identifier signified by the passed in name. null
     * if there is no object identifier associated with name.
     *
     * @return the object identifier associated with name, if present.
     */
    public static asn1objectidentifier getoid(
        string name)
    {
        return (asn1objectidentifier)objids.get(strings.tolowercase(name));
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static string getname(
        asn1objectidentifier oid)
    {
        return (string)names.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for curves
     * contained in this structure.
     */
    public static enumeration getnames()
    {
        return objids.keys();
    }
}
