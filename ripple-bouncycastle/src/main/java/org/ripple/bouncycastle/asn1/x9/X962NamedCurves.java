package org.ripple.bouncycastle.asn1.x9;

import java.math.biginteger;
import java.util.enumeration;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.util.strings;
import org.ripple.bouncycastle.util.encoders.hex;


/**
 * table of the current named curves defined in x.962 ec-dsa.
 */
public class x962namedcurves
{
    static x9ecparametersholder prime192v1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve cfp192v1 = new eccurve.fp(
                new biginteger("6277101735386680763835789423207666416083908700390324961279"),
                new biginteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
                new biginteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16));

            return new x9ecparameters(
                cfp192v1,
                cfp192v1.decodepoint(
                    hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")),
                new biginteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
                biginteger.valueof(1),
                hex.decode("3045ae6fc8422f64ed579528d38120eae12196d5"));
        }
    };

    static x9ecparametersholder prime192v2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve cfp192v2 = new eccurve.fp(
                new biginteger("6277101735386680763835789423207666416083908700390324961279"),
                new biginteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
                new biginteger("cc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953", 16));

            return new x9ecparameters(
                cfp192v2,
                cfp192v2.decodepoint(
                    hex.decode("03eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a")),
                new biginteger("fffffffffffffffffffffffe5fb1a724dc80418648d8dd31", 16),
                biginteger.valueof(1),
                hex.decode("31a92ee2029fd10d901b113e990710f0d21ac6b6"));
        }
    };

    static x9ecparametersholder prime192v3 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve cfp192v3 = new eccurve.fp(
                new biginteger("6277101735386680763835789423207666416083908700390324961279"),
                new biginteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
                new biginteger("22123dc2395a05caa7423daeccc94760a7d462256bd56916", 16));

            return new x9ecparameters(
                cfp192v3,
                cfp192v3.decodepoint(
                    hex.decode("027d29778100c65a1da1783716588dce2b8b4aee8e228f1896")),
                new biginteger("ffffffffffffffffffffffff7a62d031c83f4294f640ec13", 16),
                biginteger.valueof(1),
                hex.decode("c469684435deb378c4b65ca9591e2a5763059a2e"));
        }
    };

    static x9ecparametersholder prime239v1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve cfp239v1 = new eccurve.fp(
                new biginteger("883423532389192164791648750360308885314476597252960362792450860609699839"),
                new biginteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
                new biginteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16));

            return new x9ecparameters(
                cfp239v1,
                cfp239v1.decodepoint(
                    hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")),
                new biginteger("7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b", 16),
                biginteger.valueof(1),
                hex.decode("e43bb460f0b80cc0c0b075798e948060f8321b7d"));
        }
    };

    static x9ecparametersholder prime239v2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve cfp239v2 = new eccurve.fp(
                new biginteger("883423532389192164791648750360308885314476597252960362792450860609699839"),
                new biginteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
                new biginteger("617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c", 16));

            return new x9ecparameters(
                cfp239v2,
                cfp239v2.decodepoint(
                    hex.decode("0238af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7")),
                new biginteger("7fffffffffffffffffffffff800000cfa7e8594377d414c03821bc582063", 16),
                biginteger.valueof(1),
                hex.decode("e8b4011604095303ca3b8099982be09fcb9ae616"));
        }
    };

    static x9ecparametersholder prime239v3 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve cfp239v3 = new eccurve.fp(
                new biginteger("883423532389192164791648750360308885314476597252960362792450860609699839"),
                new biginteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
                new biginteger("255705fa2a306654b1f4cb03d6a750a30c250102d4988717d9ba15ab6d3e", 16));

            return new x9ecparameters(
                cfp239v3,
                cfp239v3.decodepoint(
                    hex.decode("036768ae8e18bb92cfcf005c949aa2c6d94853d0e660bbf854b1c9505fe95a")),
                new biginteger("7fffffffffffffffffffffff7fffff975deb41b3a6057c3c432146526551", 16),
                biginteger.valueof(1),
                hex.decode("7d7374168ffe3471b60a857686a19475d3bfa2ff"));
        }
    };

    static x9ecparametersholder prime256v1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve cfp256v1 = new eccurve.fp(
                new biginteger("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
                new biginteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
                new biginteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16));

            return new x9ecparameters(
                cfp256v1,
                cfp256v1.decodepoint(
                    hex.decode("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")),
                new biginteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
                biginteger.valueof(1),
                hex.decode("c49d360886e704936a6678e1139d26b7819f7e90"));
        }
    };

    /*
     * f2m curves
     */
    static x9ecparametersholder c2pnb163v1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m163v1n = new biginteger("0400000000000000000001e60fc8821cc74daeafc1", 16);
            biginteger c2m163v1h = biginteger.valueof(2);

            eccurve c2m163v1 = new eccurve.f2m(
                163,
                1, 2, 8,
                new biginteger("072546b5435234a422e0789675f432c89435de5242", 16),
                new biginteger("00c9517d06d5240d3cff38c74b20b6cd4d6f9dd4d9", 16),
                c2m163v1n, c2m163v1h);

            return new x9ecparameters(
                c2m163v1,
                c2m163v1.decodepoint(
                    hex.decode("0307af69989546103d79329fcc3d74880f33bbe803cb")),
                c2m163v1n, c2m163v1h,
                hex.decode("d2c0fb15760860def1eef4d696e6768756151754"));
        }
    };

    static x9ecparametersholder c2pnb163v2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m163v2n = new biginteger("03fffffffffffffffffffdf64de1151adbb78f10a7", 16);
            biginteger c2m163v2h = biginteger.valueof(2);

            eccurve c2m163v2 = new eccurve.f2m(
                163,
                1, 2, 8,
                new biginteger("0108b39e77c4b108bed981ed0e890e117c511cf072", 16),
                new biginteger("0667aceb38af4e488c407433ffae4f1c811638df20", 16),
                c2m163v2n, c2m163v2h);

            return new x9ecparameters(
                c2m163v2,
                c2m163v2.decodepoint(
                    hex.decode("030024266e4eb5106d0a964d92c4860e2671db9b6cc5")),
                c2m163v2n, c2m163v2h,
                null);
        }
    };

    static x9ecparametersholder c2pnb163v3 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m163v3n = new biginteger("03fffffffffffffffffffe1aee140f110aff961309", 16);
            biginteger c2m163v3h = biginteger.valueof(2);

            eccurve c2m163v3 = new eccurve.f2m(
                163,
                1, 2, 8,
                new biginteger("07a526c63d3e25a256a007699f5447e32ae456b50e", 16),
                new biginteger("03f7061798eb99e238fd6f1bf95b48feeb4854252b", 16),
                c2m163v3n, c2m163v3h);

            return new x9ecparameters(
                c2m163v3,
                c2m163v3.decodepoint(
                    hex.decode("0202f9f87b7c574d0bdecf8a22e6524775f98cdebdcb")),
                c2m163v3n, c2m163v3h,
                null);
        }
    };

    static x9ecparametersholder c2pnb176w1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m176w1n = new biginteger("010092537397eca4f6145799d62b0a19ce06fe26ad", 16);
            biginteger c2m176w1h = biginteger.valueof(0xff6e);

            eccurve c2m176w1 = new eccurve.f2m(
                176,
                1, 2, 43,
                new biginteger("00e4e6db2995065c407d9d39b8d0967b96704ba8e9c90b", 16),
                new biginteger("005dda470abe6414de8ec133ae28e9bbd7fcec0ae0fff2", 16),
                c2m176w1n, c2m176w1h);

            return new x9ecparameters(
                c2m176w1,
                c2m176w1.decodepoint(
                    hex.decode("038d16c2866798b600f9f08bb4a8e860f3298ce04a5798")),
                c2m176w1n, c2m176w1h,
                null);
        }
    };

    static x9ecparametersholder c2tnb191v1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m191v1n = new biginteger("40000000000000000000000004a20e90c39067c893bbb9a5", 16);
            biginteger c2m191v1h = biginteger.valueof(2);

            eccurve c2m191v1 = new eccurve.f2m(
                191,
                9,
                new biginteger("2866537b676752636a68f56554e12640276b649ef7526267", 16),
                new biginteger("2e45ef571f00786f67b0081b9495a3d95462f5de0aa185ec", 16),
                c2m191v1n, c2m191v1h);

            return new x9ecparameters(
                c2m191v1,
                c2m191v1.decodepoint(
                    hex.decode("0236b3daf8a23206f9c4f299d7b21a9c369137f2c84ae1aa0d")),
                c2m191v1n, c2m191v1h,
                hex.decode("4e13ca542744d696e67687561517552f279a8c84"));
        }
    };

    static x9ecparametersholder c2tnb191v2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m191v2n = new biginteger("20000000000000000000000050508cb89f652824e06b8173", 16);
            biginteger c2m191v2h = biginteger.valueof(4);

            eccurve c2m191v2 = new eccurve.f2m(
                191,
                9,
                new biginteger("401028774d7777c7b7666d1366ea432071274f89ff01e718", 16),
                new biginteger("0620048d28bcbd03b6249c99182b7c8cd19700c362c46a01", 16),
                c2m191v2n, c2m191v2h);

            return new x9ecparameters(
                c2m191v2,
                c2m191v2.decodepoint(
                    hex.decode("023809b2b7cc1b28cc5a87926aad83fd28789e81e2c9e3bf10")),
                c2m191v2n, c2m191v2h,
                null);
        }
    };

    static x9ecparametersholder c2tnb191v3 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m191v3n = new biginteger("155555555555555555555555610c0b196812bfb6288a3ea3", 16);
            biginteger c2m191v3h = biginteger.valueof(6);

            eccurve c2m191v3 = new eccurve.f2m(
                191,
                9,
                new biginteger("6c01074756099122221056911c77d77e77a777e7e7e77fcb", 16),
                new biginteger("71fe1af926cf847989efef8db459f66394d90f32ad3f15e8", 16),
                c2m191v3n, c2m191v3h);

            return new x9ecparameters(
                c2m191v3,
                c2m191v3.decodepoint(
                    hex.decode("03375d4ce24fde434489de8746e71786015009e66e38a926dd")),
                c2m191v3n, c2m191v3h,
                null);
        }
    };

    static x9ecparametersholder c2pnb208w1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m208w1n = new biginteger("0101baf95c9723c57b6c21da2eff2d5ed588bdd5717e212f9d", 16);
            biginteger c2m208w1h = biginteger.valueof(0xfe48);

            eccurve c2m208w1 = new eccurve.f2m(
                208,
                1, 2, 83,
                new biginteger("0", 16),
                new biginteger("00c8619ed45a62e6212e1160349e2bfa844439fafc2a3fd1638f9e", 16),
                c2m208w1n, c2m208w1h);

            return new x9ecparameters(
                c2m208w1,
                c2m208w1.decodepoint(
                    hex.decode("0289fdfbe4abe193df9559ecf07ac0ce78554e2784eb8c1ed1a57a")),
                c2m208w1n, c2m208w1h,
                null);
        }
    };

    static x9ecparametersholder c2tnb239v1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m239v1n = new biginteger("2000000000000000000000000000000f4d42ffe1492a4993f1cad666e447", 16);
            biginteger c2m239v1h = biginteger.valueof(4);

            eccurve c2m239v1 = new eccurve.f2m(
                239,
                36,
                new biginteger("32010857077c5431123a46b808906756f543423e8d27877578125778ac76", 16),
                new biginteger("790408f2eedaf392b012edefb3392f30f4327c0ca3f31fc383c422aa8c16", 16),
                c2m239v1n, c2m239v1h);

            return new x9ecparameters(
                c2m239v1,
                c2m239v1.decodepoint(
                    hex.decode("0257927098fa932e7c0a96d3fd5b706ef7e5f5c156e16b7e7c86038552e91d")),
                c2m239v1n, c2m239v1h,
                null);
        }
    };

    static x9ecparametersholder c2tnb239v2 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m239v2n = new biginteger("1555555555555555555555555555553c6f2885259c31e3fcdf154624522d", 16);
            biginteger c2m239v2h = biginteger.valueof(6);

            eccurve c2m239v2 = new eccurve.f2m(
                239,
                36,
                new biginteger("4230017757a767fae42398569b746325d45313af0766266479b75654e65f", 16),
                new biginteger("5037ea654196cff0cd82b2c14a2fcf2e3ff8775285b545722f03eacdb74b", 16),
                c2m239v2n, c2m239v2h);

            return new x9ecparameters(
                c2m239v2,
                c2m239v2.decodepoint(
                    hex.decode("0228f9d04e900069c8dc47a08534fe76d2b900b7d7ef31f5709f200c4ca205")),
                c2m239v2n, c2m239v2h,
                null);
        }
    };

    static x9ecparametersholder c2tnb239v3 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m239v3n = new biginteger("0cccccccccccccccccccccccccccccac4912d2d9df903ef9888b8a0e4cff", 16);
            biginteger c2m239v3h = biginteger.valueof(10);

            eccurve c2m239v3 = new eccurve.f2m(
                239,
                36,
                new biginteger("01238774666a67766d6676f778e676b66999176666e687666d8766c66a9f", 16),
                new biginteger("6a941977ba9f6a435199acfc51067ed587f519c5ecb541b8e44111de1d40", 16),
                c2m239v3n, c2m239v3h);

            return new x9ecparameters(
                c2m239v3,
                c2m239v3.decodepoint(
                    hex.decode("0370f6e9d04d289c4e89913ce3530bfde903977d42b146d539bf1bde4e9c92")),
                c2m239v3n, c2m239v3h,
                null);
        }
    };

    static x9ecparametersholder c2pnb272w1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m272w1n = new biginteger("0100faf51354e0e39e4892df6e319c72c8161603fa45aa7b998a167b8f1e629521", 16);
            biginteger c2m272w1h = biginteger.valueof(0xff06);

            eccurve c2m272w1 = new eccurve.f2m(
                272,
                1, 3, 56,
                new biginteger("0091a091f03b5fba4ab2ccf49c4edd220fb028712d42be752b2c40094dbacdb586fb20", 16),
                new biginteger("7167efc92bb2e3ce7c8aaaff34e12a9c557003d7c73a6faf003f99f6cc8482e540f7", 16),
                c2m272w1n, c2m272w1h);

            return new x9ecparameters(
                c2m272w1,
                c2m272w1.decodepoint(
                    hex.decode("026108babb2ceebcf787058a056cbe0cfe622d7723a289e08a07ae13ef0d10d171dd8d")),
                c2m272w1n, c2m272w1h,
                null);
        }
    };

    static x9ecparametersholder c2pnb304w1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m304w1n = new biginteger("0101d556572aabac800101d556572aabac8001022d5c91dd173f8fb561da6899164443051d", 16);
            biginteger c2m304w1h = biginteger.valueof(0xfe2e);

            eccurve c2m304w1 = new eccurve.f2m(
                304,
                1, 2, 11,
                new biginteger("00fd0d693149a118f651e6dce6802085377e5f882d1b510b44160074c1288078365a0396c8e681", 16),
                new biginteger("00bddb97e555a50a908e43b01c798ea5daa6788f1ea2794efcf57166b8c14039601e55827340be", 16),
                c2m304w1n, c2m304w1h);

            return new x9ecparameters(
                c2m304w1,
                c2m304w1.decodepoint(
                    hex.decode("02197b07845e9be2d96adb0f5f3c7f2cffbd7a3eb8b6fec35c7fd67f26ddf6285a644f740a2614")),
                c2m304w1n, c2m304w1h,
                null);
        }
    };

    static x9ecparametersholder c2tnb359v1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m359v1n = new biginteger("01af286bca1af286bca1af286bca1af286bca1af286bc9fb8f6b85c556892c20a7eb964fe7719e74f490758d3b", 16);
            biginteger c2m359v1h = biginteger.valueof(0x4c);

            eccurve c2m359v1 = new eccurve.f2m(
                359,
                68,
                new biginteger("5667676a654b20754f356ea92017d946567c46675556f19556a04616b567d223a5e05656fb549016a96656a557", 16),
                new biginteger("2472e2d0197c49363f1fe7f5b6db075d52b6947d135d8ca445805d39bc345626089687742b6329e70680231988", 16),
                c2m359v1n, c2m359v1h);

            return new x9ecparameters(
                c2m359v1,
                c2m359v1.decodepoint(
                    hex.decode("033c258ef3047767e7ede0f1fdaa79daee3841366a132e163aced4ed2401df9c6bdcde98e8e707c07a2239b1b097")),
                c2m359v1n, c2m359v1h,
                null);
        }
    };

    static x9ecparametersholder c2pnb368w1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m368w1n = new biginteger("010090512da9af72b08349d98a5dd4c7b0532eca51ce03e2d10f3b7ac579bd87e909ae40a6f131e9cfce5bd967", 16);
            biginteger c2m368w1h = biginteger.valueof(0xff70);

            eccurve c2m368w1 = new eccurve.f2m(
                368,
                1, 2, 85,
                new biginteger("00e0d2ee25095206f5e2a4f9ed229f1f256e79a0e2b455970d8d0d865bd94778c576d62f0ab7519ccd2a1a906ae30d", 16),
                new biginteger("00fc1217d4320a90452c760a58edcd30c8dd069b3c34453837a34ed50cb54917e1c2112d84d164f444f8f74786046a", 16),
                c2m368w1n, c2m368w1h);

            return new x9ecparameters(
                c2m368w1,
                c2m368w1.decodepoint(
                    hex.decode("021085e2755381dccce3c1557afa10c2f0c0c2825646c5b34a394cbcfa8bc16b22e7e789e927be216f02e1fb136a5f")),
                c2m368w1n, c2m368w1h,
                null);
        }
    };

    static x9ecparametersholder c2tnb431r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            biginteger c2m431r1n = new biginteger("0340340340340340340340340340340340340340340340340340340323c313fab50589703b5ec68d3587fec60d161cc149c1ad4a91", 16);
            biginteger c2m431r1h = biginteger.valueof(0x2760);

            eccurve c2m431r1 = new eccurve.f2m(
                431,
                120,
                new biginteger("1a827ef00dd6fc0e234caf046c6a5d8a85395b236cc4ad2cf32a0cadbdc9ddf620b0eb9906d0957f6c6feacd615468df104de296cd8f", 16),
                new biginteger("10d9b4a3d9047d8b154359abfb1b7f5485b04ceb868237ddc9deda982a679a5a919b626d4e50a8dd731b107a9962381fb5d807bf2618", 16),
                c2m431r1n, c2m431r1h);

            return new x9ecparameters(
                c2m431r1,
                c2m431r1.decodepoint(
                    hex.decode("02120fc05d3c67a99de161d2f4092622feca701be4f50f4758714e8a87bbf2a658ef8c21e7c5efe965361f6c2999c0c247b0dbd70ce6b7")),
                c2m431r1n, c2m431r1h,
                null);
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
        definecurve("prime192v1", x9objectidentifiers.prime192v1, prime192v1);
        definecurve("prime192v2", x9objectidentifiers.prime192v2, prime192v2);
        definecurve("prime192v3", x9objectidentifiers.prime192v3, prime192v3);
        definecurve("prime239v1", x9objectidentifiers.prime239v1, prime239v1);
        definecurve("prime239v2", x9objectidentifiers.prime239v2, prime239v2);
        definecurve("prime239v3", x9objectidentifiers.prime239v3, prime239v3);
        definecurve("prime256v1", x9objectidentifiers.prime256v1, prime256v1);
        definecurve("c2pnb163v1", x9objectidentifiers.c2pnb163v1, c2pnb163v1);
        definecurve("c2pnb163v2", x9objectidentifiers.c2pnb163v2, c2pnb163v2);
        definecurve("c2pnb163v3", x9objectidentifiers.c2pnb163v3, c2pnb163v3);
        definecurve("c2pnb176w1", x9objectidentifiers.c2pnb176w1, c2pnb176w1);
        definecurve("c2tnb191v1", x9objectidentifiers.c2tnb191v1, c2tnb191v1);
        definecurve("c2tnb191v2", x9objectidentifiers.c2tnb191v2, c2tnb191v2);
        definecurve("c2tnb191v3", x9objectidentifiers.c2tnb191v3, c2tnb191v3);
        definecurve("c2pnb208w1", x9objectidentifiers.c2pnb208w1, c2pnb208w1);
        definecurve("c2tnb239v1", x9objectidentifiers.c2tnb239v1, c2tnb239v1);
        definecurve("c2tnb239v2", x9objectidentifiers.c2tnb239v2, c2tnb239v2);
        definecurve("c2tnb239v3", x9objectidentifiers.c2tnb239v3, c2tnb239v3);
        definecurve("c2pnb272w1", x9objectidentifiers.c2pnb272w1, c2pnb272w1);
        definecurve("c2pnb304w1", x9objectidentifiers.c2pnb304w1, c2pnb304w1);
        definecurve("c2tnb359v1", x9objectidentifiers.c2tnb359v1, c2tnb359v1);
        definecurve("c2pnb368w1", x9objectidentifiers.c2pnb368w1, c2pnb368w1);
        definecurve("c2tnb431r1", x9objectidentifiers.c2tnb431r1, c2tnb431r1);
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
