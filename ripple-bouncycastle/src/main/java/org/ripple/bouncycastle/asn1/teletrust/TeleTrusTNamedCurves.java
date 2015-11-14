package org.ripple.bouncycastle.asn1.teletrust;

import java.math.biginteger;
import java.util.enumeration;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.asn1.x9.x9ecparametersholder;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.util.strings;
import org.ripple.bouncycastle.util.encoders.hex;

/**
 * elliptic curves defined in "ecc brainpool standard curves and curve generation"
 * http://www.ecc-brainpool.org/download/draft_pkix_additional_ecc_dp.txt
 */
public class teletrustnamedcurves
{
    static x9ecparametersholder brainpoolp160r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                new biginteger("e95e4a5f737059dc60dfc7ad95b3d8139515620f", 16), // q
                new biginteger("340e7be2a280eb74e2be61bada745d97e8f7c300", 16), // a
                new biginteger("1e589a8595423412134faa2dbdec95c8d8675e58", 16)); // b

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("04bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc31667cb477a1a8ec338f94741669c976316da6321")), // g
                new biginteger("e95e4a5f737059dc60df5991d45029409e60fc09", 16), //n
                new biginteger("01", 16)); // h
        }
    };

    static x9ecparametersholder brainpoolp160t1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                //   new biginteger("24dbff5dec9b986bbfe5295a29bfbae45e0f5d0b", 16), // z
                new biginteger("e95e4a5f737059dc60dfc7ad95b3d8139515620f", 16), // q
                new biginteger("e95e4a5f737059dc60dfc7ad95b3d8139515620c", 16), // a'
                new biginteger("7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380", 16)); // b'

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("04b199b13b9b34efc1397e64baeb05acc265ff2378add6718b7c7c1961f0991b842443772152c9e0ad")), // g
                new biginteger("e95e4a5f737059dc60df5991d45029409e60fc09", 16), //n
                new biginteger("01", 16)); // h
        }
    };

    static x9ecparametersholder brainpoolp192r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                new biginteger("c302f41d932a36cda7a3463093d18db78fce476de1a86297", 16), // q
                new biginteger("6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef", 16), // a
                new biginteger("469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9", 16)); // b

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("04c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd614b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f")), // g
                new biginteger("c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1", 16), //n
                new biginteger("01", 16)); // h
        }
    };

    static x9ecparametersholder brainpoolp192t1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                //new biginteger("1b6f5cc8db4dc7af19458a9cb80dc2295e5eb9c3732104cb") //z
                new biginteger("c302f41d932a36cda7a3463093d18db78fce476de1a86297", 16), // q
                new biginteger("c302f41d932a36cda7a3463093d18db78fce476de1a86294", 16), // a'
                new biginteger("13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79", 16)); // b'

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("043ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129097e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9")), // g'
                new biginteger("c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1", 16), //n
                new biginteger("01", 16)); // h
        }
    };

    static x9ecparametersholder brainpoolp224r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                new biginteger("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff", 16), // q
                new biginteger("68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43", 16), // a
                new biginteger("2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b", 16)); // b

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("040d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd")), // g
                new biginteger("d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f", 16), //n
                new biginteger("01", 16)); // n
        }
    };
    static x9ecparametersholder brainpoolp224t1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                //new biginteger("2df271e14427a346910cf7a2e6cfa7b3f484e5c2cce1c8b730e28b3f") //z
                new biginteger("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff", 16), // q
                new biginteger("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0fc", 16), // a'
                new biginteger("4b337d934104cd7bef271bf60ced1ed20da14c08b3bb64f18a60888d", 16)); // b'

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("046ab1e344ce25ff3896424e7ffe14762ecb49f8928ac0c76029b4d5800374e9f5143e568cd23f3f4d7c0d4b1e41c8cc0d1c6abd5f1a46db4c")), // g'
                new biginteger("d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f", 16), //n
                new biginteger("01", 16)); // h
        }
    };
    static x9ecparametersholder brainpoolp256r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                new biginteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", 16), // q
                new biginteger("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9", 16), // a
                new biginteger("26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6", 16)); // b

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997")), // g
                new biginteger("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7", 16), //n
                new biginteger("01", 16)); // h
        }
    };
    static x9ecparametersholder brainpoolp256t1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                //new biginteger("3e2d4bd9597b58639ae7aa669cab9837cf5cf20a2c852d10f655668dfc150ef0") //z
                new biginteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", 16), // q
                new biginteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374", 16), // a'
                new biginteger("662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04", 16)); // b'

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("04a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f42d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be")), // g'
                new biginteger("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7", 16), //n
                new biginteger("01", 16)); // h
        }
    };
    static x9ecparametersholder brainpoolp320r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                new biginteger("d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27", 16), // q
                new biginteger("3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4", 16), // a
                new biginteger("520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6", 16)); // b

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("0443bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e2061114fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1")), // g
                new biginteger("d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311", 16), //n
                new biginteger("01", 16)); // h
        }
    };
    static x9ecparametersholder brainpoolp320t1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                //new biginteger("15f75caf668077f7e85b42eb01f0a81ff56ecd6191d55cb82b7d861458a18fefc3e5ab7496f3c7b1") //z
                new biginteger("d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27", 16), // q
                new biginteger("d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e24", 16), // a'
                new biginteger("a7f561e038eb1ed560b3d147db782013064c19f27ed27c6780aaf77fb8a547ceb5b4fef422340353", 16)); // b'

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("04925be9fb01afc6fb4d3e7d4990010f813408ab106c4f09cb7ee07868cc136fff3357f624a21bed5263ba3a7a27483ebf6671dbef7abb30ebee084e58a0b077ad42a5a0989d1ee71b1b9bc0455fb0d2c3")), // g'
                new biginteger("d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311", 16), //n
                new biginteger("01", 16)); // h
        }
    };
    static x9ecparametersholder brainpoolp384r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                new biginteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53", 16), // q
                new biginteger("7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826", 16), // a
                new biginteger("4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11", 16)); // b

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315")), // g
                new biginteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565", 16), //n
                new biginteger("01", 16)); // h
        }
    };
    static x9ecparametersholder brainpoolp384t1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                //new biginteger("41dfe8dd399331f7166a66076734a89cd0d2bcdb7d068e44e1f378f41ecbae97d2d63dbc87bccddccc5da39e8589291c") //z
                new biginteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53", 16), // q
                new biginteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec50", 16), // a'
                new biginteger("7f519eada7bda81bd826dba647910f8c4b9346ed8ccdc64e4b1abd11756dce1d2074aa263b88805ced70355a33b471ee", 16)); // b'

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("0418de98b02db9a306f2afcd7235f72a819b80ab12ebd653172476fecd462aabffc4ff191b946a5f54d8d0aa2f418808cc25ab056962d30651a114afd2755ad336747f93475b7a1fca3b88f2b6a208ccfe469408584dc2b2912675bf5b9e582928")), // g'
                new biginteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565", 16), //n
                new biginteger("01", 16)); // h
        }
    };
    static x9ecparametersholder brainpoolp512r1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                new biginteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3", 16), // q
                new biginteger("7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca", 16), // a
                new biginteger("3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723", 16)); // b

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("0481aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f8227dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892")), // g
                new biginteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069", 16), //n
                new biginteger("01", 16)); // h
        }
    };
    static x9ecparametersholder brainpoolp512t1 = new x9ecparametersholder()
    {
        protected x9ecparameters createparameters()
        {
            eccurve curve = new eccurve.fp(
                //new biginteger("12ee58e6764838b69782136f0f2d3ba06e27695716054092e60a80bedb212b64e585d90bce13761f85c3f1d2a64e3be8fea2220f01eba5eeb0f35dbd29d922ab") //z
                new biginteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3", 16), // q
                new biginteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f0", 16), // a'
                new biginteger("7cbbbcf9441cfab76e1890e46884eae321f70c0bcb4981527897504bec3e36a62bcdfa2304976540f6450085f2dae145c22553b465763689180ea2571867423e", 16)); // b'

            return new x9ecparameters(
                curve,
                curve.decodepoint(hex.decode("04640ece5c12788717b9c1ba06cbc2a6feba85842458c56dde9db1758d39c0313d82ba51735cdb3ea499aa77a7d6943a64f7a3f25fe26f06b51baa2696fa9035da5b534bd595f5af0fa2c892376c84ace1bb4e3019b71634c01131159cae03cee9d9932184beef216bd71df2dadf86a627306ecff96dbb8bace198b61e00f8b332")), // g'
                new biginteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069", 16), //n
                new biginteger("01", 16)); // h
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
        definecurve("brainpoolp160r1", teletrustobjectidentifiers.brainpoolp160r1, brainpoolp160r1);
        definecurve("brainpoolp160t1", teletrustobjectidentifiers.brainpoolp160t1, brainpoolp160t1);
        definecurve("brainpoolp192r1", teletrustobjectidentifiers.brainpoolp192r1, brainpoolp192r1);
        definecurve("brainpoolp192t1", teletrustobjectidentifiers.brainpoolp192t1, brainpoolp192t1);
        definecurve("brainpoolp224r1", teletrustobjectidentifiers.brainpoolp224r1, brainpoolp224r1);
        definecurve("brainpoolp224t1", teletrustobjectidentifiers.brainpoolp224t1, brainpoolp224t1);
        definecurve("brainpoolp256r1", teletrustobjectidentifiers.brainpoolp256r1, brainpoolp256r1);
        definecurve("brainpoolp256t1", teletrustobjectidentifiers.brainpoolp256t1, brainpoolp256t1);
        definecurve("brainpoolp320r1", teletrustobjectidentifiers.brainpoolp320r1, brainpoolp320r1);
        definecurve("brainpoolp320t1", teletrustobjectidentifiers.brainpoolp320t1, brainpoolp320t1);
        definecurve("brainpoolp384r1", teletrustobjectidentifiers.brainpoolp384r1, brainpoolp384r1);
        definecurve("brainpoolp384t1", teletrustobjectidentifiers.brainpoolp384t1, brainpoolp384t1);
        definecurve("brainpoolp512r1", teletrustobjectidentifiers.brainpoolp512r1, brainpoolp512r1);
        definecurve("brainpoolp512t1", teletrustobjectidentifiers.brainpoolp512t1, brainpoolp512t1);
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

    public static asn1objectidentifier getoid(short curvesize, boolean twisted)
    {
        return getoid("brainpoolp" + curvesize + (twisted ? "t" : "r") + "1");
    }
}
