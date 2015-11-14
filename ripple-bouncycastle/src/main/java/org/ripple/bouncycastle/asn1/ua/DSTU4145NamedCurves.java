package org.ripple.bouncycastle.asn1.ua;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;

public class dstu4145namedcurves
{
    private static final biginteger zero = biginteger.valueof(0);
    private static final biginteger one = biginteger.valueof(1);

    public static final ecdomainparameters[] params = new ecdomainparameters[10];
    static final asn1objectidentifier[] oids = new asn1objectidentifier[10];

    //all named curves have the following oid format: 1.2.804.2.1.1.1.1.3.1.1.2.x
    //where x is the curve number 0-9
    static final string oidbase = uaobjectidentifiers.dstu4145le.getid() + ".2.";

    static
    {
        eccurve.f2m[] curves = new eccurve.f2m[10];
        curves[0] = new eccurve.f2m(163, 3, 6, 7, one, new biginteger("5ff6108462a2dc8210ab403925e638a19c1455d21", 16));
        curves[1] = new eccurve.f2m(167, 6, one, new biginteger("6ee3ceeb230811759f20518a0930f1a4315a827dac", 16));
        curves[2] = new eccurve.f2m(173, 1, 2, 10, zero, new biginteger("108576c80499db2fc16eddf6853bbb278f6b6fb437d9", 16));
        curves[3] = new eccurve.f2m(179, 1, 2, 4, one, new biginteger("4a6e0856526436f2f88dd07a341e32d04184572beb710", 16));
        curves[4] = new eccurve.f2m(191, 9, one, new biginteger("7bc86e2102902ec4d5890e8b6b4981ff27e0482750fefc03", 16));
        curves[5] = new eccurve.f2m(233, 1, 4, 9, one, new biginteger("06973b15095675534c7cf7e64a21bd54ef5dd3b8a0326aa936ece454d2c", 16));
        curves[6] = new eccurve.f2m(257, 12, zero, new biginteger("1cef494720115657e18f938d7a7942394ff9425c1458c57861f9eea6adbe3be10", 16));
        curves[7] = new eccurve.f2m(307, 2, 4, 8, one, new biginteger("393c7f7d53666b5054b5e6c6d3de94f4296c0c599e2e2e241050df18b6090bdc90186904968bb", 16));
        curves[8] = new eccurve.f2m(367, 21, one, new biginteger("43fc8ad242b0b7a6f3d1627ad5654447556b47bf6aa4a64b0c2afe42cadab8f93d92394c79a79755437b56995136", 16));
        curves[9] = new eccurve.f2m(431, 1, 3, 5, one, new biginteger("03ce10490f6a708fc26dfe8c3d27c4f94e690134d5bff988d8d28aaeaede975936c66bac536b18ae2dc312ca493117daa469c640caf3", 16));

        ecpoint[] points = new ecpoint[10];
        points[0] = curves[0].createpoint(new biginteger("2e2f85f5dd74ce983a5c4237229daf8a3f35823be", 16), new biginteger("3826f008a8c51d7b95284d9d03ff0e00ce2cd723a", 16), false);
        points[1] = curves[1].createpoint(new biginteger("7a1f6653786a68192803910a3d30b2a2018b21cd54", 16), new biginteger("5f49eb26781c0ec6b8909156d98ed435e45fd59918", 16), false);
        points[2] = curves[2].createpoint(new biginteger("4d41a619bcc6eadf0448fa22fad567a9181d37389ca", 16), new biginteger("10b51cc12849b234c75e6dd2028bf7ff5c1ce0d991a1", 16), false);
        points[3] = curves[3].createpoint(new biginteger("6ba06fe51464b2bd26dc57f48819ba9954667022c7d03", 16), new biginteger("25fbc363582dcec065080ca8287aaff09788a66dc3a9e", 16), false);
        points[4] = curves[4].createpoint(new biginteger("714114b762f2ff4a7912a6d2ac58b9b5c2fcfe76daeb7129", 16), new biginteger("29c41e568b77c617efe5902f11db96fa9613cd8d03db08da", 16), false);
        points[5] = curves[5].createpoint(new biginteger("3fcda526b6cdf83ba1118df35b3c31761d3545f32728d003eeb25efe96", 16), new biginteger("9ca8b57a934c54deeda9e54a7bbad95e3b2e91c54d32be0b9df96d8d35", 16), false);
        points[6] = curves[6].createpoint(new biginteger("02a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9e8dcd8d20fb7", 16), new biginteger("10686d41ff744d4449fccf6d8eea03102e6812c93a9d60b978b702cf156d814ef", 16), false);
        points[7] = curves[7].createpoint(new biginteger("216ee8b189d291a0224984c1e92f1d16bf75ccd825a087a239b276d3167743c52c02d6e7232aa", 16), new biginteger("5d9306bacd22b7faeb09d2e049c6e2866c5d1677762a8f2f2dc9a11c7f7be8340ab2237c7f2a0", 16), false);
        points[8] = curves[8].createpoint(new biginteger("324a6eddd512f08c49a99ae0d3f961197a76413e7be81a400ca681e09639b5fe12e59a109f78bf4a373541b3b9a1", 16), new biginteger("1ab597a5b4477f59e39539007c7f977d1a567b92b043a49c6b61984c3fe3481aaf454cd41ba1f051626442b3c10", 16), false);
        points[9] = curves[9].createpoint(new biginteger("1a62ba79d98133a16bbae7ed9a8e03c32e0824d57aef72f88986874e5aae49c27bed49a2a95058068426c2171e99fd3b43c5947c857d", 16), new biginteger("70b5e1e14031c1f70bbefe96bdde66f451754b4ca5f48da241f331aa396b8d1839a855c1769b1ea14ba53308b5e2723724e090e02db9", 16), false);

        biginteger[] n_s = new biginteger[10];
        n_s[0] = new biginteger("400000000000000000002bec12be2262d39bcf14d", 16);
        n_s[1] = new biginteger("3fffffffffffffffffffffb12ebcc7d7f29ff7701f", 16);
        n_s[2] = new biginteger("800000000000000000000189b4e67606e3825bb2831", 16);
        n_s[3] = new biginteger("3ffffffffffffffffffffffb981960435fe5ab64236ef", 16);
        n_s[4] = new biginteger("40000000000000000000000069a779cac1dabc6788f7474f", 16);
        n_s[5] = new biginteger("1000000000000000000000000000013e974e72f8a6922031d2603cfe0d7", 16);
        n_s[6] = new biginteger("800000000000000000000000000000006759213af182e987d3e17714907d470d", 16);
        n_s[7] = new biginteger("3ffffffffffffffffffffffffffffffffffffffc079c2f3825da70d390fbba588d4604022b7b7", 16);
        n_s[8] = new biginteger("40000000000000000000000000000000000000000000009c300b75a3fa824f22428fd28ce8812245ef44049b2d49", 16);
        n_s[9] = new biginteger("3fffffffffffffffffffffffffffffffffffffffffffffffffffffba3175458009a8c0a724f02f81aa8a1fcbaf80d90c7a95110504cf", 16);

        for (int i = 0; i < params.length; i++)
        {
            params[i] = new ecdomainparameters(curves[i], points[i], n_s[i]);
        }

        for (int i = 0; i < oids.length; i++)
        {
            oids[i] = new asn1objectidentifier(oidbase + i);
        }
    }

    /**
     * all named curves have the following oid format: 1.2.804.2.1.1.1.1.3.1.1.2.x
     * where x is the curve number 0-9
     */
    public static asn1objectidentifier[] getoids()
    {
        return oids;
    }

    /**
     * all named curves have the following oid format: 1.2.804.2.1.1.1.1.3.1.1.2.x
     * where x is the curve number 0-9
     */
    public static ecdomainparameters getbyoid(asn1objectidentifier oid)
    {
        string oidstr = oid.getid();
        if (oidstr.startswith(oidbase))
        {
            int index = integer.parseint(oidstr.substring(oidstr.length() - 1));
            return params[index];
        }
        return null;
    }
}
