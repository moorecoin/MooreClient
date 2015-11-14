package org.ripple.bouncycastle.asn1.cryptopro;

import java.math.biginteger;
import java.util.enumeration;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;

/**
 * table of the available named parameters for gost 3410-94.
 */
public class gost3410namedparameters
{
    static final hashtable objids = new hashtable();
    static final hashtable params = new hashtable();
    static final hashtable names = new hashtable();

    static private gost3410paramsetparameters cryptoproa = new gost3410paramsetparameters(
            1024,
            new biginteger("127021248288932417465907042777176443525787653508916535812817507265705031260985098497423188333483401180925999995120988934130659205614996724254121049274349357074920312769561451689224110579311248812610229678534638401693520013288995000362260684222750813532307004517341633685004541062586971416883686778842537820383"),
            new biginteger("68363196144955700784444165611827252895102170888761442055095051287550314083023"),
            new biginteger("100997906755055304772081815535925224869841082572053457874823515875577147990529272777244152852699298796483356699682842027972896052747173175480590485607134746852141928680912561502802222185647539190902656116367847270145019066794290930185446216399730872221732889830323194097355403213400972588322876850946740663962")
//            validationalgorithm {
//                    algorithm
//                        id-gostr3410-94-bbis,
//                    parameters
//                        gostr3410-94-validationbisparameters: {
//                            x0      1376285941,
//                            c       3996757427
//                        }
//                }

           );
    
    static private gost3410paramsetparameters cryptoprob = new gost3410paramsetparameters(
            1024,
            new biginteger("139454871199115825601409655107690713107041707059928031797758001454375765357722984094124368522288239833039114681648076688236921220737322672160740747771700911134550432053804647694904686120113087816240740184800477047157336662926249423571248823968542221753660143391485680840520336859458494803187341288580489525163"),
            new biginteger("79885141663410976897627118935756323747307951916507639758300472692338873533959"),
            new biginteger("42941826148615804143873447737955502392672345968607143066798112994089471231420027060385216699563848719957657284814898909770759462613437669456364882730370838934791080835932647976778601915343474400961034231316672578686920482194932878633360203384797092684342247621055760235016132614780652761028509445403338652341")
//    validationalgorithm {
//            algorithm
//                id-gostr3410-94-bbis,
//            parameters
//                gostr3410-94-validationbisparameters: {
//                    x0      1536654555,
//                    c       1855361757,
//                    d       14408629386140014567655
//4902939282056547857802241461782996702017713059974755104394739915140
//6115284791024439062735788342744854120601660303926203867703556828005
//8957203818114895398976594425537561271800850306
//                }
//        }
//}
         );

    static private gost3410paramsetparameters cryptoproxcha = new gost3410paramsetparameters(
    1024,
    new biginteger("142011741597563481196368286022318089743276138395243738762872573441927459393512718973631166078467600360848946623567625795282774719212241929071046134208380636394084512691828894000571524625445295769349356752728956831541775441763139384457191755096847107846595662547942312293338483924514339614727760681880609734239"),
    new biginteger("91771529896554605945588149018382750217296858393520724172743325725474374979801"),
    new biginteger("133531813272720673433859519948319001217942375967847486899482359599369642528734712461590403327731821410328012529253871914788598993103310567744136196364803064721377826656898686468463277710150809401182608770201615324990468332931294920912776241137878030224355746606283971659376426832674269780880061631528163475887")
   );
    
    static
    {      
        params.put(cryptoproobjectidentifiers.gostr3410_94_cryptopro_a, cryptoproa);       
        params.put(cryptoproobjectidentifiers.gostr3410_94_cryptopro_b, cryptoprob);       
//        params.put(cryptoproobjectidentifiers.gostr3410_94_cryptopro_c, cryptoproc);       
//        params.put(cryptoproobjectidentifiers.gostr3410_94_cryptopro_d, cryptoprod);       
        params.put(cryptoproobjectidentifiers.gostr3410_94_cryptopro_xcha, cryptoproxcha);       
//        params.put(cryptoproobjectidentifiers.gostr3410_94_cryptopro_xchb, cryptoproxcha);   
//        params.put(cryptoproobjectidentifiers.gostr3410_94_cryptopro_xchc, cryptoproxcha);
        
        objids.put("gostr3410-94-cryptopro-a", cryptoproobjectidentifiers.gostr3410_94_cryptopro_a);
        objids.put("gostr3410-94-cryptopro-b", cryptoproobjectidentifiers.gostr3410_94_cryptopro_b);
        objids.put("gostr3410-94-cryptopro-xcha", cryptoproobjectidentifiers.gostr3410_94_cryptopro_xcha);
    }

    /**
     * return the gost3410paramsetparameters object for the given oid, null if it 
     * isn't present.
     *
     * @param oid an object identifier representing a named parameters, if present.
     */
    public static gost3410paramsetparameters getbyoid(
        asn1objectidentifier  oid)
    {
        return (gost3410paramsetparameters)params.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for parameters
     * contained in this structure.
     */
    public static enumeration getnames()
    {
        return objids.keys();
    }

    public static gost3410paramsetparameters getbyname(
        string  name)
    {
        asn1objectidentifier oid = (asn1objectidentifier)objids.get(name);

        if (oid != null)
        {
            return (gost3410paramsetparameters)params.get(oid);
        }

        return null;
    }

    public static asn1objectidentifier getoid(string name)
    {
        return (asn1objectidentifier)objids.get(name);
    }
}
