package org.moorecoinlab.client.util;

import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.utils;
import org.moorecoinlab.core.hash.b58;

import java.math.biginteger;

/**
 * create some magic address, like:
 */
public class createmagicmoorecoinaddress {
    public static b58 b58 = b58.getinstance();

    public static void main(string[] v) {
        string startseed = "shezxgecjgude4epf7dff9hzgewin";
        byte[] seed_hex = null;
        string prefix = "rada";
        int targetcount = 3;
        if(v.length > 0 && v[0] != null) {
            system.out.println(v[0]);
            if(v[0].startswith("s") && v[0].length() == b58.len_family_seed) {
                startseed = v[0];
                seed_hex = b58.decodefamilyseed(startseed);
            } else if(v[0].length() == b58.len_family_seed_hex * 2) {
                seed_hex = convert.hextobytes(v[0]);
            }
        } else {
            if (seed_hex == null) seed_hex = b58.decodefamilyseed(startseed);
        }
        if(v.length > 1 && v[1] != null) prefix = v[1];
        if(v.length > 2 && v[2] != null) targetcount = integer.parseint(v[2]);

        magic(seed_hex, prefix, targetcount);
        system.exit(0);
    }

    public static void magic(byte[] seed_hex, string prefix, int targetcount) {
        biginteger bi = utils.ubigint(seed_hex);
        system.out.println("initial seed_dec is " + bi.longvalue());

        long ts0 = system.currenttimemillis();
        int round = 0, bingo = 0;

        while(true) {
            byte[] b16 = utils.lowarray(bi.tobytearray(), b58.len_family_seed_hex);
            accountid a = accountid.fromseedbytes(b16);
            if(a.address.startswith(prefix)) {
                long ts1 = system.currenttimemillis();
                system.out.println("====== bingo! ==> round:" + round + ", time=" + (ts1 - ts0) + "ms, count=" + bingo);
                system.out.println("addr=" + a + " seed_hex=" + convert.bytestohex(b16) + " seed=" + b58.encodefamilyseed(b16));
                bingo++;
                if (bingo >= targetcount)
                    break;
            }
            bi = bi.add(biginteger.one);
            round++;
            if(round % 1000 == 0) {
                long ts1 = system.currenttimemillis();
                system.out.println("  round: " + round + ", cur seed_dec is : " + bi.longvalue() + ", time=" + (ts1-ts0) + "ms");
            }
        }//end while

        long ts2 = system.currenttimemillis();
        system.out.println("ending...  round: " + round + ", cur seed_dec is : " + bi.longvalue() + ", total_time=" + (ts2-ts0) + "ms");
    }
}
