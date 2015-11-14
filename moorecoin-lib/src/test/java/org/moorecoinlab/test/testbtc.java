package org.moorecoinlab.test;

import org.moorecoinlab.btc.base58;
import org.moorecoinlab.btc.bitutil;
import org.moorecoinlab.btc.eckey;
import org.moorecoinlab.btc.account.address;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.junit.test;
import org.ripple.bouncycastle.util.encoders.hex;

import java.security.messagedigest;

import static org.moorecoinlab.btc.bitutil.bytestohexstring;

public class testbtc {

    @test
    public void testbitcoinaddressfrompub() {
        byte[] pub = hex.decode("0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6");
        byte[] priv = null;
        eckey eckey = new eckey(priv, pub);
        system.out.println(bytestohexstring(eckey.getpubkey()));
        //step 3,4. sha256 then  ripemd-160
        system.out.println(bytestohexstring(eckey.getpubkeyhash()));
        //step 5,6,7,8,9. ripemd160(sha256(input))
        address addr = eckey.toaddress(bitutil.address_version);
        //step 10. base58
        system.out.println(addr.tostring());
    }


    @test
    public void testbtcaddr() throws moorecoinexception {
        bitutil.debug = false;
        boolean b1 = bitutil.isbtcaddress("17kzeh4n8g49gfvddzsf8pjapfyod1mndl");
        boolean b2 = bitutil.isbtcaddress("17kzeh4n8g44gfvddzsf8pjapfyod1mndl");
        boolean b3 = bitutil.isbtcaddress("17kzeh4n8g49gfvddzsf8pjapfyod1mnd");
        boolean b4 = bitutil.isbtcaddress("1dkybekt5s2gdtv7aqw6rqepavnsryhoym");
        boolean b5 = bitutil.isbtcaddress("1epqtdeywdmxsndkqbbjrr7ucusf2u1t4n");
        system.out.println(b1 + ", " + b2 + ", " + b3 + ", " + b4 + ", " + b5);

        //private key in base58 format
        eckey ec = eckey.getecfromprivstr("qknnc32zsrbheepf8ugx7wefxy4aoyp6x9kgfkxpms1");
        system.out.println("priv in base58 : " + bytestohexstring(ec.getprivkeybytes()));
        system.out.println(ec.toaddress(0).tostring());

        //private key in btc-qt format
        ec = eckey.getecfromprivstr("5hry2qjml67swouwhcfsd2r31fsip7w4tsqzwrcuu6lm5esv2f9");
        system.out.println("priv in btc-qt : " + bytestohexstring(ec.getprivkeybytes()));
        system.out.println(ec.toaddress(0).tostring());

        //private key in hex
        ec = eckey.getecfromprivstr("0615dd0779606fdd958fb6ef5a608c378577b3f5e8c33fe910ec8d0400cdf044");
        system.out.println("priv in hex    : " + bytestohexstring(ec.getprivkeybytes()));
        system.out.println(ec.toaddress(0).tostring());

        //private key in base64
        ec = eckey.getecfromprivstr("bhxdb3lgb92vj7bvwmcmn4v3s/xowz/peoynbadn8eq=");
        system.out.println("priv in base64 : " + bytestohexstring(ec.getprivkeybytes()));
        system.out.println(ec.toaddress(0).tostring());
        system.out.println( bytestohexstring(ec.getpubkey()) );

        //get a new eckey,addr
        eckey ec2 = new eckey();
        system.out.println("generate new ec: " + ec2.toaddress(base58.ver_address) + "   priv:" + bytestohexstring(ec2.getprivkeybytes()));
    }

    @test
    public void testhash() {
        try {
            byte[] input = "this is a string test".getbytes();
            //byte[] input = "hello".getbytes();

            //1. sha256(i)
            byte[] sha256 = messagedigest.getinstance("sha-256").digest(input);
            system.out.println(bytestohexstring(sha256));

            //2. sha256( sha256(i) )
            sha256 = bitutil.doubledigest(input);
            system.out.println(bytestohexstring(sha256));

            //3. ripemd( sha256(i) )
            byte[] ripemd = bitutil.sha256hash160(input);
            system.out.println(bytestohexstring(ripemd));

            //4.1 addr to bytes
            system.out.println(bytestohexstring(base58.decode("1epqtdeywdmxsndkqbbjrr7ucusf2u1t4n")));
            //4.2 bytes to addr
            system.out.println( base58.encode(bitutil.parseashexorbase58("0097a5fda689533a9cddc55d4e79330d6b87966bf3532f3a3b")) );
        } catch (exception e) {
            e.printstacktrace();
        }
    }

}
