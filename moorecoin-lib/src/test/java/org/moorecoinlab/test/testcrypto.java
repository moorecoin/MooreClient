package org.moorecoinlab.test;

import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.utils;
import org.moorecoinlab.core.wallet;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.moorecoinlab.core.hash.b58;
import org.moorecoinlab.core.hash.rfc1751;
import org.moorecoinlab.crypto.ecdsa.ikeypair;
import org.moorecoinlab.crypto.ecdsa.keypair;
import org.moorecoinlab.crypto.ecdsa.seed;
import org.junit.test;
import org.ripple.bouncycastle.util.encoders.hex;

import static org.junit.assert.assertequals;

public class testcrypto {

    public static b58 b58 = b58.getinstance();

    @test
    public void testbase58(){
        byte[] address = hex.decode("000103996a3bad918657f86e12a67d693e8fc8a814da4b958a244b5f14d93e57");
        string addr = b58.encodetostring(address);
        system.out.println(addr);

        addr = "r9af63nf7brfajz4dlm4dvxwc2uctxhlbd";
        byte[] bs  = b58.decode(addr);
        system.out.println(hex.tohexstring(bs));

        byte[] bs2 = b58.decodechecked(addr, b58.ver_account_id);
        system.out.println("  " + hex.tohexstring(bs2));
    }

    @test
    public void testrootseed() {
        try {

            accountid rootid =  accountid.accounts.get("root");
            system.out.println("root address : " + rootid.address + ", " + rootid.tohex() + ", " + rootid.isnativeissuer() + ", " + rootid.tojson());

            byte[] seed = seed.passphrasetoseedbytes("masterpassphrase");
            system.out.println("master_seed_hex: " + hex.tohexstring(seed));

            system.out.println("master_seed    :" + b58.encodefamilyseed(seed));
            system.out.println("master_seed dec: " + hex.tohexstring(b58.decodefamilyseed("snopbrxtmemymhuvtgbuqafg1sutb")));

            ikeypair keypair = seed.getkeypair(seed);
            system.out.println("seed to priv   : " + keypair.privhex() + ", pub=" + keypair.pubhex());

            wallet w = wallet.fromseedstring("snopbrxtmemymhuvtgbuqafg1sutb");
            system.out.println("wallet to priv : " + w.keypair().privhex() + ", pub=" + w.keypair().pubhex());

            rootid = new accountid(utils.sha256_ripemd160(hex.decode("0330e7fc9d56bb25d6893ba3f317ae5bcf33b3291bd63db32654a313222f7fd020")));
            system.out.println("pub to address : " + rootid.address);

            system.out.println("account public : " + b58.encodeaccountpublic(keypair.pubbytes()));
            system.out.println("node public    : " + b58.encodenodepublic(keypair.pubbytes()));

            wallet another = wallet.fromseedstring("shezxgecjgude4epf7dff9jtp7pyr");
            system.out.println("fromseedstring : " + another);

        } catch (moorecoinexception e) {
            e.printstacktrace();
        }
    }

    @test
    public void testprivatekey() {
        string btcpriv = "1acaaedece405b2a958212629e16f2eb46b153eee94cdd350fdeff52795525b7";  // root's private key
        ikeypair kp = new keypair(hex.decode(btcpriv));
        system.out.println("from priv   : " + kp.privhex());
        system.out.println("priv gen pub: " + kp.pubhex());

        accountid rootid = new accountid(utils.sha256_ripemd160(kp.pubbytes()));
        system.out.println("pub to addr : " + rootid.address);
    }


    @test
    public void testbtc_compatible() {
        wallet w = wallet.fromprivatekey("0615dd0779606fdd958fb6ef5a608c378577b3f5e8c33fe910ec8d0400cdf044");
        system.out.println(w);
    }

    @test
    public void testwallet() {
        wallet w1 = new wallet("masterpassphrase");
        system.out.println(w1);


//        for(int i=0; i<10; i++) {
//            wallet w2 = new wallet();
//            system.out.println(w2);
//        }
    }

    @test
    public void testrfc1751(){
        string key = rfc1751.getkeyfromenglish("ahoy clad judd noon mini chad cuba jan kant amid del lets");
        system.out.println(key);
        assertequals(key.touppercase(), "5bdd10a694f2e36ccac0cbe28ce2ac49");
    }

    @test
    public void testnodepub() {
        /*
rippled -q validation_create
{
   "result" : {
      "status" : "success",
      "validation_key" : "bait hess blab mid wage pro hang fist reel foil roam fist",
      "validation_public_key" : "n9mkwc3kiralqfsu2hnkyyzzqrzymjvgikohfmblpexwzztmzyxy",
      "validation_seed" : "sp5xmchnaczbpq8efpalspdjuyudp"
   }
}
         */
        string b58str[] = {     "sp5xmchnaczbpq8efpalspdjuyudp",
                                "ssdmxiywcnemazcjdk2ypxkg7ppdr",
                                "snfc8r8qpcngkalsfevngsjcpkx9a"};
        string publickey[] = {  "n9mkwc3kiralqfsu2hnkyyzzqrzymjvgikohfmblpexwzztmzyxy",
                                "n9jd5abyqmiakudjqwophku6vcndbp5cvuqrwbwzrbetaoggnpmv",
                                "n9mw8ndqzuuj1eholngffj6sbe1tbsypdscn5qrmywudwbrezhfs"
        };
        int i = 0;
        for(string s : b58str) {
            seed seed = seed.frombase58(s);
            string np = b58.encodenodepublic(seed.rootkeypair().pubbytes());
            system.out.println(np);
            assertequals(np, publickey[i++]);
        }

    }

}
