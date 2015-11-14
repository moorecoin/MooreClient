package org.moorecoinlab.test;

import com.google.gson.gson;
import org.moorecoinlab.client.ws.moorecoinwebsocketclient;
import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.amount;
import org.moorecoinlab.core.currency;
import org.moorecoinlab.core.stobject;
import org.moorecoinlab.core.hash.b58;
import org.moorecoinlab.core.types.known.tx.transaction;
import org.moorecoinlab.core.types.known.tx.result.transactionmeta;
import org.moorecoinlab.core.types.known.tx.signed.signedtransaction;
import org.moorecoinlab.core.uint.uint32;
import org.moorecoinlab.crypto.ecdsa.ikeypair;
import org.moorecoinlab.crypto.ecdsa.seed;
import org.json.jsonobject;
import org.junit.test;
import org.moorecoinlab.core.types.known.tx.txns.*;

import java.math.bigdecimal;
import java.util.hashmap;
import java.util.map;

/**
 * test some kinds of tx, only sign the object, not really send to server .
 */
public class testtxn {
    final string seed_1 = "snopbrxtmemymhuvtgbuqafg1sutb"; // please change me !!
    final string seed_2 = "snopbrxtmemymhuvtgbuqafg1sutb"; // please change me !!
    accountid destaddr       = accountid.fromaddress("rew7hncfx5jjxpyfu7ywbhkogko5ptdg5q"); // please change me !!
    public static string dest2str   = "reveyznavpe28tuxzrtvwmvrlnivkcbznd";                 // please change me !!
    public static string destcnystr = "rpyppqdzj92jhrnwdesttrym2meqigthq3";                 // please change me !!

    accountid dest2          = accountid.fromaddress(dest2str);
    accountid addrcnygateway = accountid.fromaddress(destcnystr);

    @test
    public void testcreatepaymenttxsign() throws exception {
        ikeypair kp = seed.getkeypair(seed_1);
        payment txn = new payment();
        //set the target address of tx
        txn.destination(destaddr);
        //set the amount 0.01 vrp, note: vrp unit needs * 10^6
        txn.amount(amount.fromstring("10000"));
        //set the sender
        txn.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed_1)));

        //signing...
        signedtransaction sign = new signedtransaction(txn);
        // param 2 is tx fee;   param 3 is account_info.sequence returned
        sign.prepare(kp, amount.fromstring("10"), new uint32(16), null );
        system.out.println("blob:" + sign.tx_blob);
        system.out.println("hash:" + sign.hash);
        system.out.println("txn_type:" + sign.transactiontype());
        system.out.println(txn);
    }

    @test
    public void testcreatepaymentvbctxsign(){
        ikeypair kp = seed.getkeypair(seed_1);
        payment txn = new payment();
        //set the target address of tx
        txn.destination(destaddr);
        //set tx fee, vbc unit needs not * 10^6
        amount vbc = new amount(new bigdecimal("10000"), currency.vbc, accountid.vbc_0);
        txn.amount(vbc);
        //set the sender
        txn.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed_1)));
        signedtransaction sign = new signedtransaction(txn);
        // param 2 is tx fee;   param 3 is account_info.sequence returned
        sign.prepare(kp, amount.fromstring("15"), new uint32(16), null );
        system.out.println("blob:" + sign.tx_blob);
        system.out.println("hash:" + sign.hash);
        system.out.println("txn_type:" + sign.transactiontype());
        system.out.println(txn);
    }

    @test
    public void testcreateaddrefereesign() throws exception {
        ikeypair kp = seed.getkeypair(seed_2);
        addreferee txn = new addreferee();
        //set sender, aka invite target
        txn.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed_2)));
        //set target, aka invite source
        txn.destination(dest2);
        signedtransaction sign = new signedtransaction(txn);
        // param 2 is tx fee;   param 3 is account_info.sequence returned
        sign.prepare(kp, amount.fromstring("15"), new uint32(13), null );
        system.out.println("blob:" + sign.tx_blob);
        system.out.println("hash:" + sign.hash);
        system.out.println("txn_type:" + sign.transactiontype());
    }

    @test
    public void testoffercreatetxsign(){
        ikeypair kp = seed.getkeypair(seed_2);
        offercreate txn = new offercreate();
        //set sender
        txn.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed_2)));
        //other currency, need not * 10^6
        txn.takergets(new amount(new bigdecimal("10"), currency.fromstring("dnc"), dest2));
        txn.takerpays(amount.fromstring("20000000"));
        signedtransaction sign = new signedtransaction(txn);
        // param 2 is tx fee;   param 3 is account_info.sequence returned
        sign.prepare(kp, amount.fromstring("15"), new uint32(14), null );
        system.out.println("blob:" + sign.tx_blob);
        system.out.println("hash:" + sign.hash);
        system.out.println("txn_type:" + sign.transactiontype());
    }

    @test
    public void testoffercanceltxsign(){
        ikeypair kp = seed.getkeypair(seed_2);
        offercancel txn = new offercancel();
        //set sender
        txn.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed_2)));
        txn.offersequence(new uint32(14));//account_offers.seq
        signedtransaction sign = new signedtransaction(txn);
        // param 2 is tx fee;   param 3 is account_info.sequence returned
        sign.prepare(kp, amount.fromstring("15"), new uint32(15), null );
        system.out.println("blob:" + sign.tx_blob);
        system.out.println("hash:" + sign.hash);
        system.out.println("txn_type:" + sign.transactiontype());
    }

    @test
    public void testtrustsettxsign(){
        ikeypair kp = seed.getkeypair(seed_2);
        trustset txn = new trustset();
        //set sender
        txn.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed_2)));
        //set trustlimit. note, amount unit must be integer.
        amount limitamount = new amount(new bigdecimal("10000"), currency.fromstring("cny"), addrcnygateway);
        txn.limitamount(limitamount);
        signedtransaction sign = new signedtransaction(txn);
        // param 2 is tx fee;   param 3 is account_info.sequence returned
        sign.prepare(kp, amount.fromstring("15"), new uint32(17), null );
        system.out.println("blob:" + sign.tx_blob);
        system.out.println("hash:" + sign.hash);
        system.out.println("txn_type:" + sign.transactiontype());
    }

    @test
    public void testtransactionjsonparser() throws exception {
        string json = "{" +
                "  \"account\": \"rad5qjmashlehzxf9wjumo6vrk4arj9cf3\"," +
                "  \"fee\": \"10\"," +
                "  \"flags\": 0," +
                "  \"sequence\": 103929," +
                "  \"signingpubkey\": \"028472865af4cb32aa285834b57576b7290aa8c31b459047db27e16f418d6a7166\"," +
                "  \"takergets\": {" +
                "    \"currency\": \"ils\"," +
                "    \"issuer\": \"rnprnzbb92bvpahhzr4ixdtvecgv5pofm9\"," +
                "    \"value\": \"1694.768\"" +
                "  }," +
                "  \"takerpays\": \"98957503520\"," +
                "  \"transactiontype\": \"offercreate\"," +
                "  \"txnsignature\": \"304502202abe08d5e78d1e74a4c18f2714f64e87b8bd57444afa5733109eb3c077077520022100db335ee97386e4c0591cac024d50e9230d8f171eeb901b5e5e4bd6d1e0aef98c\"," +
                "  \"hash\": \"232e91912789ea1419679a4aa920c22cfc7c6b601751d6cbe89898c26d7f4394\"," +
                "  \"metadata\": {" +
                "    \"affectednodes\": [" +
                "      {" +
                "        \"creatednode\": {" +
                "          \"ledgerentrytype\": \"offer\"," +
                "          \"ledgerindex\": \"3596ce72c902bafaab56cc486acaf9b4afc67cf7cadbb81a4aa9cbdc8c5cb1aa\"," +
                "          \"newfields\": {" +
                "            \"account\": \"rad5qjmashlehzxf9wjumo6vrk4arj9cf3\"," +
                "            \"bookdirectory\": \"62a3338caf2e1bee510fc33de1863c56948e962cce173ca55c14be8a20d7f000\"," +
                "            \"ownernode\": \"000000000000000e\"," +
                "            \"sequence\": 103929," +
                "            \"takergets\": {" +
                "              \"currency\": \"ils\"," +
                "              \"issuer\": \"rnprnzbb92bvpahhzr4ixdtvecgv5pofm9\"," +
                "              \"value\": \"1694.768\"" +
                "            }," +
                "            \"takerpays\": \"98957503520\"" +
                "          }" +
                "        }" +
                "      }," +
                "      {" +
                "        \"creatednode\": {" +
                "          \"ledgerentrytype\": \"directorynode\"," +
                "          \"ledgerindex\": \"62a3338caf2e1bee510fc33de1863c56948e962cce173ca55c14be8a20d7f000\"," +
                "          \"newfields\": {" +
                "            \"exchangerate\": \"5c14be8a20d7f000\"," +
                "            \"rootindex\": \"62a3338caf2e1bee510fc33de1863c56948e962cce173ca55c14be8a20d7f000\"," +
                "            \"takergetscurrency\": \"000000000000000000000000494c530000000000\"," +
                "            \"takergetsissuer\": \"92d705968936c419ce614bf264b5eeb1cea47ff4\"" +
                "          }" +
                "        }" +
                "      }," +
                "      {" +
                "        \"modifiednode\": {" +
                "          \"finalfields\": {" +
                "            \"flags\": 0," +
                "            \"indexprevious\": \"0000000000000000\"," +
                "            \"owner\": \"rad5qjmashlehzxf9wjumo6vrk4arj9cf3\"," +
                "            \"rootindex\": \"801c5afb5862d4666d0df8e5be1385dc9b421ed09a4269542a07bc0267584b64\"" +
                "          }," +
                "          \"ledgerentrytype\": \"directorynode\"," +
                "          \"ledgerindex\": \"ab03f8aa02ffa4635e7ce2850416aec5542910a2b4dbe93c318feb08375e0db5\"" +
                "        }" +
                "      }," +
                "      {" +
                "        \"modifiednode\": {" +
                "          \"finalfields\": {" +
                "            \"account\": \"rad5qjmashlehzxf9wjumo6vrk4arj9cf3\"," +
                "            \"balance\": \"106861218302\"," +
                "            \"flags\": 0," +
                "            \"ownercount\": 9," +
                "            \"sequence\": 103930" +
                "          }," +
                "          \"ledgerentrytype\": \"accountroot\"," +
                "          \"ledgerindex\": \"cf23a37e39a571a0f22ec3e97eb0169936b520c3088963f16c5ee4ac59130b1b\"," +
                "          \"previousfields\": {" +
                "            \"balance\": \"106861218312\"," +
                "            \"ownercount\": 8," +
                "            \"sequence\": 103929" +
                "          }," +
                "          \"previoustxnid\": \"de15f43f4a73c4f6cb1c334d9e47bde84467c0902796bb81d4924885d1c11e6d\"," +
                "          \"previoustxnlgrseq\": 3225338" +
                "        }" +
                "      }" +
                "    ]," +
                "    \"transactionindex\": 0," +
                "    \"transactionresult\": \"tessuccess\"" +
                "  }" +
                "}";

        jsonobject txjson = new jsonobject(json);
        stobject meta = stobject.fromjsonobject((jsonobject) txjson.remove("metadata"));
        transactionmeta txnmeta = (transactionmeta) meta;
        system.out.println("affectednodes:"+txnmeta.affectednodes());
        system.out.println("transactionresult:"+txnmeta.engineresult());
        system.out.println("transactionindex:"+txnmeta.transactionindex());
        stobject tx = stobject.fromjsonobject(txjson);
        transaction txn = (transaction) tx;
        system.out.println("account:"+txn.account().address);
        system.out.println("fee:"+txn.fee());
        system.out.println("txtype:"+txn.transactiontype());
        system.out.println("ledger_sequence::"+txn.lastledgersequence());
        system.out.println("accounttxid:"+txn.accounttxnid());
        system.out.println("flags:"+txn.flags());
        system.out.println("previoustxid:"+txn.previoustxnid());
        system.out.println("sequence:"+txn.sequence());
        system.out.println("source tag:"+txn.sourcetag());
        system.out.println("operationlimit:"+txn.operationlimit());
        system.out.println("signature:"+txn.txnsignature().tohex());
        switch (txn.transactiontype()){
            case offercreate:
                offercreate oc = (offercreate) txn;
                system.out.println("offercreate-takergets:"+oc.takergets());
                system.out.println("offercreate-takerpays:"+oc.takerpays());
                break;
            case payment:
                payment payment = (payment) txn;
                system.out.println("payment-amount:"+payment.amount());
                system.out.println("payment-amount:"+payment.destination());
                system.out.println("payment-amount:"+payment.sendmax());
                break;
            case offercancel:
                offercancel ocl = (offercancel) txn;
                system.out.println("offercancel-offersequence:"+ocl.offersequence());
                break;
            case addreferee:
                addreferee arf = (addreferee) txn;
                system.out.println("addreferee-destaddr:"+arf.destination());
                break;
            case trustset:
                trustset trustset = (trustset) txn;
                system.out.println("trustset-limitamount:"+trustset.limitamount());
                system.out.println("trustset-qualityin:"+trustset.qualityin());
                system.out.println("trustset-qualityout:"+trustset.qualityout());
                break;
        }
    }


    private string maketx(string tx_blob) throws exception {
        map<string, object> data = new hashmap<>();
        data.put("id", 0);
        data.put("command", "submit");
        data.put("tx_blob", tx_blob);
        string postdata = new gson().tojson(data);
        string json = moorecoinwebsocketclient.request(postdata);
        system.out.println("make tx result: " + json);
        return json;
    }
}
