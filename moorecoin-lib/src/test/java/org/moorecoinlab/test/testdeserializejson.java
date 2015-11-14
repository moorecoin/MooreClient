package org.moorecoinlab.test;

import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.accountline;
import org.moorecoinlab.core.currency;
import org.json.jsonarray;
import org.json.jsonobject;
import org.junit.test;

import java.util.arraylist;
import java.util.list;

public class testdeserializejson {

    @test
    public void testaccountlineparser(){
        string jsonstr = "{\n" +
                "    \"result\": {\n" +
                "        \"account\": \"reveyznavpe28tuxzrtvwmvrlnivkcbznd\", \n" +
                "        \"lines\": [\n" +
                "            {\n" +
                "                \"account\": \"rbvskmujttfbhvtqmous9ckv9mqka6zu3w\", \n" +
                "                \"balance\": \"-102\", \n" +
                "                \"currency\": \"dnc\", \n" +
                "                \"limit\": \"0\", \n" +
                "                \"limit_peer\": \"1000000000\", \n" +
                "                \"no_ripple_peer\": true, \n" +
                "                \"quality_in\": 0, \n" +
                "                \"quality_out\": 0\n" +
                "            }, \n" +
                "            {\n" +
                "                \"account\": \"rgfddmog4qb3mkmzjeohrs2oxwj2joyzkm\", \n" +
                "                \"balance\": \"-1766.3\", \n" +
                "                \"currency\": \"dnc\", \n" +
                "                \"limit\": \"0\", \n" +
                "                \"limit_peer\": \"1000000000\", \n" +
                "                \"no_ripple_peer\": true, \n" +
                "                \"quality_in\": 0, \n" +
                "                \"quality_out\": 0\n" +
                "            }, \n" +
                "            {\n" +
                "                \"account\": \"rpw536w3t5dztpve4vpgsdzlhbqc3fx9t8\", \n" +
                "                \"balance\": \"-7932.7\", \n" +
                "                \"currency\": \"dnc\", \n" +
                "                \"limit\": \"0\", \n" +
                "                \"limit_peer\": \"1000000000\", \n" +
                "                \"quality_in\": 0, \n" +
                "                \"quality_out\": 0\n" +
                "            }\n" +
                "        ], \n" +
                "        \"status\": \"success\"\n" +
                "    }\n" +
                "}";
        jsonobject json = new jsonobject(jsonstr);
        string address = json.getjsonobject("result").getstring("account");
        jsonarray lines = json.getjsonobject("result").getjsonarray("lines");
        list<accountline> accountlinelist = new arraylist<>();
        for(int i=0;i<lines.length();i++){
            accountline accountline = accountline.fromjson(accountid.fromaddress(address), lines.getjsonobject(i));
            system.out.println("account*********"+accountline.balance.issuer().address);
            system.out.println(accountline.balance);
            system.out.println(accountline.currency);
            system.out.println(accountline.quality_in);
            system.out.println(accountline.quality_out);
            system.out.println(accountline.limit_peer);
            accountlinelist.add(accountline);
        }
        system.out.println(accountlinelist);
    }

    @test
    public void testcurrency(){
        currency currency = currency.vbc;
        system.out.println("currency:"+currency.tostring());
    }
}
