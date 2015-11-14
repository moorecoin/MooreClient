package org.moorecoinlab.client.handler;

import com.google.gson.gson;
import org.moorecoinlab.client.clientprocessor;
import org.moorecoinlab.client.util.convert;
import org.moorecoinlab.client.util.httpclient;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.moorecoinlab.core.hash.b58;
import org.apache.log4j.logger;
import org.json.jsonobject;

import java.util.*;
import java.util.concurrent.concurrenthashmap;

public class ledgerlist implements clientprocessor {

    public static final ledgerlist instance = new ledgerlist();
    private static final logger logger = logger.getlogger(ledgerlist.class);

    private static final map<integer, map<string, object>> ledgers = new concurrenthashmap<>();

    private static volatile integer maxindex = 0;

    @override
    public string processresponse(map<string, string> params) throws moorecoinexception {
        string data = "{\"method\": \"ledger_closed\",\"params\": [{}]}";
        httpclient.response response = httpclient.post(uri, data);
        jsonobject obj = new jsonobject(response.getresponsestring());
        int index = obj.getjsonobject("result").getint("ledger_index");
        int curindex = getledger(index);
        if(maxindex>0 && curindex - maxindex > 50){
            maxindex = curindex - 50;
        }
        if(curindex - maxindex >1 && maxindex > 0){
            for(int i=maxindex +1;i<curindex;i++){
                getledger(i);
            }
        }
        if(curindex > maxindex){
            maxindex = curindex;
        }

        integer[] ks = new integer[ledgers.keyset().size()];
        ledgers.keyset().toarray(ks);
        list<integer> keys = arrays.aslist(ks);
        collections.sort(keys, (o1, o2) -> o2 - o1);
        if (keys.size() > 50) {
            ledgers.keyset().foreach(key -> {
                if (keys.indexof(key) > 49) {
                    ledgers.remove(key);
                }
            });
        }
        list<map<string, object>> list = new arraylist<>();
        keys.foreach(key->{
            if(list.size() <=50 &&ledgers.get(key) != null)
                list.add(ledgers.get(key));
        });
        return new gson().tojson(list);
    }

    private int getledger(int index) throws moorecoinexception {
        gson gson = new gson();
        map<string, object> postdata = new hashmap<>();
        map<string, object> para = new hashmap<>();
        postdata.put("method", "ledger");
        para.put("ledger_index", index);
        para.put("accounts", false);
        para.put("full", false);
        para.put("expand", false);
        para.put("transactions", false);
        postdata.put("params", collections.singletonlist(para));
        string data = gson.tojson(postdata);
        httpclient.response response = httpclient.post(uri, data);
//        logger.info("method=ledger, response=" + response.getresponsestring());
        jsonobject json = new jsonobject(response.getresponsestring());
        try {
            if (json.has("result") && json.getjsonobject("result").has("ledger")) {
                json = json.getjsonobject("result").getjsonobject("ledger");

                if (json.has("ledger_index")) {
                    int currentindex = json.getint("ledger_index");
                    if (!ledgers.containskey(currentindex)) {
                        map ledger = new hashmap<>();
                        ledger.put("ledger_index", json.getint("ledger_index"));
                        ledger.put("ledger_hash", json.getstring("ledger_hash"));
                        ledger.put("close_time_human", json.getstring("close_time_human"));
                        ledger.put("creator_address", b58.getinstance().encodetostring(convert.hextobytes(json.getstring("account_hash"))));
                        ledger.put("closed", json.getboolean("closed"));
                        ledger.put("total_coins", json.getstring("total_coins"));
                        if (json.has("total_coinsvbc"))
                            ledger.put("total_coinsvbc", json.getstring("total_coinsvbc"));
                        system.out.println(json.getstring("transaction_hash"));
                        ledger.put("transaction_hash", json.getstring("transaction_hash"));
                        ledgers.put(currentindex, ledger);
                    }
                    return currentindex;
                }
            }
        }catch (exception ex){
            ex.printstacktrace();
        }
        return 0;
    }
}
