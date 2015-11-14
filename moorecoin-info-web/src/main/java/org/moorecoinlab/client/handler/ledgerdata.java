package org.moorecoinlab.client.handler;

import com.google.gson.gson;
import org.moorecoinlab.client.clientprocessor;
import org.moorecoinlab.client.util.httpclient;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.apache.commons.lang3.math.numberutils;
import org.json.jsonobject;

import java.util.collections;
import java.util.hashmap;
import java.util.map;

public class ledgerdata implements clientprocessor {
    public static final ledgerdata instance = new ledgerdata();

    @override
    public string processresponse(map<string, string> params) throws moorecoinexception {
        integer index = numberutils.createinteger(params.get("index"));
        gson gson = new gson();
        map<string, object> postdata = new hashmap<>();
        map<string, object> para = new hashmap<>();
        postdata.put("method", "ledger_data");
        para.put("ledger_index", index);
        para.put("binary", false);
        para.put("limit", 256);
        postdata.put("params", collections.singletonlist(para));
        string data = gson.tojson(postdata);
        httpclient.response response = httpclient.post(uri, data);
        jsonobject json = new jsonobject(response.getresponsestring());
        postdata = new hashmap<>();
        para = new hashmap<>();
        postdata.put("method", "ledger");
        para.put("ledger_index", index);
        para.put("accounts", false);
        para.put("full", false);
        para.put("expand", true);
        para.put("transactions", true);
        para.put("dividend", true);
        postdata.put("params", collections.singletonlist(para));
        data = gson.tojson(postdata);
        response = httpclient.post(uri, data);
        jsonobject tmp = new jsonobject(response.getresponsestring());
        jsonobject ledger = tmp.getjsonobject("result").getjsonobject("ledger");

        json.getjsonobject("result").put("transactions", ledger.getjsonarray("transactions"));
        json.getjsonobject("result").put("totalcoins", ledger.getstring("total_coins"));
        if (ledger.has("totalcoinsvbc"))
            json.getjsonobject("result").put("totalcoinsvbc", ledger.getstring("total_coinsvbc"));

        return json.tostring();
    }
}
