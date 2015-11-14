package org.moorecoinlab.client.handler;

import com.google.gson.gson;
import org.moorecoinlab.client.clientprocessor;
import org.moorecoinlab.client.util.httpclient;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.apache.commons.lang3.math.numberutils;

import java.util.collections;
import java.util.hashmap;
import java.util.map;

public class commonhandler implements clientprocessor {

    public static final commonhandler instance = new commonhandler();
    @override
    public string processresponse(map<string, string> params) throws moorecoinexception {
        string type = params.get("type");
        map<string, object> postdata = new hashmap<>();
        map<string, object> para = new hashmap<>();
        if("tx".equals(type)){
            postdata.put("method", "tx");
            para.put("transaction", params.get("address"));
            para.put("binary", false);
        }else if("ledgerinfo".equals(type)){
            postdata.put("method", "ledger");
            para.put("ledger_index", numberutils.createinteger(params.get("address")));
            para.put("accounts", false);
            para.put("expand", true);
            para.put("full", false);
            para.put("transactions", true);
        }else if("accounttxs".equals(type)){
            postdata.put("method", "account_tx");
            para.put("account", params.get("address"));
            para.put("binary", false);
//            para.put("count", false);
//            para.put("descending", false);
//            para.put("forward", false);
//            para.put("ledger_index_max", -1);
            para.put("ledger_index_min", -1);
            para.put("limit", 20);
//            para.put("offset", 1);
        }else if("accountoffers".equals(type)){
            postdata.put("method", "account_offers");
            para.put("account", params.get("address"));
            para.put("ledger_index", "current");
        }else if("accountlines".equals(type)){
            postdata.put("method", "account_lines");
            para.put("account", params.get("address"));
            para.put("ledger_index", "current");
        }else if("accountinfo".equals(type)){
            postdata.put("method", "account_info");
            para.put("account", params.get("address"));
            para.put("ledger_index", "validated");
            para.put("strict", true);
        }
        postdata.put("params", collections.singletonlist(para));
        string data = new gson().tojson(postdata);
        system.out.println(data);
        string result = httpclient.post(uri, data).getresponsestring();
//        system.out.println(result);
        return result;
    }
}
