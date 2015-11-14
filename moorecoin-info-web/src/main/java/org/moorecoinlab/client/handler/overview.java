package org.moorecoinlab.client.handler;

import com.google.gson.gson;
import org.moorecoinlab.client.clientprocessor;
import org.moorecoinlab.client.util.httpclient;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.json.jsonobject;

import java.text.simpledateformat;
import java.util.date;
import java.util.hashmap;
import java.util.map;

public class overview implements clientprocessor{

    public static final overview instance = new overview();
    @override
    public string processresponse(map<string, string> params) throws moorecoinexception {
        string resp = httpclient.get(model_server).getresponsestring();
        jsonobject json = new jsonobject(resp);
        simpledateformat format = new simpledateformat("yyyy-mm-dd hh:mm:ss");
        map<string, object> result = new hashmap<>();
        result.put("ledger_index", json.getlong("ledger_index"));
        result.put("ledger_time", format.format(new date(json.getlong("ledger_time"))));
        try {
            result.put("totalcoins", json.getstring("totalcoins"));
            result.put("totalcoinsvbc", json.getstring("totalcoinsvbc"));
        }catch (exception ex){
            result.put("totalcoins", json.getint("totalcoins"));
            result.put("totalcoinsvbc", json.getint("totalcoinsvbc"));
        }
        result.put("account_count", json.getlong("account_count") + 1214971 + 9);
        result.put("tx_count", json.getlong("tx_count"));
        return  new gson().tojson(result);
    }
}
