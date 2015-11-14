package org.moorecoinlab.client.handler;

import com.google.gson.gson;
import org.moorecoinlab.client.clientprocessor;
import org.moorecoinlab.client.util.httpclient;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.apache.log4j.logger;
import org.json.jsonobject;

import java.util.collections;
import java.util.hashmap;
import java.util.map;

public class serverstate implements clientprocessor {

    public static final serverstate instance = new serverstate();
    private static final logger logger = logger.getlogger(serverstate.class);

    @override
    public string processresponse(map<string, string> params) throws moorecoinexception {
        logger.info("get server state");

        map<string, object> postdata = new hashmap<>();
        map<string, object> para = new hashmap<>();
        postdata.put("method", "server_state");
        postdata.put("params", collections.singletonlist(para));
        string data = new gson().tojson(postdata);
        httpclient.response response = httpclient.post(uri, data);
        jsonobject json = new jsonobject(response.getresponsestring());
        json.getjsonobject("result").getjsonobject("state").put("address", uri);
        if(!admin_uri.startswith("http://-")) {
            try {
                postdata.clear();
                postdata.put("method", "peers");
                postdata.put("params", collections.singletonlist(para));
                data = new gson().tojson(postdata);
                logger.info("get data from:" + admin_uri + ", data=" + data);
                response = httpclient.post(admin_uri, data);
                logger.info("get peers from : " + admin_uri + ", result=" + response.getresponsestring());
                jsonobject peers = new jsonobject(response.getresponsestring());
                if (peers.getjsonobject("result").has("peers")) {
                    json.getjsonobject("result").put("peers", peers.getjsonobject("result").getjsonarray("peers"));
                }
            } catch (exception e) {
            }
        }
        return json.tostring();
    }
}


