package org.moorecoinlab.client.ws;

import org.moorecoinlab.api.apiexception;
import org.moorecoinlab.client.config;
import io.netty.channel.channel;
import io.netty.handler.codec.http.websocketx.textwebsocketframe;
import io.netty.handler.codec.http.websocketx.websocketframe;
import org.apache.commons.lang3.randomutils;
import org.apache.commons.lang3.stringutils;
import org.apache.log4j.logger;
import org.json.jsonobject;

import java.net.uri;
import java.net.urisyntaxexception;
import java.util.concurrent.blockingqueue;
import java.util.concurrent.concurrenthashmap;
import java.util.concurrent.concurrentmap;
import java.util.concurrent.linkedblockingqueue;
import java.util.concurrent.atomic.atomiclong;

/**
 * interact with moorecoin servers
 */
public class moorecoinwebsocketclient {
    private static final string[] servers;

    private static final concurrentmap<string, wsclient> clientmap = new concurrenthashmap<>();
    public static final concurrenthashmap<long, blockingqueue<string>> queues = new concurrenthashmap<>();
    public static final blockingqueue<string> subscribequeue = new linkedblockingqueue<>(integer.max_value);
    private static final atomiclong requestid = new atomiclong(0l);
    private static final logger logger = logger.getlogger(moorecoinwebsocketclient.class);

    static {
        string serverstr = config.getinstance().getproperty("websocket.servers");
        logger.info("load websocket.servers from config, serverstr=" + serverstr);
        if(stringutils.isblank(serverstr)){
            logger.error("property \"websocket.servers\" not found.");
            throw new runtimeexception("property \"websocket.servers\" not found.");
        }
        servers = serverstr.split(",");
        for (string server : servers) {
            try {
                uri uri = new uri(server);
                wsclient wsclient = new wsclient(uri);
                wsclient.connect();
                clientmap.put(server, wsclient);
            } catch (exception ex) {
                ex.printstacktrace();
            }
        }
    }

    /**
     * send json data to server
     */
    public static string request(string data) throws interruptedexception {
        long requestid = requestid.getandincrement();
        long currentdatarequestid = 0l;
        try {
            jsonobject json = new jsonobject(data);
            currentdatarequestid = json.getlong("id");
            json.put("id", requestid);
            data = json.tostring();
        } catch (exception ex) {

        }
        string server = servers[randomutils.nextint(0, servers.length)];
        queues.put(requestid, new linkedblockingqueue<>(1));
        channel channel = clientmap.get(server).getchannel();
        if(!channel.isactive() || !channel.isopen()){
            channel = clientmap.get(server).connect();
        }
        //logger.info("****active:"+channel.isactive() + "----open:"+channel.isopen());
        websocketframe frame = new textwebsocketframe(data);
        channel.writeandflush(frame);
        string result = websocketclienthandler.getmessage(requestid);
        if(result == null){
            return null;
        }
        jsonobject json = new jsonobject(result);
        json.put("id", currentdatarequestid);
        return json.tostring();
    }

    /**
     * send json data to server, if failed, throws the apiexception for details.
     */
    public static string req(string data) throws apiexception {
        long requestid = requestid.getandincrement();
        long currentdatarequestid;
        try {
            jsonobject json = new jsonobject(data);
            currentdatarequestid = json.getlong("id");
            json.put("id", requestid);
            data = json.tostring();
        } catch (exception ex) {
            throw new apiexception(apiexception.errorcode.malformed_request_data, "invalid \"id\" property, must be a number");
        }
        string server = servers[randomutils.nextint(0, servers.length)];
        queues.put(requestid, new linkedblockingqueue<>(1));
        channel channel = clientmap.get(server).getchannel();
        if(channel==null || !channel.isactive() || !channel.isopen()){
            channel = clientmap.get(server).connect();
        }
        //logger.debug("****藴active:" + channel.isactive() + "----open:" + channel.isopen());
        logger.debug("***request to ws:" + data);
        websocketframe frame = new textwebsocketframe(data);
        channel.writeandflush(frame);
        string result = websocketclienthandler.getmessage(requestid);
        //logger.debug("request from remote:" + result);
        if(result == null){
            throw new apiexception(apiexception.errorcode.remote_error, "websocket error on reponse.");
        }
        jsonobject json = new jsonobject(result);
        json.put("id", currentdatarequestid);
        if(json.has("status") && !json.getstring("status").equals("error"))
            return json.tostring();
        else{
            string error = json.getstring("error");
            if("actnotfound".equals(error))
                throw new apiexception(apiexception.errorcode.address_not_found, json.getstring("error_message"));
            else if("nocurrent".equals(error) || "nonetwork".equals(error)){
                throw new apiexception(apiexception.errorcode.remote_error, json.getstring("error_message"));
            }else{
                throw new apiexception(apiexception.errorcode.unknown_error, json.getstring("error_message"));
            }
        }
    }
}
