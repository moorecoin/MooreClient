package org.moorecoinlab.client;

import org.moorecoinlab.client.api.render.errorrender;
import org.moorecoinlab.client.handler.*;
import org.moorecoinlab.core.exception.moorecoinexception;
import io.netty.buffer.unpooled;
import io.netty.channel.channel;
import io.netty.channel.channelfuturelistener;
import io.netty.channel.channelhandlercontext;
import io.netty.channel.channelinboundhandleradapter;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.multipart.attribute;
import io.netty.handler.codec.http.multipart.defaulthttpdatafactory;
import io.netty.handler.codec.http.multipart.httppostrequestdecoder;
import io.netty.handler.codec.http.multipart.interfacehttpdata;
import io.netty.handler.stream.chunkedfile;
import io.netty.handler.timeout.readtimeoutexception;
import io.netty.handler.timeout.writetimeoutexception;
import io.netty.util.charsetutil;
import org.apache.commons.lang3.stringutils;
import org.apache.commons.lang3.math.numberutils;
import org.apache.log4j.logger;

import java.io.ioexception;
import java.io.randomaccessfile;
import java.io.unsupportedencodingexception;
import java.net.inetaddress;
import java.net.inetsocketaddress;
import java.net.unknownhostexception;
import java.util.hashmap;
import java.util.list;
import java.util.map;
import java.util.concurrent.concurrenthashmap;
import java.util.concurrent.concurrentmap;
import java.util.concurrent.atomic.atomicinteger;

import static io.netty.handler.codec.http.httpheaders.names.*;
import static io.netty.handler.codec.http.httpresponsestatus.continue;
import static io.netty.handler.codec.http.httpresponsestatus.ok;
import static io.netty.handler.codec.http.httpversion.http_1_1;

public class clienthandler extends channelinboundhandleradapter {

    private static final hashmap<string, clientprocessor> processors = new hashmap<>();
    private static final logger logger = logger.getlogger(clienthandler.class);
    private static final concurrentmap<string, ratelimitstatus> limitmap = new concurrenthashmap<>();

    static {
        processors.put("ledger", ledgerlist.instance);
        processors.put("ledgerdata", ledgerdata.instance);
        processors.put("serverstate", serverstate.instance);
        processors.put("accountinfo", commonhandler.instance);
        processors.put("ledgerinfo", commonhandler.instance);
        processors.put("accounttxs", commonhandler.instance);
        processors.put("accountlines", commonhandler.instance);
        processors.put("accountoffers", commonhandler.instance);
        processors.put("overview", overview.instance);
        processors.put("tx", commonhandler.instance);
    }

    public static string getclientip(channelhandlercontext ctx, httprequest request) {
        if (request == null)
            return null;
        string s = request.headers().get("x-forwarded-for");
        if (s == null || s.length() == 0 || "unknown".equalsignorecase(s))
            s = request.headers().get("proxy-client-ip");
        if (s == null || s.length() == 0 || "unknown".equalsignorecase(s))
            s = request.headers().get("wl-proxy-client-ip");
        if (s == null || s.length() == 0 || "unknown".equalsignorecase(s))
            s = request.headers().get("http_client_ip");
        if (s == null || s.length() == 0 || "unknown".equalsignorecase(s))
            s = request.headers().get("http_x_forwarded_for");
        if (s == null || s.length() == 0 || "unknown".equalsignorecase(s)) {
            inetsocketaddress socketaddress = (inetsocketaddress) ctx.channel().remoteaddress();
            inetaddress inetaddress = socketaddress.getaddress();
            s = inetaddress.gethostaddress();
        }
        if ("127.0.0.1".equals(s) || "0:0:0:0:0:0:0:1".equals(s))
            try {
                s = inetaddress.getlocalhost().gethostaddress();
            } catch (unknownhostexception unknownhostexception) {
            }
        if (s != null && !"".equals(s.trim()) && s.split(",").length > 0) {
            s = s.split(",")[0];
        }
        return s;
    }

    private string processresponse(string requesttype, map<string, string> params) throws moorecoinexception {
        if (processors.get(requesttype) == null) {
            throw new moorecoinexception("no processor found.");
        }
        return processors.get(requesttype).processresponse(params);
    }

    public ratelimitstatus updateregisterrate(string key) {
        try {
            ratelimitstatus rate = limitmap.get(key);
            if (limitmap.containskey(key)) {
                if (rate.getremaining_hits().getanddecrement() > 0) {
                    int timer = (int) (rate.getreset_time_in_seconds() - (system.currenttimemillis() / 1000));
                    if (timer <= 0) {
                        rate = new ratelimitstatus();
                        rate.sethourly_limit(5000);
                        rate.setremaining_hits(new atomicinteger(5000));
                        rate.setreset_time_in_seconds((int) ((system.currenttimemillis() + 60 * 60 * 1000) / 1000));
                        rate.setreset_time(string.valueof(system.currenttimemillis()));
                        limitmap.put(key, rate);
                    } else
                        limitmap.put(key, rate);//set remain time.
                    return rate;
                }
            } else {
                synchronized (clienthandler.class) {
                    rate = limitmap.get(key);
                    if(rate == null) {
                        rate = new ratelimitstatus();
                        rate.sethourly_limit(5000);
                        rate.setremaining_hits(new atomicinteger(5000));
                        rate.setreset_time_in_seconds((int) ((system.currenttimemillis() + 60 * 60 * 1000) / 1000));
                        rate.setreset_time(string.valueof(system.currenttimemillis()));
                        limitmap.put(key, rate);
                        return rate;
                    }else{
                        return updateregisterrate(key);
                    }
                }
            }
        } catch (exception e) {
            logger.error("update ratelimit error-->" + e, e);
            e.printstacktrace();
        }
        return null;
    }

    @override
    public void channelread(channelhandlercontext ctx, object msg) throws moorecoinexception {
        if (msg instanceof httprequest) {
            httprequest req = (httprequest) msg;
            logger.info("request from:" + req.geturi());

            boolean keepalive = httpheaders.iskeepalive(req);
            if (httpheaders.is100continueexpected(req)) {
                ctx.write(new defaultfullhttpresponse(http_1_1, continue));
            }
            map<string, string> params = new hashmap<>();
            httpmethod method = req.getmethod();
            if (method.name().equals(httpmethod.post.name())) {
                string ip = getclientip(ctx, req);
                if (ip != null) {
                    ratelimitstatus rate = updateregisterrate(ip);
                    if (rate == null) {
                        throw new moorecoinexception("rate status error");
                    }
                    if (rate != null) {
                        logger.info(req.geturi() + ": key-->" + ip + ", remains access time:" + rate.getremaining_hits());
                    }
                    if (rate != null && rate.getremaining_hits().get() <= 0) {
                        throw new moorecoinexception("too many requests.");
                    }
                }
                httppostrequestdecoder postdecoder = new httppostrequestdecoder(new defaulthttpdatafactory(false), req, charsetutil.utf_8);
                list<interfacehttpdata> datalist = postdecoder.getbodyhttpdatas();
                datalist.foreach(data -> {
                    if (data.gethttpdatatype() == interfacehttpdata.httpdatatype.attribute) {
                        attribute attribute = (attribute) data;
                        try {
                            params.put(data.getname() == null ? "json" : data.getname(), attribute.getvalue());
                        } catch (ioexception e) {
                            e.printstacktrace();
                        }
                    }
                });
            }else if(req.geturi().endswith("/")){
                sendredirect(ctx, req.geturi() + "index.html");
                return;
            }else if (req.geturi().contains("/ledger/")) {

                long start = system.currenttimemillis();
                string uri = req.geturi();
                string ledgerindex = uri.substring(uri.indexof("/ledger/") + 8, uri.length());
                randomaccessfile raf = null;
                try {
                    string classpath = this.getclass().getprotectiondomain().getcodesource().getlocation().getpath();

                    string filepath = classpath.substring(0, (classpath.contains("lib") ? classpath.lastindexof("lib") : classpath.lastindexof("target"))) + "src/webapp/ledger.html";
                    raf = new randomaccessfile(filepath, "r");
                    long filelength = raf.length();
                    byte[] bytes = new byte[(int) filelength];
                    raf.read(bytes);
                    string html = new string(bytes, "utf-8");
                    html = html.replaceall("\\$index", ledgerindex);
                    html = html.replaceall("\\$platform", org.moorecoinlab.client.util.config.getinstance().getproperty("client.name"));
                    fullhttpresponse response = new defaultfullhttpresponse(http_1_1, ok, unpooled.wrappedbuffer(html.getbytes("utf-8")));
                    response.headers().set(httpheaders.names.content_length,
                            string.valueof(filelength));
                    channel ch = ctx.channel();
                    if (!req.getmethod().equals(httpmethod.head)) {
                        ch.write(new chunkedfile(raf, 0, filelength, 8192));
                    }

                    if (!keepalive) {
                        ctx.write(response).addlistener(channelfuturelistener.close);
                    } else {
                        response.headers().set(connection, httpheaders.values.keep_alive);
                        ctx.write(response);
                    }
                } catch (exception e) {
                    e.printstacktrace();
                } finally {
                    ctx.flush();
//                    ctx.close();
                    if (raf != null) {
                        try {
                            raf.close();
                        } catch (ioexception e) {
                            e.printstacktrace();
                        }
                    }
                }
                logger.info("cost:" + (system.currenttimemillis() - start));
                return;
            }else if(req.geturi().contains("/search/")){
                string data = req.geturi().substring(req.geturi().indexof("/search/") + 8, req.geturi().length());
                randomaccessfile raf = null;
                try {
                    string classpath = this.getclass().getprotectiondomain().getcodesource().getlocation().getpath();

                    string filepath = classpath.substring(0, (classpath.contains("lib") ? classpath.lastindexof("lib") : classpath.lastindexof("target"))) + "src/webapp/index.html";
                    raf = new randomaccessfile(filepath, "r");
                    long filelength = raf.length();
                    byte[] bytes = new byte[(int) filelength];
                    raf.read(bytes);
                    string html = new string(bytes, "utf-8");
                    if(numberutils.isnumber(data))
                        html = html.replaceall("\\$sendreq", "sendreq('ledgerinfo', "+data+", 'ledger', 'ledger_detail', 'ledger info');");
                    else if(data.length()>36){
                        html = html.replaceall("\\$sendreq", "sendreq('tx', '"+data+"', 'tx', 'txinfo', 'transaction info');");
                    }else{
                        string replace = "sendreq('accountinfo', '"+data+"', 'account', 'account_info', \"account info\");\n" +
                                "                sendreq('accounttxs', '"+data+"', 'account', 'account_txs', \"account transactions\");\n" +
                                "                sendreq('accountlines', '"+data+"', 'account', 'account_lines', 'account lines');\n" +
                                "                sendreq('accountoffers', '"+data+"', 'account', 'account_offers', 'account offers');";
                        html = html.replaceall("\\$sendreq",replace);
                    }
                    html = html.replaceall("\\$platform", org.moorecoinlab.client.util.config.getinstance().getproperty("client.name"));
                    html = html.replaceall("\\./", "../");
                    fullhttpresponse response = new defaultfullhttpresponse(http_1_1, ok, unpooled.wrappedbuffer(html.getbytes("utf-8")));
                    response.headers().set(httpheaders.names.content_length,
                            string.valueof(filelength));
                    channel ch = ctx.channel();
                    if (!req.getmethod().equals(httpmethod.head)) {
                        ch.write(new chunkedfile(raf, 0, filelength, 8192));
                    }
                    if (!keepalive) {
                        ctx.write(response).addlistener(channelfuturelistener.close);
                    } else {
                        response.headers().set(connection, httpheaders.values.keep_alive);
                        ctx.write(response);
                    }
                    return;
                } catch (exception e2) {
                    e2.printstacktrace();
                } finally {
                    ctx.flush();
                    ctx.close();
                    if (raf != null) {
                        try {
                            raf.close();
                        } catch (ioexception e) {
                            e.printstacktrace();
                        }
                    }
                }
            }

            else if (req.geturi().contains(".html")) {
                string name = req.geturi().substring(req.geturi().lastindexof("/") + 1, req.geturi().lastindexof(".html"));
                //index page
                randomaccessfile raf = null;
                try {
                    string classpath = this.getclass().getprotectiondomain().getcodesource().getlocation().getpath();

                    string filepath = classpath.substring(0, (classpath.contains("lib") ? classpath.lastindexof("lib") : classpath.lastindexof("target"))) + "src/webapp/" + name + ".html";
                    raf = new randomaccessfile(filepath, "r");
                    long filelength = raf.length();
                    byte[] bytes = new byte[(int) filelength];
                    raf.read(bytes);
                    string html = new string(bytes, "utf-8");
                    html = html.replaceall("\\$platform", org.moorecoinlab.client.util.config.getinstance().getproperty("client.name"));
                    fullhttpresponse response = new defaultfullhttpresponse(http_1_1, ok, unpooled.wrappedbuffer(html.getbytes("utf-8")));
                    response.headers().set(httpheaders.names.content_length,
                            string.valueof(filelength));
                    channel ch = ctx.channel();
                    if (!req.getmethod().equals(httpmethod.head)) {
                        ch.write(new chunkedfile(raf, 0, filelength, 8192));
                    }
                    if (!keepalive) {
                        ctx.write(response).addlistener(channelfuturelistener.close);
                    } else {
                        response.headers().set(connection, httpheaders.values.keep_alive);
                        ctx.write(response);
                    }
                    return;
                } catch (exception e2) {
                    e2.printstacktrace();
                } finally {
                    ctx.flush();
                    ctx.close();
                    if (raf != null) {
                        try {
                            raf.close();
                        } catch (ioexception e) {
                            e.printstacktrace();
                        }
                    }
                }
            } else if (req.geturi().contains("static")) {
                string classpath = this.getclass().getprotectiondomain().getcodesource().getlocation().getpath();
                string filepath = classpath.substring(0, (classpath.contains("lib") ? classpath.lastindexof("lib") : classpath.lastindexof("target")))
                        + "src/webapp/" + req.geturi().substring(req.geturi().lastindexof("static"), req.geturi().length());
                randomaccessfile raf = null;
                try {
                    raf = new randomaccessfile(filepath, "r");
                    long filelength = raf.length();
                    byte[] bytes = new byte[(int) filelength];
                    raf.read(bytes);
                    fullhttpresponse response = new defaultfullhttpresponse(http_1_1, ok, unpooled.wrappedbuffer(bytes));
                    response.headers().set(httpheaders.names.content_length,
                            string.valueof(filelength));
                    channel ch = ctx.channel();
                    if (!req.getmethod().equals(httpmethod.head)) {
                        ch.write(new chunkedfile(raf, 0, filelength, 8192));
                    }
                    if (!keepalive) {
                        ctx.write(response).addlistener(channelfuturelistener.close);
                    } else {
                        response.headers().set(connection, httpheaders.values.keep_alive);
                        ctx.write(response);
                    }
                } catch (exception e) {
                    e.printstacktrace();
                } finally {
                    ctx.flush();
                    ctx.close();
                    if (raf != null)
                        try {
                            raf.close();
                        } catch (ioexception e) {
                            e.printstacktrace();
                        }
                }
                return;
            } else {
                throw new moorecoinexception(405, "method not allowed.");
            }
            string type = params.get("type");
            if (stringutils.isblank(type)) {
                throw new moorecoinexception(400, "can not find request type.");
            }
            byte[] bytes = new byte[0];
            try {
                bytes = this.processresponse(type, params).getbytes("utf-8");
            } catch (unsupportedencodingexception e) {
                e.printstacktrace();
            }
            fullhttpresponse response = new defaultfullhttpresponse(http_1_1, ok, unpooled.wrappedbuffer(bytes));
            response.headers().set(content_type, "application/json");
            response.headers().set(content_length, response.content().readablebytes());


            if (!keepalive) {
                ctx.write(response).addlistener(channelfuturelistener.close);
            } else {
                response.headers().set(connection, httpheaders.values.keep_alive);
                ctx.write(response);
            }
            ctx.flush();
        }
    }

    private static void sendredirect(channelhandlercontext ctx, string newuri) {
        fullhttpresponse response = new defaultfullhttpresponse(http_1_1, httpresponsestatus.found);
        response.headers().set(location, newuri);

        // close the connection as soon as the error message is sent.
        ctx.writeandflush(response).addlistener(channelfuturelistener.close);
    }

    @override
    public void exceptioncaught(channelhandlercontext ctx, throwable cause) {
        string errorresponse;
        if (cause instanceof moorecoinexception) {
            moorecoinexception exception = (moorecoinexception) cause;
            errorresponse = errorrender.render(exception.getcode(), exception.getmessage());
        } else if (cause instanceof readtimeoutexception || cause instanceof writetimeoutexception) {
            ctx.flush();
            ctx.close();
            return;
        } else {
            errorresponse = errorrender.render(500, "internal server error.");
        }
        byte[] bytes = new byte[0];
        try {
            bytes = errorresponse.getbytes("utf-8");
        } catch (unsupportedencodingexception e) {
            e.printstacktrace();
        }
        fullhttpresponse response = new defaultfullhttpresponse(http_1_1, ok, unpooled.wrappedbuffer(bytes));
        response.headers().set(content_type, "application/json");
        ctx.write(response);
        logger.error("catch exception-->" + cause.getmessage());
        cause.printstacktrace();
        ctx.flush();
        ctx.close();
    }

    public static void main(string[] args) {
        string uri = "http://localhost/ledger/1232323";
        system.out.println(uri.substring(uri.indexof("/ledger/") + 8, uri.length()));
        ;
    }
}
