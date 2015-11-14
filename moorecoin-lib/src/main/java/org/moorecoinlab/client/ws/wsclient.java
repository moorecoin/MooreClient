package org.moorecoinlab.client.ws;

import io.netty.bootstrap.bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.nioeventloopgroup;
import io.netty.channel.socket.socketchannel;
import io.netty.channel.socket.nio.niosocketchannel;
import io.netty.handler.codec.http.defaulthttpheaders;
import io.netty.handler.codec.http.httpclientcodec;
import io.netty.handler.codec.http.httpobjectaggregator;
import io.netty.handler.codec.http.websocketx.websocketclienthandshakerfactory;
import io.netty.handler.codec.http.websocketx.websocketversion;
import io.netty.handler.ssl.sslcontext;
import io.netty.handler.ssl.util.insecuretrustmanagerfactory;

import java.net.uri;


/**
 * websocket client wrap
 */
public class wsclient {

    private channel channel;
    private uri uri;
    private eventloopgroup group = null;

    public wsclient(uri uri){
        this.uri = uri;
    }

    public channel getchannel() {
        return channel;
    }
    public channel connect(){
        if(group != null)
            group.shutdowngracefully();

        group = new nioeventloopgroup();
        try {
            final websocketclienthandler handler =
                    new websocketclienthandler(
                            websocketclienthandshakerfactory.newhandshaker(
                                    uri, websocketversion.v13, null, false, new defaulthttpheaders(), integer.max_value));

            final boolean ssl = "wss".equalsignorecase(uri.getscheme());
            final sslcontext sslctx;
            if (ssl) {
                sslctx = sslcontext.newclientcontext(insecuretrustmanagerfactory.instance);
            } else {
                sslctx = null;
            }

            bootstrap b = new bootstrap();
            b.group(group)
                    .channel(niosocketchannel.class)
                    .handler(new channelinitializer<socketchannel>() {
                        @override
                        protected void initchannel(socketchannel ch) {
                            channelpipeline p = ch.pipeline();
                            if (sslctx != null) {
                                p.addlast(sslctx.newhandler(ch.alloc(), uri.gethost(), uri.getport()));
                            }
                            p.addlast(
                                    new httpclientcodec(),
                                    new httpobjectaggregator(1000000),
                                    handler);
                        }
                    });
            channelfuture cf = b.connect(uri.gethost(), uri.getport());
            channel = cf.sync().channel();

            handler.handshakefuture().sync();
        }catch (exception e){
            e.printstacktrace();
        }
        return channel;
    }
}
