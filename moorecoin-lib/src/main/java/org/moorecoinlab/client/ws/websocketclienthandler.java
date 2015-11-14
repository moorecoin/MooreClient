/*
 * copyright 2012 the netty project
 *
 * the netty project licenses this file to you under the apache license,
 * version 2.0 (the "license"); you may not use this file except in compliance
 * with the license. you may obtain a copy of the license at:
 *
 *   http://www.apache.org/licenses/license-2.0
 *
 * unless required by applicable law or agreed to in writing, software
 * distributed under the license is distributed on an "as is" basis, without
 * warranties or conditions of any kind, either express or implied. see the
 * license for the specific language governing permissions and limitations
 * under the license.
 */
//the mit license
//
//copyright (c) 2009 carl bystr拧m
//
//permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "software"), to deal
//in the software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the software, and to permit persons to whom the software is
//furnished to do so, subject to the following conditions:
//
//the above copyright notice and this permission notice shall be included in
//all copies or substantial portions of the software.
//
//the software is provided "as is", without warranty of any kind, express or
//implied, including but not limited to the warranties of merchantability,
//fitness for a particular purpose and noninfringement. in no event shall the
//authors or copyright holders be liable for any claim, damages or other
//liability, whether in an action of contract, tort or otherwise, arising from,
//out of or in connection with the software or the use or other dealings in
//the software.

package org.moorecoinlab.client.ws;

import io.netty.channel.*;
import io.netty.handler.codec.http.fullhttpresponse;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.util.charsetutil;
import org.apache.log4j.logger;
import org.json.jsonobject;

import java.util.concurrent.timeunit;

public class websocketclienthandler extends simplechannelinboundhandler<object> {

    private static final logger logger = logger.getlogger(websocketclienthandler.class);
    private final websocketclienthandshaker handshaker;
    private channelpromise handshakefuture;

    public websocketclienthandler(websocketclienthandshaker handshaker) {
        this.handshaker = handshaker;
    }

    public static string getmessage(long requestid) {
        try {
            string message = moorecoinwebsocketclient.queues.get(requestid).poll(5, timeunit.seconds);
            moorecoinwebsocketclient.queues.remove(requestid);
            return message;
        } catch (interruptedexception e) {
            e.printstacktrace();
        }
        return null;
    }

    public channelfuture handshakefuture() {
        return handshakefuture;
    }

    @override
    public void handleradded(channelhandlercontext ctx) {
        handshakefuture = ctx.newpromise();
    }

    @override
    public void channelactive(channelhandlercontext ctx) {
        handshaker.handshake(ctx.channel());
    }

    @override
    public void channelinactive(channelhandlercontext ctx) {
        logger.info("websocket client disconnected!");
        ctx.close();
    }

    @override
    public void channelread0(channelhandlercontext ctx, object msg) throws exception {
        channel ch = ctx.channel();
        if (!handshaker.ishandshakecomplete()) {
            handshaker.finishhandshake(ch, (fullhttpresponse) msg);
            system.out.println("websocket client connected!");
            handshakefuture.setsuccess();
            return;
        }

        if (msg instanceof fullhttpresponse) {
            fullhttpresponse response = (fullhttpresponse) msg;
            throw new illegalstateexception(
                    "unexpected fullhttpresponse (getstatus=" + response.getstatus() +
                            ", content=" + response.content().tostring(charsetutil.utf_8) + ')');
        }

        websocketframe frame = (websocketframe) msg;
        if (frame instanceof textwebsocketframe) {
            textwebsocketframe textframe = (textwebsocketframe) frame;
            string result = textframe.text();
//            logger.info(result);
            jsonobject json = new jsonobject(result);
            if(json.has("id")) {
                moorecoinwebsocketclient.queues.get(json.getlong("id")).put(result);
            }else{
                moorecoinwebsocketclient.subscribequeue.offer(result);
            }
        } else if (frame instanceof pongwebsocketframe) {
            system.out.println("websocket client received pong");
        } else if (frame instanceof closewebsocketframe) {
            system.out.println("websocket client received closing");
            ch.close();
        }
    }

    @override
    public void exceptioncaught(channelhandlercontext ctx, throwable cause) {
        logger.error("handler receive exception:" + cause.getmessage());
        cause.printstacktrace();
        if (!handshakefuture.isdone()) {
            handshakefuture.setfailure(cause);
        }
        ctx.close();
    }
}
