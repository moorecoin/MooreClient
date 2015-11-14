package org.moorecoinlab.client;

import io.netty.bootstrap.serverbootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.nioeventloopgroup;
import io.netty.channel.socket.socketchannel;
import io.netty.channel.socket.nio.nioserversocketchannel;
import io.netty.handler.codec.http.httpcontentcompressor;
import io.netty.handler.codec.http.httpobjectaggregator;
import io.netty.handler.codec.http.httpservercodec;
import io.netty.handler.logging.loglevel;
import io.netty.handler.logging.logginghandler;
import io.netty.handler.timeout.readtimeouthandler;
import io.netty.handler.timeout.writetimeouthandler;

public class clientserver {

    public static final int port = 9901;
    static final boolean ssl = system.getproperty("ssl") != null;
    private static eventloopgroup bossgroup = new nioeventloopgroup(1);
    private static eventloopgroup workergroup = new nioeventloopgroup();

    public static void main(string args[]){
        try {
            serverbootstrap b = new serverbootstrap();
            b.option(channeloption.so_backlog, 1024);
            b.group(bossgroup, workergroup);
            b.channel(nioserversocketchannel.class);
            b.handler(new logginghandler(loglevel.info));
            b.childhandler(new channelinitializer<socketchannel>() {
                @override
                protected void initchannel(socketchannel sh) throws exception {
                    channelpipeline p = sh.pipeline();
                    p.addlast(new readtimeouthandler(5));
                    p.addlast(new writetimeouthandler(5));
                    p.addlast(new httpservercodec());
                    p.addlast(new httpobjectaggregator(1048576));
                    p.addlast("deflater", new httpcontentcompressor(1));
                    p.addlast(new clienthandler());
                }
            });

            channel ch = b.bind(port).sync().channel();

            system.err.println("open your web browser and navigate to " +
                    (ssl? "https" : "http") + "://127.0.0.1:" + port + "/index.html");

            ch.closefuture().sync();
        } catch (exception e){
            e.printstacktrace();
        }finally {
            bossgroup.shutdowngracefully();
            workergroup.shutdowngracefully();
        }
    }

    public static void shutdown(){
        bossgroup.shutdowngracefully();
        workergroup.shutdowngracefully();
    }
}
