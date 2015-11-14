package org.moorecoinlab.client.util;

import org.moorecoinlab.core.exception.moorecoinexception;
import org.apache.commons.lang3.stringutils;
import org.apache.log4j.logger;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.net.httpurlconnection;
import java.net.url;
import java.util.zip.gzipinputstream;

public class httpclient {

    private static final logger logger = logger.getlogger(httpclient.class.getname());

    public static response post(string url, string data) throws moorecoinexception {
        httpurlconnection conn = null;
        try {
            url requesturl = new url(url);
            byte[] bytes = data.getbytes("utf-8");
            conn = (httpurlconnection) requesturl.openconnection();
            conn.setrequestproperty("user-agent", "99coin-agent");
            conn.setrequestproperty("accept-encoding", "gzip");
            conn.setconnecttimeout(6 * 1000);
            conn.setreadtimeout(6 * 1000);
            conn.setdoinput(true);
            conn.setdooutput(true);
            conn.setrequestmethod("post");
            conn.getoutputstream().write(bytes);
            string encode = conn.getcontentencoding();
            inputstream instream;
            if (stringutils.isnotblank(encode) && encode.tolowercase().contains("gzip")) {
                instream = new gzipinputstream(conn.getinputstream());
            } else {
                instream = conn.getinputstream();
            }
            byte[] inputbytes = readinputstream(instream);
            string response = new string(inputbytes, "utf-8");
            logger.debug("response from peer->" + response);
            response resp = new response();
            resp.setrequestlength(bytes.length);
            resp.setresponselength(inputbytes.length);
            resp.setresponsestring(response);
            return resp;
        }catch (exception e){
            e.printstacktrace();
            logger.warn("error to sending http request.." + e.getmessage());
            throw new moorecoinexception("error when sending request, message:" + e.getmessage());
        }finally {
            if(conn != null){
                conn.disconnect();
            }
        }
    }

    public static response get(string url) throws moorecoinexception {
        httpurlconnection conn = null;
        try {
            url requesturl = new url(url);
            conn = (httpurlconnection) requesturl.openconnection();
            conn.setrequestproperty("user-agent", "99coin-agent");
            conn.setrequestproperty("accept-encoding", "gzip");
            conn.setconnecttimeout(6 * 1000);
            conn.setreadtimeout(6 * 1000);
            conn.setdoinput(true);
            conn.setdooutput(true);
            conn.setrequestmethod("get");
            string encode = conn.getcontentencoding();
            inputstream instream;
            if (stringutils.isnotblank(encode) && encode.tolowercase().contains("gzip")) {
                instream = new gzipinputstream(conn.getinputstream());
            } else {
                instream = conn.getinputstream();
            }
            byte[] inputbytes = readinputstream(instream);
            string response = new string(inputbytes, "utf-8");
            logger.debug("response from peer->" + response);
            response resp = new response();
            resp.setresponselength(inputbytes.length);
            resp.setresponsestring(response);
            return resp;
        }catch (exception e){
            e.printstacktrace();
            logger.warn("error to sending http request.." + e.getmessage());
            throw new moorecoinexception("error when sending request, message:" + e.getmessage());
        }finally {
            if(conn != null){
                conn.disconnect();
            }
        }
    }

    private static byte[] readinputstream(inputstream instream) throws ioexception {
        bytearrayoutputstream outstream = new bytearrayoutputstream();
        byte[] buffer = new byte[1024];
        int len ;
        while ((len = instream.read(buffer)) != -1) {
            outstream.write(buffer, 0, len);
        }
        byte[] data = outstream.tobytearray();
        outstream.close();
        instream.close();
        return data;
    }

    public static class response{
        private int requestlength;
        private int responselength;
        private string responsestring;

        public int getrequestlength() {
            return requestlength;
        }

        public void setrequestlength(int requestlength) {
            this.requestlength = requestlength;
        }

        public int getresponselength() {
            return responselength;
        }

        public void setresponselength(int responselength) {
            this.responselength = responselength;
        }

        public string getresponsestring() {
            return responsestring;
        }

        public void setresponsestring(string responsestring) {
            this.responsestring = responsestring;
        }
    }
}
