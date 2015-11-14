package org.moorecoinlab.test;

import com.google.gson.gson;
import org.json.jsonobject;
import org.moorecoinlab.api.apiexception;
import org.moorecoinlab.api.accountimpl;
import org.moorecoinlab.api.transactionimpl;
import org.moorecoinlab.client.ws.moorecoinwebsocketclient;
import org.junit.test;
import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.amount;
import org.moorecoinlab.core.currency;

import java.math.bigdecimal;
import java.net.urisyntaxexception;
import java.util.hashmap;
import java.util.map;
import java.util.concurrent.timeunit;

/**
 * moorecoin network provides websocket interface to make tx. this is a test class for websocket api with moorecoin.
 * the config file is searched by order:
 *   1, {project_resources}/moorecoin.properties
 *   2, {project_resources}/moorecoin.properties
 *
 * the config key is "websocket.servers", value is ip list, split by ","
 */
public class testwebsocket {
    string addrforlisten = "r4djtkvx4gsgmk3xw8yzzvk5ewfbhj8bql";   // change me !!

    @test
    public void testsubscribe() {
        //step 1: send subscribe request to moorecoin, return immediately
        //multiple accounts subscription is allowed, merge accounts to an array, or send subscription requests several times respectively .
        try {
            string subscribe = moorecoinwebsocketclient.request("{\n" +
                    "  \"id\": 10,\n" +
                    "  \"command\": \"subscribe\",\n" +
                    "  \"accounts\": [\"" + addrforlisten + "\"]\n" +
                    "}");
            system.out.println("subscribe account:" + addrforlisten + ", result=" + subscribe);
        } catch (exception e) {
            e.printstacktrace();
        }

        //step 2: get the subscribe data.  multiple accounts info would be packaged in subscribequeue .
        //note: all subscriptions will return. need to determine the format, type, relevant account .
        int count = 0;
        while (count < 3) {
            long start = system.currenttimemillis();
            try {
                //load data from queue. 5 seconds of timeout for each loop, then next fetching loop.  poll() method is easy to debug.
                string data = moorecoinwebsocketclient.subscribequeue.poll(5, timeunit.seconds);
                //if using take() method, there is not need of timeout. take() will block and wait until something is returned.
                //string data = moorecoinwebsocketclient.subscribequeue.take();

                system.out.println("get subscribe message:" + data);
                if (system.currenttimemillis() - start < 1000 && data == null) {
                    thread.sleep(2000);
                }
                count++;
            } catch (interruptedexception e) {
                e.printstacktrace();
            }
        }
    }

    @test
    public void testaccounttx() throws urisyntaxexception, interruptedexception {
        string addr = addrforlisten; // change me !!

        string data = "{\"id\":1,\"command\":\"account_tx\",\"account\":\"" + addr + "\"," +
                "\"tx_type\":\"payment\",\"binary\":false,\"forward\":false,\"ledger_index_max\":-1,\"ledger_index_min\":-1,\"limit\":20, \"marker\":{\n" +
                "            \"ledger\": 1223, \n" +
                "            \"seq\": 0\n" +
                "        }}";
        int count = 0;
        while(count < 2) {
            try {
                string resp = moorecoinwebsocketclient.request(data);
                system.out.println(resp);
                count++;
                thread.sleep(3000);
            }catch (exception ex){
                ex.printstacktrace();
            }
        }
    }
    @test
    public void testaccountdividend(){
        string data = "{\"id\":0, \"account\":\"" + addrforlisten + "\", \"command\":\"account_dividend\"}";
        try {
            string resp = moorecoinwebsocketclient.request(data);
            system.out.println(resp);
            thread.sleep(1000);
        }catch (exception ex){
            ex.printstacktrace();
        }
    }


    ////// -----------------------------  test account section -----------------------------
    static accountimpl userimpl = new accountimpl();

    @test
    public void testgetacctinfo() {
        string json = userimpl.getaccountinfo(addrforlisten);
        system.out.println(json);
    }

    @test
    public void testaccountcurrencys() {
        string json = userimpl.accountcurrencies(addrforlisten);
        system.out.println(json);
    }

    @test
    public void testaccountlines() {
        string address = "r4djtkvx4gsgmk3xw8yzzvk5ewfbhj8bql"; // change me !!
        string peer = "rlemulvgcgbx7m3zgsmz4exqrljalbd6tt";    // change me !!
        string json = userimpl.getaccountlines(address, peer);
        system.out.println(json);
    }

    @test
    public void testaccountlinescurrency() {
        string json = userimpl.getaccountlinescurrency(addrforlisten);
        system.out.println(json);
    }

    @test
    public void testsequence() {
        int json = userimpl.getusercurrentsequence(addrforlisten);
        system.out.println("getusercurrentsequence() : " + json);
    }



    ////// -----------------------------  test transaction section -----------------------------
    static transactionimpl tximpl = new transactionimpl();

    @test
    public void testbookoffer() throws apiexception {
        jsonobject jsonobject = tximpl.bookoffers("cny", addrforlisten, "vbc", null, null, 20);
        system.out.println(jsonobject.tostring());
    }


    @test
    public void testmakeoffer() throws apiexception {
        string seed = "ssch---change-private-seed---"; // change me !!
        /*
        string address = addrforlisten;
        int sequence = 3;
        amount takergets = new amount(new bigdecimal(100));
        amount takerpays = new amount(new bigdecimal(15), currency.fromstring("cny"), accountid.fromaddress(addrforlisten));
        string json = tximpl.makeoffer(seed, takergets, takerpays, sequence);
        system.out.println(json);
        */
    }

    @test
    public void testaccountoffer() throws apiexception {
        string address = addrforlisten;
        string json = tximpl.accountoffers(address, 12, "vrp", null, "rub", addrforlisten, null);
        system.out.println(json);
    }

    @test
    public void testoffercancel() throws apiexception {
        string seed = "snopbrxtmemymhuvtgbuqafg1sutb"; // change me !!
        string json = tximpl.offercancel(seed, 2, 5589);
        system.out.println(json);
    }



}
