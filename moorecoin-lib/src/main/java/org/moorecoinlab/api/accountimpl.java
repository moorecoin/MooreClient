package org.moorecoinlab.api;

import com.google.gson.gson;
import org.moorecoinlab.client.ws.moorecoinwebsocketclient;
import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.accountline;
import org.apache.log4j.logger;
import org.json.jsonarray;
import org.json.jsonobject;
import org.moorecoinlab.core.issuerline;

import java.util.*;


/**
 * user account implements, defined by websocket api of moorecoin.
 * @see org.moorecoinlab.test.testwebsocket for usage
 */
public class accountimpl {
    private static final logger logger = logger.getlogger(accountimpl.class);
    
    /**
     * api impl: get account basic info
     *
     * {
     * "id": 2,
     * "command": "account_info",
     * "account": "r9cza1mlk5r5am25arfxfmqgnwjzgnfk59",
     * "strict": true,
     * "ledger_index": "validated"
     * }
     * @param address
     * @return
     */
    public string getaccountinfo(string address) throws apiexception {
        map<string, object> requestdata = new hashmap<>();
        requestdata.put("id", 0);
        requestdata.put("command", "account_info");
        requestdata.put("account", address);
        requestdata.put("strict", true);
        requestdata.put("ledger_index", "validated");
        string data = new gson().tojson(requestdata);
        string accountinfo = null;
        try {
            accountinfo = moorecoinwebsocketclient.req(data);
        } catch (apiexception e) {
            if (e.code.compareto(apiexception.errorcode.address_not_found) == 0) {
                accountinfo = formatnotfounduser(address).tostring();
            } else {
                throw new apiexception(e.code, e.getmessage());
            }
        }
        return accountinfo;
    }

    /**
     * api impl: get account receive_currencies and send_currencies
     */
    public string accountcurrencies(string address) throws apiexception {
        map<string, object> data = new hashmap<>();
        data.put("id", 1);
        data.put("command", "account_currencies");
        data.put("account", address);

        string postdata = new gson().tojson(data);
        string json = moorecoinwebsocketclient.req(postdata);
        return json;
    }


    /**
     * api impl: get account accountlines info
     * {
     * "id": 1,
     * "command": "account_lines",
     * "account": "r9cza1mlk5r5am25arfxfmqgnwjzgnfk59",
     * "ledger": "current"
     * }
     *
     * @param address
     * @return
     * @throws apiexception
     */
    public string getaccountlines(string address, string peer) throws apiexception {
        map<string, object> requestdata = new hashmap<>();
        requestdata.put("id", 0);
        requestdata.put("command", "account_lines");
        requestdata.put("account", address);
        requestdata.put("ledger", "current");
        requestdata.put("peer", peer);
        string data = new gson().tojson(requestdata);
        try {
//            list<jsonobject> accountlinelist = new arraylist<>();
//            map<string, issuerline> issuerlines = new hashmap<>();


            treemap<string, issuerline> resultmap = new treemap<>();
            string accountinfo;
            try {
                accountinfo = moorecoinwebsocketclient.req(data);
                jsonobject json = new jsonobject(accountinfo);
                jsonarray lines = json.getjsonobject("result").getjsonarray("lines");
                for (int i = 0; i < lines.length(); i++) {
                    jsonobject line = lines.getjsonobject(i);
                    accountline accountline = accountline.fromjson(accountid.fromaddress(address), line);
                    string currency = line.getstring("currency");
                    double balance = line.getdouble("balance");
                    string account = line.getstring("account");
                    string issuer = address;
                    double limit = line.getdouble("limit");
                    if (balance > 0) {
                        issuer = account;
                    } else if (balance == 0 && limit > 0) {
                        issuer = account;
                    }
                    string key = currency+"#"+issuer;
                    issuerline issuerline = new issuerline();
                    if(resultmap.containskey(key)){
                        issuerline = resultmap.get(key);
                    }else{
                        issuerline.setcurrency(currency);
                        issuerline.setissuer(issuer);
                        resultmap.putifabsent(key, issuerline);
                    }
                    issuerline.setamount(issuerline.getamount() + balance);
                    issuerline.getlines().add(line);
                }
            } catch (apiexception e) {
                if (e.code.compareto(apiexception.errorcode.address_not_found) == 0) {
                    //
                } else {
                    throw new apiexception(e.code, e.getmessage());
                }
            }

            jsonobject linesmap = new jsonobject();
            linesmap.put("issuer_lines", resultmap.values());
            linesmap.put("account", address);

            return linesmap.tostring();
        } catch (exception ex) {
            ex.printstacktrace();
            throw new apiexception(apiexception.errorcode.remote_error, "can not retrive account info through method \"account_info\"");
        }
    }


    /**
     * @param address
     * @return
     */
    public int getusercurrentsequence(string address) {
        map<string, object> requestdata = new hashmap<>();
        requestdata.put("id", 0);
        requestdata.put("command", "account_info");
        requestdata.put("account", address);
        string data = new gson().tojson(requestdata);
        string accountinfo;

        try {
            accountinfo = moorecoinwebsocketclient.req(data);
            jsonobject json = new jsonobject(accountinfo);
            string status = json.getstring("status");
            if (!status.equalsignorecase("success")) {  //result not success
                return -1;
            }
            jsonobject jsonaccountdata = json.getjsonobject("result").getjsonobject("account_data");
            int sequence = jsonaccountdata.getint("sequence");
            return sequence;
        } catch (apiexception e) {
            e.printstacktrace();
        }

        return -1;
    }


    /**
     * {
     * "id": 1,
     * "command": "account_lines",
     * "account": "r9cza1mlk5r5am25arfxfmqgnwjzgnfk59",
     * "ledger": "current"
     * }
     *
     * @param address
     * @return
     * @throws apiexception
     */
    public string getaccountlinescurrency(string address) throws apiexception {
        map<string, object> requestdata = new hashmap<>();
        requestdata.put("id", 0);
        requestdata.put("command", "account_lines");
        requestdata.put("account", address);
        requestdata.put("ledger", "current");
        string data = new gson().tojson(requestdata);
        try {
            string accountinfo = moorecoinwebsocketclient.request(data);
            jsonobject json = new jsonobject(accountinfo);
            jsonarray lines = json.getjsonobject("result").getjsonarray("lines");
            list<jsonobject> accountlinelist = new arraylist<>();
//            list<jsonobject> issuerlinelist = new arraylist<>();
            map<string, issuerline> issuerlines = new hashmap<>();
            for (int i = 0; i < lines.length(); i++) {
                jsonobject line = lines.getjsonobject(i);
                accountline accountline = accountline.fromjson(accountid.fromaddress(address), line);
                if (!accountline.balance.issuer().address.equals(address)) {
                    issuerline il = issuerlines.get(accountline.currency.humancode());
                    if (il == null) {
                        il = new issuerline();
                        list<jsonobject> issuerlinelist = new arraylist<>();
                        issuerlinelist.add(line);
                        il.setamount(accountline.balance.doublevalue());
                        il.setcurrency(accountline.currency.humancode());
                        il.setlines(issuerlinelist);
                        issuerlines.put(accountline.currency.humancode(), il);
                    } else {
                        il.setamount(il.getamount() + (accountline.balance.doublevalue()));
                        il.getlines().add(line);
                    }
                } else
                    accountlinelist.add(line);
            }
            jsonobject linesmap = new jsonobject();
            list<string> curr = new arraylist<>();
            curr.add("vrp - moorecoin");
            curr.add("vbc - moorecoin");
            issuerlines.keyset().foreach(c -> curr.add(c));
            linesmap.put("currencies", new jsonarray(new gson().tojson(curr)));
//            linesmap.put("sequence", json)
            return linesmap.tostring();
        } catch (exception ex) {
            ex.printstacktrace();
            throw new apiexception(apiexception.errorcode.remote_error, "can not retrive account info through method \"account_info\"");


        }
    }


    private static jsonobject formatnotfounduser(string address) {
        jsonobject jsonobject = new jsonobject();
        jsonobject.put("id", 10);  //
        jsonobject.put("status", "success");

        jsonobject jsonobjectresult = new jsonobject();
        jsonobjectresult.put("ledger_current_index",0);
        jsonobjectresult.put("validated",false);

        jsonobject jsonobjectdata = new jsonobject();
        jsonobjectdata.put("account",address);
        jsonobjectdata.put("balance","0");
        jsonobjectdata.put("balancevbc", "0");
        jsonobjectdata.put("inactive", true);

        jsonobjectresult.put("account_data", jsonobjectdata);
        jsonobject.put("result", jsonobjectresult);
        return jsonobject;
    }




}
