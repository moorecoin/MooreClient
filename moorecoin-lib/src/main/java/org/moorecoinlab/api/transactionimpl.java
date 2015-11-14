package org.moorecoinlab.api;

import com.google.gson.gson;

import org.moorecoinlab.client.ws.moorecoinwebsocketclient;
import org.moorecoinlab.core.*;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.hash.b58;
import org.moorecoinlab.core.serialized.enums.ledgerentrytype;
import org.moorecoinlab.core.types.known.tx.transaction;
import org.moorecoinlab.core.types.known.tx.result.affectednode;
import org.moorecoinlab.core.types.known.tx.result.transactionmeta;
import org.moorecoinlab.core.types.known.tx.signed.signedtransaction;
import org.moorecoinlab.core.types.known.tx.txns.*;
import org.moorecoinlab.core.uint.uint32;
import org.moorecoinlab.crypto.ecdsa.ikeypair;
import org.moorecoinlab.crypto.ecdsa.seed;
import org.apache.commons.collections4.maputils;
import org.apache.commons.lang3.stringutils;
import org.apache.log4j.logger;
import org.json.jsonarray;
import org.json.jsonobject;

import java.math.bigdecimal;
import java.math.roundingmode;
import java.text.numberformat;
import java.util.arraylist;
import java.util.hashmap;
import java.util.list;
import java.util.map;

/**
 * implements of all kinds of transactions, defined by websocket api of moorecoin.
 * @see  "api documents"
 * @see org.moorecoinlab.test.testwebsocket for usage
 */
public class transactionimpl {
    private static final logger logger = logger.getlogger(transactionimpl.class);

    /**
     * see: https://ripple.com/build/rippled-apis/#path-find
     */
    public string findpath(string sourceaccount, string destinationaccount, amount destinationamount) throws apiexception {
        map<string, object> data = new hashmap<>();
        data.put("id", 0);
        data.put("command", "ripple_path_find");
        data.put("source_account", sourceaccount);
        data.put("destination_account", destinationaccount);

        if (destinationamount.currencystring().equals("xrp") || destinationamount.currencystring().equals("vrp")) {
            data.put("destination_amount", string.valueof(destinationamount.value().multiply(new bigdecimal("1000000")).longvalue()));
        } else {
            map<string, object> destamount = new hashmap<>();
            destamount.put("issuer", destinationaccount);
            destamount.put("value", string.valueof(destinationamount.doublevalue()));
            destamount.put("currency", destinationamount.currencystring());
            data.put("destination_amount", destamount);
        }
        map<string, object> currency = new hashmap<>();
        currency.put("currency", destinationamount.currencystring());
//        data.put("source_currencies", collections.singletonlist(currency));
        string postdata = new gson().tojson(data);
        logger.info("request:" + postdata);
        string json = moorecoinwebsocketclient.req(postdata);

        return json;
    }

    /**
     * see: https://ripple.com/build/rippled-apis/#book-offers
     */
    public jsonobject bookoffers(string currency1, string issuer1, string currency2, string issuer2, string taker, int limit) throws apiexception {
        map<string, object> data = new hashmap<>();
        data.put("id", 0);
        data.put("command", "book_offers");
        data.put("limit", limit * 10);
        if (taker == null) {
            data.put("taker", taker);
        }
        list<jsonobject> bids = new arraylist<>();
        list<jsonobject> asks = new arraylist<>();
        map<string, object> maptakergets = new hashmap<>();
        maptakergets.put("currency", currency1);
        if (issuer1 != null) {
            maptakergets.put("issuer", issuer1);
        }
        map<string, object> maptakerpays = new hashmap<>();
        maptakerpays.put("currency", currency2);
        if (issuer2 != null) {
            maptakerpays.put("issuer", issuer2);
        }
        data.put("taker_gets", maptakergets);
        data.put("taker_pays", maptakerpays);

        string postdata = new gson().tojson(data);
        string jsonstrask = moorecoinwebsocketclient.req(postdata);
        if (jsonstrask != null) {
            jsonobject json = new jsonobject(jsonstrask);  //check success
            if (json.getstring("status").equalsignorecase("success")) {
                jsonobject jsonresult = json.getjsonobject("result");
                jsonarray jsonarray = jsonresult.getjsonarray("offers");
                asks = formatofferarray(jsonarray, currency1, currency2, 0, limit);
                ;
            }
        }

        data.put("taker_gets", maptakerpays);
        data.put("taker_pays", maptakergets);

        postdata = new gson().tojson(data);
        string jsonstrbids = moorecoinwebsocketclient.req(postdata);
        if (jsonstrbids != null) {
            jsonobject json = new jsonobject(jsonstrbids);  //check success
            if (json.getstring("status").equalsignorecase("success")) {
                jsonobject jsonresult = json.getjsonobject("result");
                jsonarray jsonarray = jsonresult.getjsonarray("offers");
                bids = formatofferarray(jsonarray, currency1, currency2, 1, limit);
            }
        }

        jsonobject result = new jsonobject();
        result.put("bids", bids.sublist(0, limit < bids.size() ? limit : bids.size()));
        result.put("asks", asks.sublist(0, limit < asks.size() ? limit : asks.size()));

        return result;
    }

    /**
     * see: https://ripple.com/build/rippled-apis/#submit
     */
    public string makeoffer(string seed, amount taketgets, amount takerpays, int sequence) throws apiexception {
        ikeypair kp = seed.getkeypair(seed);
        offercreate offer = new offercreate();
        offer.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed)));
        offer.takergets(taketgets);
        offer.takerpays(takerpays);
        string fee = "1000";
        signedtransaction sign = new signedtransaction(offer);

        sign.prepare(kp, amount.fromstring(fee), new uint32(sequence), null);
        string json = maketx(sign.tx_blob);
        return json;
    }

    /**
     * retrieves a list of offers made by a given account that are outstanding as of a particular ledger version.
     * see: https://ripple.com/build/rippled-apis/#account-offers
     * @param limit   (optional, default varies) limit the number of transactions to retrieve. the server is not required to honor this value. cannot be lower than 10 or higher than 400.
     * @return
     */
    public string accountoffers(string address, int limit, string c1, string issuer1, string c2, string issuer2, string marker) throws apiexception {
        map<string, object> data = new hashmap<>();
        data.put("id", 0);
        data.put("command", "account_offers");
        data.put("account", address);
        data.put("ledger", "current");
        if (limit >= 10 && limit <= 400) {
            data.put("limit", limit);
        }

        if (marker != null) {
            data.put("marker", marker);
        }
        string postdata = new gson().tojson(data);
        string jsonresult = moorecoinwebsocketclient.req(postdata);
        jsonobject jsonobject = new jsonobject(jsonresult);
        if (jsonobject.getstring("status").equalsignorecase("success")) {
            jsonobject result = new jsonobject();
            jsonarray jsonarray = jsonobject.getjsonobject("result").getjsonarray("offers");
            if (jsonobject.getjsonobject("result").has("marker")) {
                string markerreturn = jsonobject.getjsonobject("result").getstring("marker");
                result.put("marker", markerreturn);
            }

            result.put("offers", formataccountoffersall(jsonarray));
            return result.tostring();
            //return jsonarray.tostring();
        } else {
            throw new apiexception(apiexception.errorcode.unknown_error, "unknow error");
        }
    }

    public string offercancel(string seed, int offersequence, int sequence) throws apiexception {
        ikeypair kp = seed.getkeypair(seed);
        offercancel offercancel = new offercancel();
        offercancel.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed)));
        offercancel.offersequence(new uint32(offersequence));
        signedtransaction sign = new signedtransaction(offercancel);
        string fee = "1000";
        sign.prepare(kp, amount.fromstring(fee), new uint32(sequence), null);
        string json = maketx(sign.tx_blob);
        return json;
    }

    public string makepaymenttransaction(string seed, string recipient, amount amount, int sequence, boolean isresolved, jsonarray paths, amount sendmax) throws apiexception {
        ikeypair kp = seed.getkeypair(seed);
        payment txn = new payment();
        accountid destination = accountid.fromaddress(recipient);
        txn.destination(destination);
        txn.amount(amount);
        txn.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed)));
        if (paths != null) {
            txn.sendmax(sendmax);
            txn.paths(pathset.translate.fromjsonarray(paths));
        }
        signedtransaction sign = new signedtransaction(txn);
        long fee = 1000;
        if (amount.currencystring().equals("vrp") || amount.currencystring().equals("xrp") || amount.currencystring().equals("vbc")) {
            fee = (long) (amount.doublevalue() * 1000);
        }
        fee = math.max(1000, fee);
        if (!isresolved) {
            fee = 10000 + fee;
        }
        sign.prepare(kp, amount.fromstring(string.valueof(fee)), new uint32(sequence), null);
        string json = maketx(sign.tx_blob);
        return json;
    }

    public string addreferee(string seed, string refereeaddress, int sequence) throws apiexception {
        ikeypair kp = seed.getkeypair(seed);
        addreferee txn = new addreferee();
        accountid destination = accountid.fromaddress(refereeaddress);
        txn.destination(destination);
        txn.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed)));
        signedtransaction sign = new signedtransaction(txn);
        long fee = 1000;
        sign.prepare(kp, amount.fromstring(string.valueof(fee)), new uint32(sequence), null);
        string json = maketx(sign.tx_blob);
        return json;
    }

    public string trustset(string seed, string issure, string currency, int sequence, boolean isremove) throws apiexception {
        ikeypair kp = seed.getkeypair(seed);
        trustset txn = new trustset();
        int trustamount = 1000000000;
        if (isremove) {
            trustamount = 0;
        }
        currency = currency.substring(0, 3);
        amount limitamount = new amount(new bigdecimal(trustamount), currency.fromstring(currency), accountid.fromaddress(issure));
        txn.limitamount(limitamount);
        txn.account(accountid.fromseedbytes(b58.getinstance().decodefamilyseed(seed)));
        signedtransaction sign = new signedtransaction(txn);
        long fee = 1000;
        sign.prepare(kp, amount.fromstring(string.valueof(fee)), new uint32(sequence), null);
        string json = maketx(sign.tx_blob);
        return json;
    }


    /**
     * all methods using this maketx, will call submit interface of "moorecoind", and blob data needs be signed.
     * see: https://ripple.com/build/rippled-apis/#submit
     */
    public string maketx(string tx_blob) throws apiexception {
        map<string, object> data = new hashmap<>();
        data.put("id", 0);
        data.put("command", "submit");
        data.put("tx_blob", tx_blob);
        string postdata = new gson().tojson(data);
        string json = moorecoinwebsocketclient.req(postdata);
        logger.info("make tx result: " + json);
        return json;
    }


    public map<string, object> generateeffectlistfromtxmetabytype(string address, txobj item, transactionmeta meta, string type) {
        list<effect> effects = new arraylist<>();
        list<effect> showeffects = new arraylist<>();
        for (affectednode node : meta.affectednodes()) {
            switch (type) {
                case "failed":
                case "unknown":
                case "account_set":
                    if (node.ismodifiednode()) {
                        stobject obj = (stobject) node.get(field.modifiednode);
                        stobject ff = (stobject) obj.get(field.finalfields);
                        amount balance = (amount) ff.get(field.balance);
                        effect feeeffect = new effect();
                        //if other payments, it stands for fee changes.
                        feeeffect.setamount(new amountobj(-item.getfee().getamount(), "vrp", null));
                        feeeffect.settype("fee");
                        feeeffect.setbalance(new amountobj(balance.doublevalue(), "vrp", null));
                        effects.add(feeeffect);
                    }
                case "moorecoining":
                case "offer_moorecoining":
                    if (node.ismodifiednode()) {
                        stobject obj = (stobject) node.get(field.modifiednode);
                        stobject ff = (stobject) obj.get(field.finalfields);
                        if (ff != null) {
                            amount highlimit = (amount) ff.get(field.highlimit);
                            amount lowlimit = (amount) ff.get(field.lowlimit);
                            amount balance = (amount) ff.get(field.balance);
                            stobject prefields = (stobject) obj.get(field.previousfields);
                            if (highlimit != null && lowlimit != null) {

                                if (lowlimit.issuerstring().equals(address)) {
                                    effect effect = new effect();
                                    if (prefields != null) {
                                        amount prebalance = (amount) prefields.get(field.balance);
                                        if (prebalance != null) {
                                            effect.setamount(new amountobj((prebalance.doublevalue() - balance.doublevalue()), balance.currencystring(), highlimit.issuerstring()));
                                        }
                                    }
                                    if (effect.getamount() == null) {
                                        effect.setamount(item.getamount());
                                    }
                                    effect.settype("amount");
                                    effect.setbalance(new amountobj(-balance.doublevalue(), balance.currencystring(), balance.issuerstring()));
                                    effects.add(effect);
                                }else{
                                    effect effect = new effect();
                                    if (prefields != null) {
                                        amount prebalance = (amount) prefields.get(field.balance);
                                        if (prebalance != null) {
                                            effect.setamount(new amountobj(-(prebalance.doublevalue() - balance.doublevalue()), balance.currencystring(), lowlimit.issuerstring()));
                                        }
                                    }
                                    if (effect.getamount() == null) {
                                        effect.setamount(item.getamount());
                                    }
                                    effect.settype("amount");
                                    effect.setbalance(new amountobj(balance.doublevalue(), balance.currencystring(), balance.issuerstring()));
                                    effects.add(effect);
                                }
                            }
                        }
                    }
                    continue;
                case "sent":
                case "received":
                    if (node.ismodifiednode() && (node.ledgerentrytype() == ledgerentrytype.accountroot || node.ledgerentrytype() == ledgerentrytype.ripplestate)) {
                        stobject obj = (stobject) node.get(field.modifiednode);
                        stobject ff = (stobject) obj.get(field.finalfields);
                        stobject prevfields = (stobject) obj.get(field.previousfields);
                        if (ff != null) {
                            amount highlimit = (amount) ff.get(field.highlimit);
                            amount lowlimit = (amount) ff.get(field.lowlimit);
                            amount balance = (amount) ff.get(field.balance);
                            accountid account = (accountid) ff.get(field.account);
                            amount balancevbc = (amount) ff.get(field.balancevbc);
                            //vrp&&vbc payment tx
                            if (account != null) {
                                //when vrp&&vbc payments, all balance change is in single finalfields object in one modifiednode
                                if (account.address.equals(address)) {
                                    //vrp||vbc tx
                                    if (item.getamount().getcurrency().equals("vrp") || item.getamount().getcurrency().equals("vbc")) {
                                        boolean havebalanceeffect = true;
                                        if (prevfields != null) {
                                            amount prebalance = (amount) prevfields.get(field.balance);
                                            if (prebalance != null) {
                                                if (prebalance.subtract(balance).doublevalue() * 1000000 == item.getfee().getamount() * 1000000) {
                                                    havebalanceeffect = false;
                                                }
                                            }
                                        }
                                        //if tx payment currency is payment, and is tx type is sent, then add a fee effect
                                        if ("sent".equals(item.gettype())) {

                                            //vrp&vbc tx, balance is vrp balance..
                                            effect feeeffect = new effect();

                                            //if vrp payment, then compute balance from meta balance amount.
                                            if (item.getamount().getcurrency().equals("vrp")) {
                                                if (prevfields != null) {
                                                    amount prebalance = (amount) prevfields.get(field.balance);
                                                    if (prebalance != null && (prebalance.subtract(balance).doublevalue() * 1000000 == item.getfee().getamount() * 1000000)) {
                                                        feeeffect.setbalance(new amountobj(balance.doublevalue(), "vrp", null));
                                                    } else {
                                                        feeeffect.setbalance(new amountobj(balance.doublevalue() + item.getamount().getamount(), "vrp", null));
                                                    }
                                                } else {
                                                    feeeffect.setbalance(new amountobj(balance.doublevalue() + item.getamount().getamount(), "vrp", null));
                                                }
                                            } else {
                                                feeeffect.setbalance(new amountobj(balance.doublevalue(), "vrp", null));
                                            }
                                            feeeffect.settype("fee");
                                            feeeffect.setamount(new amountobj(-item.getfee().getamount(), "vrp", null));
                                            effects.add(feeeffect);
                                        }
                                        if (havebalanceeffect) {
                                            effect effect = new effect();
                                            if (item.getamount().getcurrency().equals("vbc")) {
                                                balance = (amount) ff.get(field.balancevbc);
                                            }
                                            if (item.getamount().getcurrency().equals("vrp")) {
                                                effect.setbalance(new amountobj(balance.doublevalue(), "vrp", null));
                                            } else {
                                                effect.setbalance(new amountobj(balancevbc.doublevalue(), "vbc", null));
                                            }
                                            effect.settype("amount");
                                            amountobj amount = item.getamount();
                                            effect.setamount(new amountobj(item.gettype().equals("sent") ? -amount.getamount() : amount.getamount()
                                                    , amount.getcurrency(), amount.getissuer()));
                                            effects.add(effect);
                                        }


                                    } else {
                                        effect feeeffect = new effect();
                                        //if other payments, it stands for fee changes.
                                        feeeffect.setbalance(new amountobj(balance.doublevalue(), "vrp", null));
                                        feeeffect.settype("fee");
                                        feeeffect.setamount(new amountobj(-item.getfee().getamount(), "vrp", null));
                                        effects.add(feeeffect);
                                    }
                                }
                            } else {
                                //other currency payment, contains highlimit and lowlimit
                                //it stands for tx amount's currency's balance changes
                                if (highlimit != null && lowlimit != null) {
                                    //balance change abount current account
                                    //highlimit stands for recipient
                                    string issuer = lowlimit.issuerstring();
                                    if(highlimit.value().intvalue() == 0){
                                        issuer = highlimit.issuerstring();
                                    }
                                    if (highlimit.issuerstring().equals(address)) {
                                        effect effect = new effect();
                                        amount prebalance = (amount) prevfields.get(field.balance);
                                        if(prebalance != null) {
                                            effect.setamount(new amountobj(prebalance.subtract(balance).doublevalue(), prebalance.currencystring(), issuer));
                                            effect.setbalance(new amountobj(math.abs(balance.doublevalue()), balance.currencystring(), issuer));
                                            effect.settype("amount");
                                            effects.add(effect);
                                        }
                                    } else if (lowlimit.issuerstring().equals(address)) {
                                        effect effect = new effect();
                                        //paths tx
                                        amount prebalance = (amount) prevfields.get(field.balance);
                                        if (prebalance != null) {
                                            effect.setamount(new amountobj(-prebalance.subtract(balance).doublevalue(), prebalance.currencystring(), issuer));
                                            effect.setbalance(new amountobj(math.abs(balance.doublevalue()), balance.currencystring(), issuer));
                                            effect.settype("amount");
                                            effects.add(effect);
                                        }
                                    }
                                }

                            }
                        }
                    } else if (node.iscreatednode()) {
                        stobject obj = (stobject) node.get(field.creatednode);
                        stobject nf = (stobject) obj.get(field.newfields);
                        accountid account = (accountid) nf.get(field.account);
                        if (account != null && address.equals(account.address)) {
                            effect effect = new effect();
                            amount amount = (amount) nf.get(field.balancevbc);
                            amount balance = (amount) nf.get(field.balance);
                            if (amount != null) {
                                effect.setbalance(new amountobj(amount.doublevalue(), "vbc", null));
                            }
                            if (balance != null)
                                effect.setbalance(new amountobj(balance.doublevalue(), "vrp", null));
                            effect.settype("fee");
                            effect.setamount(item.getamount());
                            effects.add(effect);
                        }
                    } else if (node.ledgerentrytype() == ledgerentrytype.offer) {
                        stobject obj = (stobject) node.get(node.getfield());
                        stobject ff = (stobject) obj.get(field.finalfields);
                        stobject prevfields = (stobject) obj.get(field.previousfields);
                        amount takergets = (amount) ff.get(field.takergets);
                        amount takerpays = (amount) ff.get(field.takerpays);
                        if (prevfields == null) {
                            continue;
                        }
                        amount pretakergets = (amount) prevfields.get(field.takergets);
                        amount pretakerpays = (amount) prevfields.get(field.takerpays);
                        //show effects
                        if (address.equals(item.getsender())) {

                            effect showeffect = new effect();
                            showeffect.settakergets(new amountobj(pretakergets.subtract(takergets).doublevalue(), pretakergets.currencystring(), pretakergets.issuerstring()));
                            showeffect.settakerpays(new amountobj(pretakerpays.subtract(takerpays).doublevalue(), pretakerpays.currencystring(), pretakerpays.issuerstring()));
                            showeffect.settype("bought");
                            showeffects.add(showeffect);
                        } else {
                            accountid account = (accountid) ff.get(field.account);
                            if (address.equals(account)) {
                                effect showeffect = new effect();
                                showeffect.settakergets(new amountobj(pretakergets.subtract(takergets).doublevalue(), pretakergets.currencystring(), pretakergets.issuerstring()));
                                showeffect.settakerpays(new amountobj(pretakerpays.subtract(takerpays).doublevalue(), pretakerpays.currencystring(), pretakerpays.issuerstring()));
                                showeffect.settype("bought");
                                showeffects.add(showeffect);
                            }
                        }
                    }
                    continue;
                case "dividend":
                    if (node.ismodifiednode()) {
                        stobject obj = (stobject) node.get(field.modifiednode);
                        stobject ff = (stobject) obj.get(field.finalfields);
                        if (ff != null) {
                            amount balance = (amount) ff.get(field.balance);
                            amount balancevbc = (amount) ff.get(field.balancevbc);
                            effect effect = new effect();
                            effect.setbalance(new amountobj(balance.doublevalue(), "vrp", null));
                            effect.settype("amount");
                            effect.setamount(item.getamount());
                            effects.add(effect);
                            effect effectvbc = new effect();
                            effectvbc.setbalance(new amountobj(balancevbc.doublevalue(), "vbc", null));
                            effectvbc.settype("amount");
                            effectvbc.setamount(item.getamountvbc());
                            effects.add(effectvbc);
                        }
                    }
                    continue;
                case "addreferee":
                case "connecting":
                    if (node.ismodifiednode()) {
                        stobject obj = (stobject) node.get(field.modifiednode);
                        stobject ff = (stobject) obj.get(field.finalfields);
                        if (ff != null) {
                            accountid account = (accountid) ff.get(field.account);
                            if (account != null && account.address.equals(address)) {
                                amount balance = (amount) ff.get(field.balance);
                                effect effect = new effect();
                                effect.setbalance(new amountobj(balance.doublevalue(), "vrp", null));
                                effect.settype("fee");
                                effect.setamount(new amountobj(-item.getfee().getamount(), "vrp", null));
                                effects.add(effect);
                            }
                        }
                    }
                    continue;
                case "referee":
                case "connected":
                    continue;
                case "offer_cancelled":
                    if (node.ledgerentrytype() == ledgerentrytype.offer) {
                        if (node.isdeletednode()) {
                            stobject deletenode = (stobject) node.get(field.deletednode);
                            stobject ff = (stobject) deletenode.get(field.finalfields);
                            amount takergets;
                            amount takerpays;
                            if (ff != null) {
                                accountid account = (accountid) ff.get(field.account);
                                takergets = (amount) ff.get(field.takergets);
                                takerpays = (amount) ff.get(field.takerpays);
                                if (account != null && account.address.equals(address)) {
                                    item.settakerpays(new amountobj(takerpays.doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                    item.settakergets(new amountobj(takergets.doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                    item.setofferstatus("offer_cancelled");
                                    item.setsender(address);
                                }
                            }
                        }
                    } else if (node.ledgerentrytype() == ledgerentrytype.accountroot && node.ismodifiednode()) {
                        stobject deletenode = (stobject) node.get(field.modifiednode);
                        stobject ff = (stobject) deletenode.get(field.finalfields);
                        if (ff != null) {
                            accountid account = (accountid) ff.get(field.account);
                            if (account != null && account.address.equals(address)) {
                                //trust line balance change
                                amount balance = (amount) ff.get(field.balance);
                                if (account != null && account.address.equals(address)) {
                                    effect effect = new effect();
                                    effect.settype("amount");
                                    effect.setamount(new amountobj(-item.getfee().getamount(), item.getfee().getcurrency(), item.getfee().getissuer()));
                                    effect.setbalance(new amountobj(balance.doublevalue(), balance.currencystring(), balance.issuerstring()));
                                    effects.add(effect);
                                }
                            }
                        }
                    }
                    continue;
                case "offercreate":
                    if (node.ledgerentrytype() == ledgerentrytype.offer) {
                        amount takergets;
                        amount takerpays;
                        //account in delete node and fieldsprev amount is not zero, offer ok.
                        if (node.isdeletednode()) {
                            stobject deletenode = (stobject) node.get(field.deletednode);
                            stobject fieldsprev = (stobject) deletenode.get(field.previousfields);
                            stobject ff = (stobject) deletenode.get(field.finalfields);
                            if (fieldsprev != null
                                    && (takergets = (amount) fieldsprev.get(field.takergets)) != null
                                    && !takergets.iszero()) {
                                if (ff != null) {
                                    accountid account = (accountid) ff.get(field.account);
                                    if (account != null && account.address.equals(address)) {
                                        takerpays = (amount) fieldsprev.get(field.takerpays);
                                        if (item.gettakergets() == null) {
                                            item.settakerpays(new amountobj(takerpays.doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                            item.settakergets(new amountobj(takergets.doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                            item.setofferstatus("offer_funded");
                                        }
                                    } else if (address.equals(item.getsender())) {
                                        //show effects on offer met
                                        //sender create an offer, some offers has been filled
                                        takergets = (amount) ff.get(field.takergets);
                                        takerpays = (amount) ff.get(field.takerpays);
                                        amount pretakergets = (amount) fieldsprev.get(field.takergets);
                                        amount pretakerpays = (amount) fieldsprev.get(field.takerpays);
                                        effect effect = new effect();
                                        effect.settype("offer_filled");
                                        if(address.equals(account.address)) {
                                            effect.settakergets(new amountobj(pretakergets.subtract(takergets).doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                            effect.settakerpays(new amountobj(pretakerpays.subtract(takerpays).doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                        }else{
                                            effect.settakergets(new amountobj(pretakerpays.subtract(takerpays).doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                            effect.settakerpays(new amountobj(pretakergets.subtract(takergets).doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                        }
                                        showeffects.add(effect);
                                    }
                                }
                            } else if (ff != null) {
                                accountid account = (accountid) ff.get(field.account);
                                takergets = (amount) ff.get(field.takergets);
                                takerpays = (amount) ff.get(field.takerpays);
                                if (account != null && account.address.equals(address)) {
                                    effect effect = new effect();
                                    effect.settype("offer_cancelled");
                                    effect.settakergets(new amountobj(takergets.doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                    effect.settakerpays(new amountobj(takerpays.doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                    showeffects.add(effect);
                                }
                            }
                        } else if (node.ismodifiednode()) {
                            stobject modifiednode = (stobject) node.get(field.modifiednode);
                            stobject fieldsprev = (stobject) modifiednode.get(field.previousfields);
                            stobject ff = (stobject) modifiednode.get(field.finalfields);
                            if (ff != null) {
                                accountid account = (accountid) ff.get(field.account);
                                if (account != null && account.address.equals(address)) {
                                    //offer not filled.
                                    item.setofferstatus("offer_partially_funded");
                                    if (fieldsprev != null) {
                                        takergets = (amount) fieldsprev.get(field.takergets);
                                        takerpays = (amount) fieldsprev.get(field.takerpays);
                                        amount ffgets = (amount) ff.get(field.takergets);
                                        amount ffpays = (amount) ff.get(field.takerpays);
                                        if (item.gettakergets() == null) {
                                            item.settakerpays(new amountobj(takerpays.doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                            item.settakergets(new amountobj(takergets.doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                        }
                                        item.setpartiallypays(new amountobj(takerpays.value().subtract(ffpays.value()).doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                        item.setpartiallygets(new amountobj(takergets.value().subtract(ffgets.value()).doublevalue(), takergets.currencystring(), takergets.issuerstring()));

                                        effect effect = new effect();
                                        effect.settype("offer_filled");
                                        effect.settakergets(new amountobj(takergets.subtract(ffgets).doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                        effect.settakerpays(new amountobj(takerpays.subtract(ffpays).doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                        showeffects.add(effect);
                                    }
                                    takergets = (amount) ff.get(field.takergets);
                                    takerpays = (amount) ff.get(field.takerpays);
                                    effect effect = new effect();
                                    effect.settype("offer_remained");
                                    effect.settakergets(new amountobj(takergets.doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                    effect.settakerpays(new amountobj(takerpays.doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                    showeffects.add(effect);

                                }
                            }

                        } else if (node.iscreatednode()) {
                            stobject creatednode = (stobject) node.get(field.creatednode);
                            stobject nf = (stobject) creatednode.get(field.newfields);

                            if (nf != null) {
                                accountid account = (accountid) nf.get(field.account);
                                if (account != null && account.address.equals(address)) {
                                    takergets = (amount) nf.get(field.takergets);
                                    takerpays = (amount) nf.get(field.takerpays);
                                    //offer not filled.
                                    if (item.gettakergets() == null) {
                                        item.setofferstatus("offer_create");
                                        item.settakerpays(new amountobj(takerpays.doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                        item.settakergets(new amountobj(takergets.doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                    } else {
                                        if (takergets.doublevalue() < item.gettakergets().getamount()) {
                                            item.setofferstatus("offer_partially_funded");
                                            effect effect = new effect();
                                            effect.settype("offer_remained");
                                            effect.settakergets(new amountobj(takergets.doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                            effect.settakerpays(new amountobj(takerpays.doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                            showeffects.add(effect);
                                            item.setpartiallypays(new amountobj(new bigdecimal(string.valueof(item.gettakergets().getamount())).subtract(takerpays.value()).doublevalue(), takerpays.currencystring(), takerpays.issuerstring()));
                                            item.setpartiallygets(new amountobj(new bigdecimal(string.valueof(item.gettakerpays().getamount())).subtract(takerpays.value()).doublevalue(), takergets.currencystring(), takergets.issuerstring()));
                                        } else {
                                            item.setofferstatus("offer_create");
                                        }
                                    }
                                }
                            }
                        }
                    } else if (node.ledgerentrytype() == ledgerentrytype.ripplestate) {
                        if (node.iscreatednode()) {
                            //offer filled cause an account has some gateway's balance, but trust limit is zero.
                            stobject creatednode = (stobject) node.get(field.creatednode);
                            stobject nf = (stobject) creatednode.get(field.newfields);
                            if (nf != null) {
                                amount highlimit = (amount) nf.get(field.highlimit);
                                amount lowlimit = (amount) nf.get(field.lowlimit);
                                amount balance = (amount) nf.get(field.balance);
                                if(lowlimit != null && highlimit!=null) {
                                    string issuer = lowlimit.issuerstring();
                                    if (highlimit.value().intvalue() == 0) {
                                        issuer = highlimit.issuerstring();
                                    }
                                    if (highlimit.issuerstring().equals(address)) {
                                        effect effect = new effect();
                                        effect.settype("amount");
                                        effect.setamount(new amountobj(-balance.doublevalue(), balance.currencystring(), issuer));
                                        effect.setbalance(new amountobj(-balance.doublevalue(), balance.currencystring(), issuer));
                                        effects.add(effect);
                                    } else if (lowlimit.issuerstring().equals(address)) {
                                        effect effect = new effect();
                                        effect.settype("amount");
                                        effect.setamount(new amountobj(balance.doublevalue(), balance.currencystring(), issuer));
                                        effect.setbalance(new amountobj(balance.doublevalue(), balance.currencystring(), issuer));
                                        effects.add(effect);
                                    }
                                }
                            }

                        } else if (node.ismodifiednode()) {
                            stobject modifynode = (stobject) node.get(field.modifiednode);
                            stobject ff = (stobject) modifynode.get(field.finalfields);
                            stobject prevfields = (stobject) modifynode.get(field.previousfields);
                            if (ff != null && prevfields != null) {
                                amount highlimit = (amount) ff.get(field.highlimit);
                                amount lowlimit = (amount) ff.get(field.lowlimit);
                                amount prebalance = (amount) prevfields.get(field.balance);
                                if (highlimit != null && lowlimit != null) {
                                    string issuer = lowlimit.issuerstring();
                                    if(highlimit.value().intvalue() == 0){
                                        issuer = highlimit.issuerstring();
                                    }
                                    //trust line balance change
                                    amount balance = (amount) ff.get(field.balance);
                                    if (highlimit.issuerstring().equals(address)) {
                                        effect effect = new effect();
                                        effect.settype("amount");
                                        if (prebalance != null) {
                                            effect.setamount(new amountobj(-balance.subtract(prebalance).doublevalue(), balance.currencystring(), issuer));
                                        }
                                        effect.setbalance(new amountobj(-balance.doublevalue(), balance.currencystring(), issuer));
                                        effects.add(effect);
                                    }else if(lowlimit.issuerstring().equals(address)){
                                        effect effect = new effect();
                                        effect.settype("amount");
                                        if (prebalance != null) {
                                            effect.setamount(new amountobj(balance.subtract(prebalance).doublevalue(), balance.currencystring(), issuer));
                                        }
                                        effect.setbalance(new amountobj(balance.doublevalue(), balance.currencystring(), issuer));
                                        effects.add(effect);
                                    }
                                }
                            }
                        }
                    } else if (node.ledgerentrytype() == ledgerentrytype.accountroot && node.ismodifiednode()) {
                        stobject modifiednode = (stobject) node.get(field.modifiednode);
                        stobject ff = (stobject) modifiednode.get(field.finalfields);
                        stobject prevfields = (stobject) modifiednode.get(field.previousfields);
                        if (ff != null) {
                            accountid account = (accountid) ff.get(field.account);
//                            boolean vbcoffer = false;
                            if (account != null && account.address.equals(address)) {

                                //trust line balance change
                                amount balance = (amount) ff.get(field.balance);
                                effect effect = new effect();
                                effect.settype("amount");
                                if (prevfields != null) {
                                    if (item.getsender().equals(address)) {
                                        if (balance.currencystring().equals("xrp")) {
                                            amount prebalance = (amount) prevfields.get(field.balance);
                                            //not only fee change.
                                            if (((long) prebalance.doublevalue() * 1000000l - (long) item.getfee().getamount().doublevalue() * 1000000l) != (long) balance.doublevalue() * 1000000) {
                                                effect = new effect();
                                                effect.setamount(new amountobj(-item.getfee().getamount(), "vrp", null));
                                                effect.setbalance(new amountobj(prebalance.doublevalue() - item.getfee().getamount(), "vrp", null));
                                                effect.settype("fee");
                                                effects.add(effect);
                                            } else {
                                                //only fee
                                                effect = new effect();
                                                effect.setamount(new amountobj(-item.getfee().getamount(), "vrp", null));
                                                effect.setbalance(new amountobj(balance.doublevalue(), "vrp", null));
                                                effect.settype("fee");
                                                effects.add(effect);
                                            }
                                        }
                                    }
                                    effect = new effect();
                                    if (prevfields.get(field.balancevbc) != null) {
                                        //vbc offer
//                                        vbcoffer = true;
                                        amount balancevbc = (amount) ff.get(field.balancevbc);
                                        amount prebalancevbc = (amount) prevfields.get(field.balancevbc);
                                        effect.setamount(new amountobj(balancevbc.subtract(prebalancevbc).doublevalue(), "vbc", null));
                                        effect.setbalance(new amountobj(balancevbc.doublevalue(), "vbc", null));
                                        effects.add(effect);
                                    } else if (prevfields.get(field.balance) != null) {
                                        amount prebalance = (amount) prevfields.get(field.balance);
                                        effect.setbalance(new amountobj(balance.doublevalue(), balance.currencystring(), balance.issuerstring()));
                                        if (item.getsender().equals(address) &&
                                                balance.currencystring().equals("xrp")) {
                                            if (math.abs(prebalance.subtract(balance).doublevalue()) > item.getfee().getamount()) {
                                                effect.setamount(new amountobj(balance.subtract(prebalance).doublevalue() + item.getfee().getamount(), balance.currencystring(), balance.issuerstring()));
                                                effects.add(effect);
                                            }
                                        } else {
                                            effect.setamount(new amountobj(balance.subtract(prebalance).doublevalue(), balance.currencystring(), balance.issuerstring()));
                                            effects.add(effect);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    continue;
            }
        }
//        if (type.equals("offercreate")) {
//            for (effect effect : effects) {
//                if (effect.getamount() == null) {
//                    if ("offer_create".equals(item.getofferstatus())) {
//                        //set fee
//                        effect.setamount(new amountobj(-item.getfee().getamount(), item.getfee().getcurrency(), item.getfee().getissuer()));
//                        effect.settype("fee");
//                    } else if (item.gettakergets() != null && effect.getbalance().getcurrency().equals(item.gettakergets().getcurrency())) {
//                        if ("offer_partially_funded".equals(item.getofferstatus()) && effect.getamount() == null) {
//                            effect.setamount(new amountobj(-item.getpartiallygets().getamount(), item.getpartiallygets().getcurrency(), item.getpartiallygets().getissuer()));
//                        } else {
//                            effect.setamount(new amountobj(-item.gettakergets().getamount(), item.gettakergets().getcurrency(), item.gettakergets().getissuer()));
//                        }
//                    } else if (item.gettakerpays() != null && effect.getbalance().getcurrency().equals(item.gettakerpays().getcurrency())) {
//                        if ("offer_partially_funded".equals(item.getofferstatus())) {
//                            effect.setamount(item.getpartiallypays());
//                        } else {
//                            effect.setamount(item.gettakerpays());
//                        }
//                    }
//                }
//            }
//        }
        map<string, object> result = new hashmap<>();
        result.put("effects", effects);
        result.put("show_effects", showeffects);
        result.put("item", item);
        return result;
    }


    /**
     * @param address
     * @return
     */
    public string getaccounttx(string address, map<string, object> marker) throws apiexception {
        map<string, object> data = new hashmap<>();
        data.put("id", 0);
        data.put("command", "account_tx");
        data.put("account", address);
        data.put("limit", 20);
        data.put("binary", false);
        data.put("ledger_index_min", -1);
        if (maputils.isnotempty(marker)) {
            data.put("marker", marker);
        }
        string postdata = new gson().tojson(data);
        string json = moorecoinwebsocketclient.req(postdata);
        system.out.println("tx:" + json);
        jsonobject jsonobject = new jsonobject(json);
        if (jsonobject.getjsonobject("result").has("marker")) {
            marker = new hashmap<>();
            marker.put("ledger", jsonobject.getjsonobject("result").getjsonobject("marker").getint("ledger"));
            marker.put("seq", jsonobject.getjsonobject("result").getjsonobject("marker").getint("seq"));
        }
        jsonarray txs = jsonobject.getjsonobject("result").getjsonarray("transactions");

        list<txobj> resultlist = new arraylist<>();
        for (int i = 0; i < txs.length(); i++) {
            jsonobject txobj = txs.getjsonobject(i).getjsonobject("tx");
            jsonobject metaobj = txs.getjsonobject(i).getjsonobject("meta");
            transaction tx = (transaction) transaction.fromjsonobject(txobj);
            transactionmeta meta = (transactionmeta) transactionmeta.fromjsonobject(metaobj);
            txobj item = new txobj();
//            rippledate date = rippledate.fromsecondssincerippleepoch(txobj.getint("date"));
//            simpledateformat format = new simpledateformat("yyyy-mm-dd hh:mm:ss");
            item.setdate(string.valueof(txobj.getint("date")));
            item.setsender(tx.account().address);
            if (!tx.account().address.equals(address))
                item.setcontact(tx.account().address);
            //if is tx maker, then set fee obj;
            amountobj fee = new amountobj(tx.fee().doublevalue(), "vrp", null);
            item.setfee(fee);
            item.sethash(tx.get(field.hash).tohex());
            //if tx result is not success, then set type to failed;
            if (meta.engineresult().asinteger() != 0) {
                item.settype("failed");
            }else{
                if (tx instanceof payment) {
                    payment payment = (payment) tx;
                    item.setrecipient(payment.destination().address);
                    if (!((payment) tx).destination().address.equals(address))
                        item.setcontact(payment.destination().address);
                    double paymentamount = payment.amount().doublevalue();
                    amountobj amount = new amountobj(paymentamount, payment.amount().currencystring().replace("xrp", "vrp"), payment.amount().issuerstring());
                    item.setamount(amount);

                    if (!address.equals(payment.destination().address) && !address.equals(tx.account().address)) {
                        if (payment.paths() != null) {
                            for (pathset.path path : payment.paths()) {
                                for (pathset.hop hop : path) {
                                    if (hop.account != null && address.equals(hop.account.address)) {
                                        item.settype("moorecoining");
                                        break;
                                    }
                                }
                            }
                            if (item.gettype() == null) {
                                item.settype("offercreate");
                            }
                        } else
                            item.settype("moorecoining");
                    } else
                        item.settype(((payment) tx).destination().address.equals(address) ? "received" : "sent");

                }
                if (tx instanceof dividend) {
                    if (!((dividend) tx).destination().address.equals(address)) {
                        continue;
                    }
                    dividend dividend = (dividend) tx;
                    item.setrecipient(address);
                    item.settype("dividend");
                    item.setamount(new amountobj(dividend.dividendcoins().doublevalue() / 1000000, "vrp", null));
                    item.setamountvbc(new amountobj(dividend.dividendcoinsvbc().doublevalue() / 1000000, "vbc", null));
                }
                if (tx instanceof addreferee) {
                    addreferee addreferee = (addreferee) tx;
                    item.setrecipient(addreferee.destination().address);
                    if (!addreferee.destination().address.equals(address))
                        item.setcontact(addreferee.destination().address);
                    item.settype(addreferee.destination().address.equals(address) ? "referee" : "addreferee");
                }
                if (tx instanceof trustset) {
                    trustset trustset = (trustset) tx;
                    amount limit = trustset.limitamount();
                    amountobj limitamount = new amountobj(limit.doublevalue(), limit.currencystring(), limit.issuerstring());
                    item.setlimitamount(limitamount);
                    item.setrecipient(limit.issuer().address);
                    if (!limit.issuer().address.equals(address))
                        item.setcontact(limit.issuer().address);
                    item.settype(limit.issuer().address.equals(address) ? "connected" : "connecting");
                }
                if (tx instanceof offercreate) {
                    offercreate offercreate = (offercreate) tx;
                    if (item.getsender().equals(address)) {
                        item.setsender(address);
                    }
                    if (address.equals(offercreate.takergets().issuerstring()) || address.equals(offercreate.takerpays().issuerstring())) {
                        item.settype("offer_moorecoining");
                    } else
                        item.settype("offercreate");
                    if (item.getsender().equals(address) || item.gettype().equals("offer_moorecoining")) {
                        amountobj takergets = new amountobj(offercreate.takergets().doublevalue(), offercreate.takergets().currencystring(), offercreate.takergets().issuerstring());
                        amountobj takerpays = new amountobj(offercreate.takerpays().doublevalue(), offercreate.takerpays().currencystring(), offercreate.takerpays().issuerstring());
                        item.settakergets(takergets);
                        item.settakerpays(takerpays);
                    }

                }
                if (tx instanceof offercancel) {
                    item.settype("offer_cancelled");
                }
                if (tx instanceof accountset){
                    item.settype("account_set");
                }
                if (stringutils.isblank(item.gettype())) {
                    item.settype("unknown");
                }
            }
            map<string, object> result = generateeffectlistfromtxmetabytype(address, item, meta, item.gettype());
            list<effect> effects = (list<effect>) result.get("effects");
            if (item.gettype().equals("offercreate") && effects.size() > 1 && item.getofferstatus() == null) {
                item.setofferstatus("offer_funded");
            }
            item = (txobj) result.get("item");
            item.seteffects(effects);
            item.setshoweffects((list<effect>) result.get("show_effects"));
            resultlist.add(item);
        }
        map<string, object> resultmap = new hashmap<>();
        resultmap.put("account", address);
        resultmap.put("transactions", resultlist);
        if (maputils.isnotempty(marker)) {
            resultmap.put("marker", marker);
        }
        return new gson().tojson(resultmap);
    }

    /**
     * @param offers
     * @param currency1
     * @param currency2
     * @param flag     0--asks(sell)  1--bids(buy)
     * @return
     */
    private list<jsonobject> formatofferarray(jsonarray offers, string currency1, string currency2, int flag, int limit) {
        list<jsonobject> result = new arraylist<>();
        int len = offers.length();
        bigdecimal showsum = new bigdecimal(0);

        bigdecimal preprice = new bigdecimal(0);

        if (flag == 1) {
            jsonobject jsonobjectofferpre = new jsonobject();
            for (int i = 0; i < len; i++) {
                if (result.size() >= limit) {
                    break;
                }
                jsonobject jo = offers.getjsonobject(i);
                map<string, bigdecimal> takervalue = getoffervalue(jo);
                showsum = showsum.add(takervalue.get("takerpays"));
                bigdecimal showprice = new bigdecimal(0);
                if (takervalue.get("takerpays").compareto(new bigdecimal(0)) != 0) {
                    showprice = takervalue.get("takergets").divide(takervalue.get("takerpays"), 6, roundingmode.half_up);
                }

                jsonobject jsonobject = new jsonobject();
                jsonobject.put("account", jo.getstring("account"));
                jsonobject.put("showsum", showsum);
                jsonobject.put("showprice", showprice);
                jsonobject.put("showtakerpays", takervalue.get("takerpays"));

                if (i == 0) {
                    jsonobjectofferpre = jsonobject;
                    preprice = showprice;
                } else {
                    if (preprice.compareto(showprice) != 0) {
                        if (preprice.compareto(new bigdecimal(0)) != 0) {
                            result.add(jsonobjectofferpre);
                        }
                        jsonobjectofferpre = jsonobject;
                        preprice = showprice;
                    } else {
                        jsonobjectofferpre.put("showsum", new bigdecimal(jsonobjectofferpre.get("showsum").tostring()).add(takervalue.get("takerpays")));
                        jsonobjectofferpre.put("showtakerpays", new bigdecimal(jsonobjectofferpre.get("showtakerpays").tostring()).add(takervalue.get("takerpays")));
                    }
                }
                //result.add(jsonobject);
            }
            if (preprice.compareto(new bigdecimal(0)) != 0) {
                result.add(jsonobjectofferpre);
            }
        } else {
            preprice = new bigdecimal(0);
            jsonobject jsonobjectofferpre = new jsonobject();
            for (int i = 0; i < len; i++) {
                if (result.size() > limit) {
                    break;
                }
                jsonobject jo = offers.getjsonobject(i);
                map<string, bigdecimal> takervalue = getoffervalue(jo);
                showsum = showsum.add(takervalue.get("takergets"));
                bigdecimal showprice;
                if (isnative(currency2)) {
                    showprice = new bigdecimal(jo.getstring("quality")).divide(new bigdecimal(1000000));
                } else if(isnative(currency1)) {
                    showprice = new bigdecimal(jo.getstring("quality")).multiply(new bigdecimal(1000000));
                }else{
                    showprice = new bigdecimal(jo.getstring("quality"));
                }
                jsonobject jsonobject = new jsonobject();
                jsonobject.put("account", jo.getstring("account"));
                jsonobject.put("showsum", showsum.toplainstring());
                jsonobject.put("showprice", showprice.toplainstring());
                jsonobject.put("showtakergets", takervalue.get("takergets"));


                if (i == 0) {
                    jsonobjectofferpre = jsonobject;
                    preprice = showprice;
                } else {
                    if (preprice.compareto(showprice) != 0) {
                        if (preprice.compareto(new bigdecimal(0)) != 0) {
                            result.add(jsonobjectofferpre);
                        }
                        jsonobjectofferpre = jsonobject;
                        preprice = showprice;
                    } else {
                        jsonobjectofferpre.put("showsum", new bigdecimal(jsonobjectofferpre.get("showsum").tostring()).add(takervalue.get("takergets")));
                        jsonobjectofferpre.put("showtakergets", new bigdecimal(jsonobjectofferpre.get("showtakergets").tostring()).add(takervalue.get("takergets")));
                    }
                }
            }
            if (preprice.compareto(new bigdecimal(0)) != 0) {
                result.add(jsonobjectofferpre);
            }
        }
        return result;
    }

    private boolean isnative(string currency){
        return currency.equalsignorecase("vrp") || currency.equalsignorecase("xrp") || currency.equalsignorecase("vbc");
    }

    private map<string, bigdecimal> getoffervalue(jsonobject jo) {
        map<string, bigdecimal> result = new hashmap<>();

        string taketpaysstr = jo.get("takerpays").tostring();
        if (taketpaysstr.indexof("currency") > 0) {
            if (taketpaysstr.contains("vbc")) {
                result.put("takerpays", new bigdecimal(jo.getjsonobject("takerpays").getstring("value")).divide(new bigdecimal(1000000), 6, roundingmode.half_up));
            } else {
                result.put("takerpays", new bigdecimal(jo.getjsonobject("takerpays").getstring("value")));
            }
        } else {
            result.put("takerpays", new bigdecimal(jo.getstring("takerpays")).divide(new bigdecimal(1000000), 6, roundingmode.half_up));
        }

        string takegetsstr = jo.get("takergets").tostring();
        if (takegetsstr.indexof("currency") > 0) {
            if (takegetsstr.contains("vbc")) {
                result.put("takergets", new bigdecimal(jo.getjsonobject("takergets").getstring("value")).divide(new bigdecimal(1000000), 6, roundingmode.half_up));
            } else {
                result.put("takergets", new bigdecimal(jo.getjsonobject("takergets").getstring("value")));
            }

        } else {
            result.put("takergets", new bigdecimal(jo.getstring("takergets")).divide(new bigdecimal(1000000), 6, roundingmode.half_up));
        }

        return result;
    }

    private map getaccountoffers(string address, int limit, string c1, string issuer1, string c2, string issuer2, string marker) throws apiexception {
        map<string, object> data = new hashmap<>();
        data.put("id", 0);
        data.put("command", "account_offers");
        data.put("account", address);
        data.put("ledger", "current");
        if (limit >= 10 && limit <= 400) {
            data.put("limit", limit);
        }

        if (marker != null) {
            data.put("marker", marker);
        }

        map<string, object> result = new hashmap<>();
        string postdata = new gson().tojson(data);
        string jsonresult = moorecoinwebsocketclient.req(postdata);
        jsonobject jsonobject = new jsonobject(jsonresult);
        if (jsonobject.getstring("status").equalsignorecase("success")) {
            string markerreturn = null;
            if (jsonobject.getjsonobject("result").has("marker")) {
                markerreturn = jsonobject.getjsonobject("result").getstring("marker");
                result.put("maker", markerreturn);
            }
            jsonarray jsonarray = jsonobject.getjsonobject("result").getjsonarray("offers");
            result.put("offers", formataccountoffers(c1, issuer1, c2, issuer2, jsonarray));

        } else {
            throw new apiexception(apiexception.errorcode.unknown_error, "unknown error");
        }
        return result;

    }


    private list<jsonobject> formataccountoffersall(jsonarray jsonarray) {

        list<jsonobject> list = new arraylist<>();
        int len = jsonarray.length();
        for (int i = 0; i < len; i++) {
            jsonobject jsonobject = jsonarray.getjsonobject(i);
            string takergetsstr = jsonobject.get("taker_gets").tostring();
            string takerpaysstr = jsonobject.get("taker_pays").tostring();

            bigdecimal getvalue;
            bigdecimal payvalue;
            bigdecimal price;
            string priceunit = "vrp";

            jsonobject jsonobjecttmp = new jsonobject();
            jsonobject pricejson = new jsonobject();

            if (takergetsstr.contains("currency")) {
                getvalue = new bigdecimal(jsonobject.getjsonobject("taker_gets").getstring("value"));
                if (jsonobject.getjsonobject("taker_gets").getstring("currency").equalsignorecase("vbc")) {   //vbc
                    getvalue = getvalue.divide(new bigdecimal(1000000), 6, roundingmode.half_up);
                    jsonobject.getjsonobject("taker_gets").put("value", getvalue + "");
                }
                priceunit = jsonobject.getjsonobject("taker_gets").getstring("currency");
            } else { //vrp
                getvalue = new bigdecimal(jsonobject.getstring("taker_gets")).divide(new bigdecimal(1000000), 6, roundingmode.half_up);
                jsonobjecttmp.put("currency", "vrp");
                jsonobjecttmp.put("value", getvalue + "");
                jsonobject.put("taker_gets", jsonobjecttmp);
            }


            if (takerpaysstr.contains("currency")) {
                payvalue = new bigdecimal(jsonobject.getjsonobject("taker_pays").getstring("value"));
                if (jsonobject.getjsonobject("taker_pays").getstring("currency").equalsignorecase("vbc")) {
                    payvalue = payvalue.divide(new bigdecimal(1000000), 6, roundingmode.half_up);
                    jsonobject.getjsonobject("taker_pays").put("value", payvalue + "");
                }
            } else { //vrp
                payvalue = new bigdecimal(jsonobject.getstring("taker_pays")).divide(new bigdecimal(1000000), 6, roundingmode.half_up);
                jsonobjecttmp.put("currency", "vrp");
                jsonobjecttmp.put("value", payvalue + "");
                jsonobject.put("taker_pays", jsonobjecttmp);
            }


            if (payvalue.compareto(new bigdecimal(0)) == 0) {
                continue;
            }

            price = getvalue.divide(payvalue, 6, roundingmode.half_up);
            pricejson.put("value", price + "");
            pricejson.put("currency", priceunit);
            jsonobject.put("price", pricejson);

            jsonobject.put("type", "buy"); //

            list.add(jsonobject);
        }
        return list;
    }


    private list<jsonobject> formataccountoffers(string c1, string issuer1, string c2, string issuer2, jsonarray
            jsonarray) {
        list<jsonobject> list = new arraylist<>();
        int len = jsonarray.length();
        for (int i = 0; i < len; i++) {
            jsonobject jsonobject = jsonarray.getjsonobject(i);
            string takergets = jsonobject.get("taker_gets").tostring();
            string takerpays = jsonobject.get("taker_pays").tostring();
            if (issuer1 != null) {
                if (!takergets.contains(issuer1) && !takerpays.contains(issuer1)) {
                    continue;
                }
            }
            if (issuer2 != null) {
                if (!takergets.contains(issuer2) && !takerpays.contains(issuer2)) {
                    continue;
                }
            }

            bigdecimal amountpays;
            bigdecimal amountgets;
            jsonobject jsonobjecttmp = new jsonobject();
            string price;
            if (issuer1 == null || issuer2 == null) {  //have origin currency
                if (takergets.contains("currency")) {
                    amountpays = new bigdecimal(jsonobject.getstring("taker_pays"));
                    bigdecimal amount = amountpays.divide(new bigdecimal(1000000), 6, roundingmode.half_up);
                    jsonobject jsontakergets = jsonobject.getjsonobject("taker_gets");
                    amountgets = new bigdecimal(jsontakergets.getstring("value"));
                    if (jsontakergets.getstring("currency").equalsignorecase("vbc")) {
                        amountgets = amountgets.divide(new bigdecimal(1000000), 6, roundingmode.half_up);
                        jsonobject.getjsonobject("taker_gets").put("value", amountgets + "");
//                        jsonobjecttmpvbc.put("currency", "vbc");
//                        jsonobjecttmpvbc.put("value", amountgets+"");
//                        jsonobject.put("taker_gets", jsonobjecttmpvbc);
                    }

                    if (amountgets.compareto(new bigdecimal(0)) == 0 || amount.compareto(new bigdecimal(0)) == 0) {
                        continue;
                    }

                    if (takergets.contains(c1)) {
                        jsonobject.put("type", "sell");
                        jsonobject pricejson = new jsonobject();
                        pricejson.put("value", amount.divide(amountgets, 6, roundingmode.half_up) + "");
                        pricejson.put("currency", "vrp");
                        jsonobject.put("price", pricejson);
                    } else {
                        jsonobject.put("type", "buy");
                        jsonobject pricejson = new jsonobject();
                        pricejson.put("value", amountgets.divide(amount, 6, roundingmode.half_up) + "");
                        pricejson.put("currency", jsontakergets.getstring("currency"));
                        jsonobject.put("price", pricejson);

                    }
                    jsonobjecttmp.put("currency", "vrp");
                    jsonobjecttmp.put("value", amount + "");
                    jsonobject.put("taker_pays", jsonobjecttmp);

                } else {
                    amountgets = new bigdecimal(jsonobject.getstring("taker_gets"));
                    bigdecimal amount = amountgets.divide(new bigdecimal(1000000), 6, roundingmode.half_up);
                    jsonobject jsontakerpays = jsonobject.getjsonobject("taker_pays");
                    amountpays = new bigdecimal(jsontakerpays.getstring("value"));

                    if (jsontakerpays.getstring("currency").equalsignorecase("vbc")) {
                        amountpays = amountpays.divide(new bigdecimal(1000000), 6, roundingmode.half_up);
                        jsonobject.getjsonobject("taker_pays").put("value", amountpays + "");
                    }

                    if (amount.compareto(new bigdecimal(0)) == 0 || amountpays.compareto(new bigdecimal(0)) == 0) {
                        continue;
                    }

                    if (takerpays.contains(c1)) {
                        jsonobject.put("type", "buy");
                        jsonobject pricejson = new jsonobject();
                        pricejson.put("value", amount.divide(amountpays, 6, roundingmode.half_up) + "");
                        pricejson.put("currency", "vrp");
                        jsonobject.put("price", pricejson);
                    } else {
                        jsonobject.put("type", "sell");
                        jsonobject pricejson = new jsonobject();
                        pricejson.put("value", amountpays.divide(amount, 6, roundingmode.half_up) + "");
                        pricejson.put("currency", jsontakerpays.getstring("currency"));
                        jsonobject.put("price", pricejson);

                    }

                    jsonobjecttmp.put("currency", "vrp");
                    jsonobjecttmp.put("value", amount + "");
                    jsonobject.put("taker_gets", jsonobjecttmp);
                }
                list.add(jsonobject);
            } else {
                jsonobject jsontakerpays = jsonobject.getjsonobject("taker_pays");
                jsonobject jsontakergets = jsonobject.getjsonobject("taker_gets");
                bigdecimal getvalue = new bigdecimal(jsontakergets.getstring("value"));
                bigdecimal payvalue = new bigdecimal(jsontakerpays.getstring("value"));

                if (jsontakergets.getstring("currency").equalsignorecase("vbc")) {
                    getvalue = getvalue.divide(new bigdecimal(1000000), 6, roundingmode.half_up);
                    jsonobject.getjsonobject("taker_gets").put("value", getvalue + "");
                }

                if (jsontakerpays.getstring("currency").equalsignorecase("vbc")) {
                    payvalue = payvalue.divide(new bigdecimal(1000000), 6, roundingmode.half_up);
                    jsonobject.getjsonobject("taker_pays").put("value", payvalue + "");
                }

                if (payvalue.compareto(new bigdecimal(0)) == 0 || getvalue.compareto(new bigdecimal(0)) == 0) {
                    continue;
                }

                if (takergets.contains(issuer1)) {
                    jsonobject pricejson = new jsonobject();
                    pricejson.put("value", payvalue.divide(getvalue, 6, roundingmode.half_up) + "");
                    pricejson.put("currency", c2);
                    jsonobject.put("price", pricejson);

                    jsonobject.put("type", "sell");
                } else {
                    jsonobject pricejson = new jsonobject();
                    pricejson.put("value", getvalue.divide(payvalue, 6, roundingmode.half_up) + "");
                    pricejson.put("currency", c2);
                    jsonobject.put("price", pricejson);
                    jsonobject.put("type", "buy");
                }
                list.add(jsonobject);
            }

        }
        return list;
    }


    private string commaandround(bigdecimal value) {
        numberformat nf = numberformat.getinstance();
        nf.setminimumfractiondigits(6);
        return nf.format(value.setscale(6, bigdecimal.round_half_up));
    }


}