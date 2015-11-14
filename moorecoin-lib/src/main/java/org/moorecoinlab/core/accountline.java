package org.moorecoinlab.core;

import org.json.jsonexception;
import org.json.jsonobject;

import java.math.bigdecimal;

public class accountline {
    public amount balance;
    public amount limit_peer;
    public amount limit;

    public currency currency;

    public boolean freeze = false;
    public boolean freeze_peer = false;

    public boolean authorized = false;
    public boolean authorized_peer = false;

    public boolean no_ripple = false;
    public boolean no_ripple_peer = false;

    public int quality_in = 0;
    public int quality_out = 0;

    public static accountline fromjson(accountid orientedto, jsonobject line) {
        accountline l = new accountline();
        try {

            accountid peer = accountid.fromaddress(line.getstring("account"));

            bigdecimal balance = new bigdecimal(line.getstring("balance"));
            bigdecimal limit = new bigdecimal(line.getstring("limit"));
            bigdecimal limit_peer = new bigdecimal(line.getstring("limit_peer"));

            l .currency = currency.fromstring(line.getstring("currency"));
            l.balance = new amount(balance, l.currency, peer);

            l.limit = new amount(limit, l.currency, peer);
            l.limit_peer = new amount(limit_peer, l.currency, orientedto);

            l.freeze = line.optboolean("freeze", false);
            l.freeze_peer = line.optboolean("freeze_peer", false);

            l.authorized = line.optboolean("authorized", false);
            l.authorized_peer = line.optboolean("authorized_peer", false);

            l.no_ripple = line.optboolean("no_ripple", false);
            l.no_ripple_peer = line.optboolean("no_ripple_peer", false);

            l.quality_in = line.optint("quality_in", 0);
            l.quality_out = line.optint("quality_out", 0);

        } catch (jsonexception e) {
            throw new runtimeexception(e);
        }
        return l;
    }

}
