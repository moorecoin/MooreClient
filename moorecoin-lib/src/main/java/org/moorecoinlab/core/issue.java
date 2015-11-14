package org.moorecoinlab.core;

import org.json.jsonexception;
import org.json.jsonobject;

import java.math.bigdecimal;

/**
 * represents a currency/issuer pair
 */
public class issue implements comparable<issue> {

    public static final issue vrp = fromstring("vrp");
    currency currency;
    accountid issuer;

    public issue(currency currency, accountid issuer) {
        this.currency = currency;
        this.issuer = issuer;
    }

    public static issue fromstring(string pair) {
        string[] split = pair.split("/");
        return getissue(split);
    }

    private static issue getissue(string[] split) {
        if (split.length == 2) {
            return new issue(currency.fromstring(split[0]), accountid.fromstring(split[1]));
        } else if (split[0].equals("vrp")) {
            return new issue(currency.vrp, accountid.vrp_issuer);
        } else {
            throw new runtimeexception("issue string must be vrp or $currency/$issuer");
        }
    }

    public currency currency() {
        return currency;
    }

    public accountid issuer() {
        return issuer;
    }

    @override
    public string tostring() {
        if (isnative()) {
            return "vrp";
        } else {
            return string.format("%s/%s", currency, issuer);
        }
    }

    public jsonobject tojson() {
        jsonobject o = new jsonobject();
        try {
            o.put("currency", currency);
            if (!isnative()) {
                o.put("issuer", issuer);
            }
        } catch (jsonexception e) {
            throw new runtimeexception(e);
        }
        return o;
    }

    public amount amount(bigdecimal value) {
        return new amount(value, currency, issuer, isnative());
    }

    private boolean isnative() {
        return this == vrp || currency.equals(currency.vrp);
    }

    public amount amount(number value) {
        return new amount(bigdecimal.valueof(value.doublevalue()), currency, issuer, isnative());
    }

    @override
    public int compareto(issue o) {
        int ret = issuer.compareto(o.issuer);
        if (ret != 0) {
            return ret;
        }
        ret = currency.compareto(o.currency);
        return ret;
    }

    public amount roundedamount(bigdecimal amount) {
        return amount(amount.roundvalue(amount, isnative()));
    }
}
