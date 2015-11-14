package org.moorecoinlab.core;

import org.json.jsonobject;

import java.util.arraylist;
import java.util.list;

public class issuerline {
    private boolean show = false;
    private double amount;
    private string currency;
    private string issuer;
    private list<jsonobject> lines = new arraylist<>();



    public list<jsonobject> getlines() {
        return lines;
    }

    public void setlines(list<jsonobject> lines) {
        this.lines = lines;
    }

    public boolean isshow() {
        return show;
    }

    public void setshow(boolean show) {
        this.show = show;
    }

    public double getamount() {
        return amount;
    }

    public void setamount(double amount) {
        this.amount = amount;
    }

    public string getcurrency() {
        return currency;
    }

    public void setcurrency(string currency) {
        this.currency = currency;
    }

    public string getissuer() {
        return issuer;
    }

    public void setissuer(string issuer) {
        this.issuer = issuer;
    }
}
