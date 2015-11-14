package org.moorecoinlab.core;

public class amountobj {
    private double amount;
    private string currency;
    private string issuer;

    public amountobj(double amount, string currency, string issuer){
        this.amount = amount;
        this.currency = currency;
        this.issuer = issuer;
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
