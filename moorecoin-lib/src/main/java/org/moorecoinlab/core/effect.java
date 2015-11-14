package org.moorecoinlab.core;

public class effect {
    private amountobj amount;
    private amountobj balance;
//    private amountobj balancevbc;
    private string type;
    private amountobj takergets;
    private amountobj takerpays;

    public amountobj getamount() {
        return amount;
    }

    public void setamount(amountobj amount) {
        this.amount = amount;
    }

    public amountobj getbalance() {
        return balance;
    }

    public void setbalance(amountobj balance) {
        this.balance = balance;
    }

    public string gettype() {
        return type;
    }

    public void settype(string type) {
        this.type = type;
    }

    public amountobj gettakerpays() {
        return takerpays;
    }

    public void settakerpays(amountobj takerpays) {
        this.takerpays = takerpays;
    }

    public amountobj gettakergets() {
        return takergets;
    }

    public void settakergets(amountobj takergets) {
        this.takergets = takergets;
    }
}
