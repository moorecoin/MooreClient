package org.moorecoinlab.core;

import java.util.list;

public class txobj {
    private string date;
    private string sender;
    private string recipient;
    private amountobj amount;
    private amountobj amountvbc;
    private string type;
    private string hash;
    private string contact;
    private amountobj limitamount;
    private amountobj takergets;
    private amountobj takerpays;
    private amountobj partiallygets;
    private amountobj partiallypays;
    private string offerstatus;

    private list<effect> effects;
    private list<effect> showeffects;

    private amountobj fee;
    private long balance;

    public string getdate() {
        return date;
    }

    public void setdate(string date) {
        this.date = date;
    }

    public string getsender() {
        return sender;
    }

    public void setsender(string sender) {
        this.sender = sender;
    }

    public string getrecipient() {
        return recipient;
    }

    public void setrecipient(string recipient) {
        this.recipient = recipient;
    }

    public amountobj getfee() {
        return fee;
    }

    public void setfee(amountobj fee) {
        this.fee = fee;
    }

    public long getbalance() {
        return balance;
    }

    public void setbalance(long balance) {
        this.balance = balance;
    }

    public string gettype() {
        return type;
    }

    public void settype(string type) {
        this.type = type;
    }

    public list<effect> geteffects() {
        return effects;
    }

    public void seteffects(list<effect> effects) {
        this.effects = effects;
    }

    public string gethash() {
        return hash;
    }

    public void sethash(string hash) {
        this.hash = hash;
    }

    public string getcontact() {
        return contact;
    }

    public void setcontact(string contact) {
        this.contact = contact;
    }

    public void settakergets(amountobj takergets) {
        this.takergets = takergets;
    }

    public void settakerpays(amountobj takerpays) {
        this.takerpays = takerpays;
    }

    public amountobj getamount() {
        return amount;
    }

    public void setamount(amountobj amount) {
        this.amount = amount;
    }

    public amountobj getamountvbc() {
        return amountvbc;
    }

    public void setamountvbc(amountobj amountvbc) {
        this.amountvbc = amountvbc;
    }

    public amountobj gettakergets() {
        return takergets;
    }

    public amountobj gettakerpays() {
        return takerpays;
    }

    public amountobj getlimitamount() {
        return limitamount;
    }

    public void setlimitamount(amountobj limitamount) {
        this.limitamount = limitamount;
    }

    public string getofferstatus() {
        return offerstatus;
    }

    public void setofferstatus(string offerstatus) {
        offerstatus = offerstatus;
    }

    public list<effect> getshoweffects() {
        return showeffects;
    }

    public void setshoweffects(list<effect> showeffects) {
        this.showeffects = showeffects;
    }

    public amountobj getpartiallygets() {
        return partiallygets;
    }

    public void setpartiallygets(amountobj partiallygets) {
        this.partiallygets = partiallygets;
    }

    public amountobj getpartiallypays() {
        return partiallypays;
    }

    public void setpartiallypays(amountobj partiallypays) {
        this.partiallypays = partiallypays;
    }
}
