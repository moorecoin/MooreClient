package org.moorecoinlab.core.exception;

/**
 * exception of all moorecoinj
 */
public class moorecoinexception extends runtimeexception {
    private int code;
    private string msg;


    public moorecoinexception(string msg){
        super(msg);
        this.msg = msg;
    }

    public moorecoinexception(int code, string msg){
        super(msg);
        this.code = code;
        this.msg = msg;
    }

    public int getcode() {
        return code;
    }

    public string getmsg() {
        return msg;
    }
}
