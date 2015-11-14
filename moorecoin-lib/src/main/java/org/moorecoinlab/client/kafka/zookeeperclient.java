package org.moorecoinlab.client.kafka;

import org.moorecoinlab.client.config;
import org.apache.log4j.logger;
import org.apache.zookeeper.*;

import java.io.ioexception;


public class zookeeperclient {
    private static final logger log = logger.getlogger(zookeeperclient.class);
    public static zookeeper zk;
    private static string zkcluster;
    private static final string rootpath = config.getinstance().getproperty("zookeeper.ledger_index");

    static {
        zkcluster = config.getinstance().getproperty("zookeeper.cluster");
        log.info("zkcluster from config: " + zkcluster);

        if (zk == null) {
            synchronized (zookeeper.class) {
                if (zk == null) {
                    try {
                        zk = new zookeeper(zkcluster, 30000, new sessionwatcher());

                    } catch (ioexception e) {
                        e.printstacktrace();
                    } finally {

                    }
                }
            }
        }
    }

    public static int getledgerindex() {
        try {
            if (zk.exists(rootpath, false) == null) {
                return 0;
            } else {
                return integer.valueof(new string(zk.getdata(rootpath, false, null)));
            }
        } catch (keeperexception e) {
            e.printstacktrace();
        } catch (interruptedexception e) {
            e.printstacktrace();
        }
        return -1;
    }

    public static string getpathvalue(string path) {
        try {
            if (zk.exists(path, false) == null) {
                return null;
            } else {
                return new string(zk.getdata(path, false, null));
            }
        } catch (keeperexception e) {
            e.printstacktrace();
        } catch (interruptedexception e) {
            e.printstacktrace();
        }
        return null;
    }

    public static void setpathvalue(string path, string value) {
        try {
            if (zk.exists(path, false) == null) {
                return;
            } else {
                zk.setdata(path, value.getbytes(), -1);
            }
        } catch (keeperexception e) {
            e.printstacktrace();
        } catch (interruptedexception e) {
            e.printstacktrace();
        }
    }

    public static void saveledger(int ledgerindex) {
        try {
            if (zk.exists(rootpath, false) == null) {
                string cr = zk.create(rootpath, string.valueof(ledgerindex).getbytes(),
                        zoodefs.ids.open_acl_unsafe, createmode.persistent);
                log.debug("create node:" + cr);
            } else {
                zk.setdata(rootpath, string.valueof(ledgerindex).getbytes(), -1);
            }
        } catch (keeperexception e) {
            e.printstacktrace();
        } catch (interruptedexception e) {
            e.printstacktrace();
        }
    }

    public static void restart() {
        if (zk != null) {
            try {
                zk.close();
            } catch (interruptedexception e) {
                e.printstacktrace();
            }
            zk = null;
        }
        if (zk == null) {
            synchronized (zookeeper.class) {
                if (zk == null) {
                    try {
                        zk = new zookeeper(zkcluster, 30000, new sessionwatcher());

                    } catch (ioexception e) {
                        e.printstacktrace();
                    } finally {

                    }
                }
            }
        }
    }

    public static class sessionwatcher implements watcher {
        @override
        public void process(watchedevent watchedevent) {
            log.info("receive event:" + watchedevent);
            //session timeout
            if (watchedevent.getstate() == event.keeperstate.expired) {
                zookeeperclient.restart();
            }
        }
    }
}
