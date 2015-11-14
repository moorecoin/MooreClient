package org.moorecoinlab.client.kafka;

import org.moorecoinlab.client.config;
import kafka.consumer.consumerconfig;
import kafka.consumer.consumeriterator;
import kafka.consumer.kafkastream;
import kafka.javaapi.consumer.consumerconnector;
import org.apache.commons.lang3.math.numberutils;
import org.apache.log4j.logger;
import org.apache.log4j.priority;

import java.util.hashmap;
import java.util.list;
import java.util.map;
import java.util.properties;


public class accountbalanceconsumer {
    private final logger logger = logger.getlogger(accountbalanceconsumer.class);
    private final string groupid;
    private final string topic;
    private final boolean loadfromstart;
    private consumerconnector consumer = null;
    protected consumeriterator<byte[], byte[]> consumeriterator;

    public accountbalanceconsumer(string topic, string groupid, boolean loadfromstart) {
        this.groupid = groupid;
        this.topic = topic;
        this.loadfromstart = loadfromstart;
        startconsumer();
    }

    private void startconsumer(){
        synchronized (accountbalanceconsumer.class) {
            boolean success = false;
            map<string, list<kafkastream<byte[], byte[]>>> consumermap = null;
            while (!success) {
                try {
                    consumer = kafka.consumer.consumer.createjavaconsumerconnector(createconsumerconfig());
                    map<string, integer> topiccountmap = new hashmap<>();
                    topiccountmap.put(topic, 1);
                    consumermap = consumer.createmessagestreams(topiccountmap);
                    success = true;
                } catch (exception ex) {
                    if (logger.isenabledfor(priority.error)) {
                        logger.error("init cosumer stream error, restart connector.");
                    } else {
                        system.err.println("init cosumer stream error, restart connector.");
                    }
                    shutdown();
                }
            }
            list<kafkastream<byte[], byte[]>> streams = consumermap.get(topic);
            consumeriterator = streams.get(0).iterator();
        }
    }

    public void shutdown() {
        if (consumer != null) consumer.shutdown();
    }

    public void run() {
    }

    private consumerconfig createconsumerconfig() {
        properties props = new properties();
        string cluster = config.getinstance().getproperty("zookeeper.cluster");
        logger.info("kafka config zk cluster:" + cluster);
        props.put("zookeeper.connect", cluster);
        props.put("group.id", groupid);
        props.put("zookeeper.session.timeout.ms", "30000");
        props.put("zookeeper.sync.time.ms", "200");
//        props.put("rebalance.backoff.ms", "5000");
        props.put("auto.commit.interval.ms", "1000");
        if(loadfromstart)
            props.put("auto.offset.reset", "smallest");
        else
            props.put("auto.offset.reset", "largest");
        return new consumerconfig(props);
    }

    /**
     * get current zk offset value
     * /consumers/{group_id}/offsets/{topic}/{partition}
     * @return
     */
    public long getcurrentoffset(){
        string path = "/consumers/" + groupid + "/offsets/" + topic + "/0";
        string pathvalue = zookeeperclient.getpathvalue(path);
        if(numberutils.isnumber(pathvalue)){
            return long.valueof(pathvalue);
        }else{
            return -1;
        }
    }

    /**
     * get current zk offset value
     * /consumers/{group_id}/offsets/{topic}/{partition}
     * @return
     */
    public void resetcurrentoffset(long offset){
        shutdown();
        string path = "/consumers/" + groupid + "/offsets/" + topic + "/0";
        zookeeperclient.setpathvalue(path, string.valueof(offset));
        startconsumer();
    }

    public void sleep(long miliseconds){
        try {
            thread.sleep(miliseconds);
        } catch (interruptedexception e) {
            e.printstacktrace();
        }
    }
}
