package org.moorecoinlab.client;

import java.io.serializable;
import java.util.concurrent.atomic.atomicinteger;
import java.util.concurrent.locks.reentrantlock;

/**
 * rate limit status object
 * @author wenfengsun
 * @since 2010-3-17涓嬪崍01:39:52
 */
public class ratelimitstatus extends reentrantlock implements serializable{

	private static final long serialversionuid = 776385000746792594l;
	private integer hourly_limit;
	private atomicinteger remaining_hits;
	private integer reset_time_in_seconds;
	private string reset_time;

    public atomicinteger getremaining_hits() {
        return remaining_hits;
    }

    public void setremaining_hits(atomicinteger remaining_hits) {
        this.remaining_hits = remaining_hits;
    }

    public integer gethourly_limit() {
		return hourly_limit;
	}
	public void sethourly_limit(integer hourly_limit) {
		this.hourly_limit = hourly_limit;
	}
	public integer getreset_time_in_seconds() {
		return reset_time_in_seconds;
	}
	public void setreset_time_in_seconds(integer reset_time_in_seconds) {
		this.reset_time_in_seconds = reset_time_in_seconds;
	}
	public string getreset_time() {
		return reset_time;
	}
	public void setreset_time(string reset_time) {
		this.reset_time = reset_time;
	}
	public string tostring(){
		return "hourly_limit="+hourly_limit+", remaining_hits="+remaining_hits+", reset_time_in_seconds="+reset_time_in_seconds
		+", reset_time="+reset_time;
	}
}
