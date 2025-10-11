package com.jaradat.ddosmitigator.mitigation;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * A simple, in-memory service to manage a list of blocked IP addresses.
 * In a real-world system, this might interact with a firewall or a distributed database.
 */
public class BlocklistService {

    private final Set<String> blockedIps = Collections.synchronizedSet(new HashSet<>());

    /**
     * Adds an IP address to the blocklist.
     * @param ipAddress The IP to block.
     */
    public void blockIp(String ipAddress) {
        blockedIps.add(ipAddress);
    }

    /**
     * Removes an IP address from the blocklist.
     * @param ipAddress The IP to unblock.
     */
    public void unblockIp(String ipAddress) {
        blockedIps.remove(ipAddress);
    }

    /**
     * Checks if a given IP address is currently on the blocklist.
     * @param ipAddress The IP to check.
     * @return true if the IP is blocked, false otherwise.
     */
    public boolean isBlocked(String ipAddress) {
        return blockedIps.contains(ipAddress);
    }

    /**
     * Returns the number of IPs currently on the blocklist.
     * @return The size of the blocklist.
     */
    public int getBlocklistSize() {
        return blockedIps.size();
    }
}