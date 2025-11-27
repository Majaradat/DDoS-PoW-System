package com.jaradat.ddosmitigator.detection;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

public class IPProfile {

    private final String ipAddress;
    private final Queue<Long> requestTimestamps;
    private final Map<String, Integer> requestUrlCounts;
    private final long firstRequestTimestamp;
    private int totalRequestCount = 0;

    // --- STATE & REPUTATION VARIABLES (NEW) ---
    private int currentSeverity = 0;
    private long firstDetectionTimestamp = 0;
    private int strikeCount = 0; // The "strike count" for this IP.
    private long verifiedUntilTimestamp = 0; // When their "verified" status expires.

    public IPProfile(String ipAddress) {
        this.ipAddress = ipAddress;
        this.requestTimestamps = new LinkedList<>();
        this.requestUrlCounts = new HashMap<>();
        this.firstRequestTimestamp = System.currentTimeMillis();
    }

    public void addRequest(String url) {
        this.requestTimestamps.add(System.currentTimeMillis());
        this.requestUrlCounts.put(url, this.requestUrlCounts.getOrDefault(url, 0) + 1);
        this.totalRequestCount++;
    }

    public double getCurrentRPS(int windowSizeInSeconds) {
        long windowInMillis = windowSizeInSeconds * 1000L;
        long currentTime = System.currentTimeMillis();
        
        while (!requestTimestamps.isEmpty() && requestTimestamps.peek() < currentTime - windowInMillis) {
            requestTimestamps.poll();
        }
        
        if (requestTimestamps.isEmpty()) {
            return 0.0;
        }
        
        long durationInMillis = currentTime - requestTimestamps.peek();
        double durationInSeconds = Math.max(1.0, durationInMillis / 1000.0);
        
        return (double) requestTimestamps.size() / durationInSeconds;
    }

    public double getRepetitionScore() {
        if (totalRequestCount == 0) return 0.0;
        int maxCount = requestUrlCounts.isEmpty() ? 0 : Collections.max(requestUrlCounts.values());
        return (double) maxCount / totalRequestCount;
    }

    public long getSessionDurationSeconds() {
        return (System.currentTimeMillis() - this.firstRequestTimestamp) / 1000L;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    // --- NEW GETTERS AND SETTERS FOR STATE & REPUTATION ---

    public int getCurrentSeverity() {
        return currentSeverity;
    }

    public void setCurrentSeverity(int severity) {
        if (severity > 0 && this.currentSeverity == 0) {
            this.firstDetectionTimestamp = System.currentTimeMillis();
        } else if (severity == 0) {
            this.firstDetectionTimestamp = 0;
        }
        this.currentSeverity = severity;
    }

    public long getFirstDetectionTimestamp() {
        return firstDetectionTimestamp;
    }

    public int getStrikeCount() {
        return strikeCount;
    }

    /**
     * Increases the strike count for this IP. This is called after a re-offense.
     */
    public void incrementStrikeCount() {
        this.strikeCount++;
    }

    /**
     * Checks if this IP has a valid, unexpired "Verified" status.
     */
    public boolean isVerified() {
        return System.currentTimeMillis() < this.verifiedUntilTimestamp;
    }

    /**
     * Grants this IP a "Verified" status for a set duration after solving a challenge.
     * @param durationInMillis The duration of the verified status in milliseconds.
     */
    public void setVerified(long durationInMillis) {
        this.verifiedUntilTimestamp = System.currentTimeMillis() + durationInMillis;
    }

    /**
     * Clears the request history metrics (timestamps, counts) but preserves Reputation (Strikes).
     * Used to reset the RPS calculation for a new simulation phase.
     */
    public void clearRequestHistory() {
        this.requestTimestamps.clear();
        this.requestUrlCounts.clear();
        this.totalRequestCount = 0;
    }
}