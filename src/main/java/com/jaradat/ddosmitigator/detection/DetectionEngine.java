package com.jaradat.ddosmitigator.detection;

import com.jaradat.ddosmitigator.core.Request;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DetectionEngine {

    private final Map<String, IPProfile> activeProfiles = new HashMap<>();
    private final PolicyManager policyManager;
    private static final int TIME_WINDOW_SECONDS = 10;
    // The "grace period" in milliseconds. We wait 2 seconds before acting.
    private static final long OBSERVATION_WINDOW_MS = 2000; 

    public DetectionEngine(PolicyManager policyManager) {
        this.policyManager = policyManager;
    }

    /**
     * Processes a request, updates the IP's profile, and returns the
     * "actionable" severity level, considering the observation window.
     */
    public int processRequest(Request request) {
        String ip = request.getIpAddress();
        IPProfile profile = activeProfiles.computeIfAbsent(ip, IPProfile::new);
        profile.addRequest(request.getUrl());

        int calculatedSeverity = calculateCurrentSeverity(profile);
        profile.updateSeverity(calculatedSeverity);

        // Check if we should take action
        if (profile.getCurrentSeverity() > 0 && profile.getFirstDetectionTimestamp() > 0) {
            long timeSinceFirstDetection = System.currentTimeMillis() - profile.getFirstDetectionTimestamp();
            if (timeSinceFirstDetection >= OBSERVATION_WINDOW_MS) {
                // The grace period is over. The threat is confirmed. Return the current severity.
                return profile.getCurrentSeverity();
            }
        }

        // We are still in the observation window or there's no threat. No action needed yet.
        return 0;
    }

    /**
     * This private helper method contains the core detection logic.
     * It compares an IP's current behavior against the loaded policies.
     */
    private int calculateCurrentSeverity(IPProfile profile) {
        double currentRPS = profile.getCurrentRPS(TIME_WINDOW_SECONDS);
        double repetitionScore = profile.getRepetitionScore();
        long sessionDuration = profile.getSessionDurationSeconds();

        List<PolicyRule> rules = policyManager.getRules();
        // Check rules from most severe to least severe.
        for (int i = rules.size() - 1; i >= 0; i--) {
            PolicyRule rule = rules.get(i);
            // Check if all conditions for this rule are met.
            if (currentRPS >= (rule.rps * 0.9) && 
                repetitionScore >= rule.repetitionScore && 
                sessionDuration < rule.sessionDurationSeconds) {
                return rule.level; // Return the highest level that matches.
            }
        }
        return 0; // No rules matched, traffic is normal.
    }
    
    /**
     * A helper method to get the profile for a specific IP, used by the demo script.
     */
    public IPProfile getProfile(String ip) {
        return activeProfiles.get(ip);
    }
}