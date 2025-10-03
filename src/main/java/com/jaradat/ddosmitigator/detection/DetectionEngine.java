package com.jaradat.ddosmitigator.detection;

import com.jaradat.ddosmitigator.core.Request;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DetectionEngine {

    private final Map<String, IPProfile> activeProfiles = new HashMap<>();
    private final PolicyManager policyManager;
    private static final int TIME_WINDOW_SECONDS = 10;
    
    // --- NEW: Define our observation window (e.g., 2 seconds) ---
    private static final long OBSERVATION_WINDOW_MS = 2000;

    public DetectionEngine(PolicyManager policyManager) {
        this.policyManager = policyManager;
    }

    /**
     * The main analysis method. It updates a profile's state but returns the
     * severity level ONLY if an action (like a challenge) should be taken.
     * @return The severity level (1-4) if action is needed, otherwise 0.
     */
    public int processRequest(Request request) {
        String ip = request.getIpAddress();
        IPProfile profile = activeProfiles.computeIfAbsent(ip, IPProfile::new);
        profile.addRequest(request.getUrl());

        // Step 1: Calculate the potential threat level based on current behavior.
        int calculatedSeverity = calculateCurrentSeverity(profile);
        
        // Step 2: Update the profile's internal state.
        profile.setCurrentSeverity(calculatedSeverity);

        // Step 3: Apply the observation window logic.
        if (profile.getCurrentSeverity() > 0) {
            // If this is the first time we've detected a threat for this IP, start the clock.
            if (profile.getFirstDetectionTimestamp() == 0) {
                profile.setFirstDetectionTimestamp(System.currentTimeMillis());
                System.out.printf("[DETECTION ENGINE] Initial threat (Severity %d) detected for %s. Entering observation window...\n", profile.getCurrentSeverity(), ip);
                return 0; // Still in observation, don't act yet.
            }

            // If a threat has been sustained for longer than our window, it's time to act.
            long threatDuration = System.currentTimeMillis() - profile.getFirstDetectionTimestamp();
            if (threatDuration > OBSERVATION_WINDOW_MS) {
                return profile.getCurrentSeverity(); // Window passed, return the severity to trigger a challenge.
            }
        } else {
            // If behavior is normal, reset the clock.
            profile.resetDetectionState();
        }

        return 0; // Default to no action.
    }

    /**
     * This is the core detection logic that calculates a severity level.
     */
    private int calculateCurrentSeverity(IPProfile profile) {
        double currentRPS = profile.getCurrentRPS(TIME_WINDOW_SECONDS);
        double repetitionScore = profile.getRepetitionScore();
        long sessionDuration = profile.getSessionDurationSeconds();

        List<PolicyRule> rules = policyManager.getRules();
        for (int i = rules.size() - 1; i >= 0; i--) {
            PolicyRule rule = rules.get(i);
            if (currentRPS >= rule.rps && 
                repetitionScore >= rule.repetitionScore && 
                sessionDuration < rule.sessionDurationSeconds) {
                return rule.level;
            }
        }
        return 0;
    }
    
    // Helper method to access profile data for logging.
    public IPProfile getProfile(String ip) {
        return activeProfiles.getOrDefault(ip, new IPProfile(ip));
    }
}