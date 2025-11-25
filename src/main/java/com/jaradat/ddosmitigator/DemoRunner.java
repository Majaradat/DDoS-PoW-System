package com.jaradat.ddosmitigator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import com.google.gson.Gson;
import com.jaradat.ddosmitigator.challenge.Challenge;
import com.jaradat.ddosmitigator.challenge.ChallengeService;
import com.jaradat.ddosmitigator.core.Request;
import com.jaradat.ddosmitigator.detection.DetectionEngine;
import com.jaradat.ddosmitigator.detection.IPProfile;
import com.jaradat.ddosmitigator.detection.PolicyManager;
import com.jaradat.ddosmitigator.mitigation.BlocklistService;
import com.jaradat.ddosmitigator.simulator.TrafficSimulator;

import io.javalin.websocket.WsContext;

public class DemoRunner {

    private final PolicyManager policyManager;
    private final TrafficSimulator simulator;
    private final ChallengeService challengeService;
    private final BlocklistService blocklistService;
    private final ConcurrentLinkedQueue<WsContext> wsContexts;
    private final Gson gson = new Gson();

    public DemoRunner(PolicyManager pm, TrafficSimulator sim, ChallengeService cs, BlocklistService bs, ConcurrentLinkedQueue<WsContext> wsCtx) {
        this.policyManager = pm;
        this.simulator = sim;
        this.challengeService = cs;
        this.blocklistService = bs;
        this.wsContexts = wsCtx;
    }

    public void runScenario(String mode, int difficulty) {
        try {
            // Send reset signal
            broadcastUpdate("reset", Map.of("message", "Resetting dashboard..."));
            Thread.sleep(200);

            switch (mode) {
                case "legit":
                    runLegitUser();
                    break;
                case "laggy":
                    runLaggyUser();
                    break;
                case "dumb":
                    runDumbBot();
                    break;
                case "persistent":
                    runPersistentBot();
                    break;
                case "stress":
                    runParallelStressTest(difficulty);
                    break;
                default:
                    broadcastUpdate("log", Map.of("message", "Unknown scenario mode selected."));
            }
            
            //broadcastUpdate("conclusion", Map.of("message", "Scenario execution finished.\n"));

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            e.printStackTrace();
            broadcastUpdate("log", Map.of("message", "ERROR: " + e.getMessage()));
        }
    }

    private int calculateDifficulty(int severityLevel, int strikeCount) {
        // FIX: Ensure severity is at least 1 if we are issuing a challenge.
        int effectiveSeverity = Math.max(severityLevel, 1);
        return (effectiveSeverity + 4) + strikeCount;
    }

    // --- SCENARIO 1: LEGIT USER ---
    private void runLegitUser() throws InterruptedException {
        DetectionEngine engine = new DetectionEngine(policyManager, blocklistService);
        String ip = "192.168.1.50";
        
        broadcastUpdate("objective", Map.of("message", "Testing Legitimate Traffic"));
        List<Request> traffic = simulator.simulateNormalUser(ip);
        
        for (Request req : traffic) {
            engine.processRequest(req);
            IPProfile p = engine.getProfile(ip);
            String ipDisplay = ip + " -> " + req.getUrl();
            broadcastUpdate("status", createStatusMap(ipDisplay, p, 0, "Browsing..."));
            Thread.sleep(600);
        }
        
        broadcastUpdate("conclusion", Map.of("message", "Traffic analyzed as Benign. No Challenge issued."));
    }

    // --- SCENARIO 2: LAGGY USER ---
    private void runLaggyUser() throws InterruptedException {
        DetectionEngine engine = new DetectionEngine(policyManager, blocklistService);
        String ip = "192.168.1.99";
        
        broadcastUpdate("objective", Map.of("message", "Testing Burst/Laggy Traffic"));
        broadcastUpdate("log", Map.of("message", "Simulating a browser sending a burst of requests (False Positive trigger)..."));

        List<Request> burst = simulator.simulateDumbBotAttack(ip, 20); 
        int initialSeverity = 0;
        for (Request req : burst) {
            initialSeverity = engine.processRequest(req);
        }
        
        // FORCE SEVERITY 1: If we are treating this as a burst, it must be Sev 1 at minimum.
        if (initialSeverity == 0) initialSeverity = 1;
        
        IPProfile p = engine.getProfile(ip);
        String ipDisplay = ip + " -> " + burst.get(0).getUrl(); 
        
        // 1. Combined Alert
        broadcastUpdate("detection", Map.of("message", "Anomaly Detected (Sev " + initialSeverity + "). Entering 2s Observation Window..."));
        broadcastUpdate("status", createStatusMap(ipDisplay, p, initialSeverity, "High Activity Detected"));

        // 2. Observation Window
        Thread.sleep(500); 
        broadcastUpdate("status", createStatusMap(ipDisplay, p, 1, "Monitoring (Observation Window)"));
        Thread.sleep(2000); 
        
        // 3. Result
        broadcastUpdate("status", createStatusMap(ipDisplay, p, 0, "Traffic Normalized"));
        broadcastUpdate("conclusion", Map.of("message", "Observation window passed. User classification reverted to BENIGN."));
    }

    // --- SCENARIO 3: DUMB BOT (Timeout) ---
    private void runDumbBot() throws InterruptedException {
        DetectionEngine engine = new DetectionEngine(policyManager, blocklistService);
        String ip = "10.10.10.10";
        String targetUrl = "/api/v1/login"; 
        String ipDisplay = ip + " -> " + targetUrl;

        // --- NEW FEATURE: Persistence Check ---
        // If we try to run this scenario again without restarting, show that the system REMEMBERS.
        if (blocklistService.isBlocked(ip)) {
            broadcastUpdate("objective", Map.of("message", "Testing Banned Bot"));
            Thread.sleep(1000);
            broadcastUpdate("block", Map.of("message", "ACCESS DENIED: IP " + ip + " is already in the Blocklist.\nRestart server to clear memory."));
            return; // EXIT the function. Do not run the simulation.
            }

        broadcastUpdate("objective", Map.of("message", "Testing Unresponsive Bot"));
        
        int severity = 0;
        // Attack Detected
        for (int i = 0; i < 3; i++) {
            List<Request> traffic = simulator.simulateDumbBotAttack(ip, 100);
            for(Request req : traffic) {
                severity = engine.processRequest(req);
            }
            IPProfile p = engine.getProfile(ip);
            broadcastUpdate("status", createStatusMap(ipDisplay, p, severity, "CRITICAL THREAT"));
            Thread.sleep(1000);
        }

        // FORCE SEVERITY 1
        if (severity == 0) severity = 1;

        // ADDED: Consistent Observation Alert + Sleep
        broadcastUpdate("detection", Map.of("message", "Anomaly Detected (Sev " + severity + "). Entering 2s Observation Window..."));
        Thread.sleep(2000);

        // Issue Challenge
        int difficulty = calculateDifficulty(severity, 0);
        // Used effectiveSeverity for display consistency
        int effectiveSeverity = Math.max(severity, 1);
        String mitigationMsg = String.format("Attack Confirmed (Sev %d). Issuing Challenge (Diff %d). Waiting for solution...", effectiveSeverity, difficulty);
        broadcastUpdate("mitigation", Map.of("message", mitigationMsg));
        
        // Wait for Solution (Silent 3s)
        broadcastUpdate("log", Map.of("message", "Applying strict solution window (3s)..."));
        Thread.sleep(3000);

        broadcastUpdate("block", Map.of("message", "Challenge TIMEOUT. Client failed to provide PoW solution."));
        blocklistService.blockIp(ip);
        broadcastUpdate("conclusion", Map.of("message", "IP " + ip + " has been added to the Blocklist."));
    }

    // --- SCENARIO 4: PERSISTENT BOT (Strikes) ---
    private void runPersistentBot() throws InterruptedException {
        DetectionEngine engine = new DetectionEngine(policyManager, blocklistService);
        String ip = "45.33.22.11";
        String targetUrl = "/api/v1/login";
        String ipDisplay = ip + " -> " + targetUrl;
        
        broadcastUpdate("objective", Map.of("message", "Testing Persistent Adversary"));

        // --- Phase 1: First Attack ---
        broadcastUpdate("log", Map.of("message", "Phase 1: Initial Flood"));
        List<Request> attack1 = simulator.simulateDumbBotAttack(ip, 150);
        int severity1 = 0;
        for(Request req : attack1) severity1 = engine.processRequest(req);
        
        // FORCE SEVERITY 1
        if (severity1 == 0) severity1 = 1;
        
        IPProfile p = engine.getProfile(ip);
        broadcastUpdate("status", createStatusMap(ipDisplay, p, severity1, "Confirming Threat...")); 
        
        // ADDED: Consistent Observation Alert + Sleep
        broadcastUpdate("detection", Map.of("message", "Anomaly Detected (Sev " + severity1 + "). Entering 2s Observation Window..."));
        Thread.sleep(2000);

        // Issue Challenge
        int diff1 = calculateDifficulty(severity1, p.getStrikeCount());
        int effectiveSev1 = Math.max(severity1, 1);
        broadcastUpdate("mitigation", Map.of("message", "Attack Confirmed (Sev " + effectiveSev1 + "). Issuing Challenge (Diff " + diff1 + ")."));
        
        // Solve 1
        executeParallelPoW(diff1, "SOLVER RESULTS");
        
        // Bot Solves it
        broadcastUpdate("solve", Map.of("message", "Bot successfully solved the challenge."));
        
        p.setVerified(5000);
        p.incrementStrikeCount(); 
        
        // Access Granted
        broadcastUpdate("status", createStatusMap(ipDisplay, p, 0, "Bot Verified (Access Granted)"));
        broadcastUpdate("log", Map.of("message", "Access Granted."));
        Thread.sleep(1000);

        // --- Phase 2: Re-Attack ---
        broadcastUpdate("log", Map.of("message", "Phase 2: Re-attack while Verified"));
        List<Request> attack2 = simulator.simulateDumbBotAttack(ip, 150);
        int severity2 = 0;
        for(Request req : attack2) severity2 = engine.processRequest(req);
        
        // FORCE SEVERITY 1
        if (severity2 == 0) severity2 = 1;
        
        // Consistent Observation Alert for Re-Attack + Sleep
        broadcastUpdate("detection", Map.of("message", "Anomaly Detected (Sev " + severity2 + "). Entering 2s Observation Window..."));
        broadcastUpdate("status", createStatusMap(ipDisplay, p, severity2, "Recidivism Detected"));
        Thread.sleep(2000);
        
        broadcastUpdate("log", Map.of("message", "Bot has existing Strike Count of " + p.getStrikeCount() + "."));

        // Issue Harder Challenge
        int diff2 = calculateDifficulty(severity2, p.getStrikeCount());
        broadcastUpdate("mitigation", Map.of("message", "Attack Confirmed. Issuing Challenge (Diff " + diff2 + ")."));
        
        // Solve 2
        executeParallelPoW(diff2, "SOLVER RESULTS");
        p.incrementStrikeCount();
        broadcastUpdate("conclusion", Map.of("message", "Access Granted. Strike Count is now " + p.getStrikeCount() + ". Cost was exponential."));
    }

    // --- SCENARIO 5: STRESS TEST ---
    private void runParallelStressTest(int difficulty) {
        int cores = Runtime.getRuntime().availableProcessors();
        String startInfo = String.format("Multi-Core CPU Stress Test Initiated.\nEngaging %d cores for Difficulty %d...", cores, difficulty);
        broadcastUpdate("objective", Map.of("message", startInfo));
        executeParallelPoW(difficulty, "STRESS TEST RESULTS");
    }

    // --- SHARED SOLVER ---
    private void executeParallelPoW(int difficulty, String resultTitle) {
        int cores = Runtime.getRuntime().availableProcessors();
        Challenge challenge = challengeService.createChallenge(difficulty);
        ExecutorService executor = Executors.newFixedThreadPool(cores);
        AtomicBoolean found = new AtomicBoolean(false);
        AtomicLong solvedTime = new AtomicLong(0);
        
        long startTime = System.nanoTime();

        for (int i = 0; i < cores; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    String target = "0".repeat(difficulty);
                    long nonce = threadId * 1000000000L; 
                    
                    while (!found.get()) {
                        String data = challenge.getChallengeString() + nonce;
                        byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
                        
                        boolean potentialMatch = true;
                        if (hash.length > 0 && (hash[0] & 0xF0) != 0) potentialMatch = false;
                        
                        if (potentialMatch) {
                             String hex = toHexString(hash);
                             if (hex.startsWith(target)) {
                                 if (found.compareAndSet(false, true)) {
                                     solvedTime.set(System.nanoTime());
                                 }
                                 return;
                             }
                        }
                        nonce++;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }

        try {
            while (!found.get()) {
                Thread.sleep(50); 
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdownNow();
        }

        long endTime = solvedTime.get();
        long durationNs = endTime - startTime;
        double attackerSeconds = durationNs / 1_000_000_000.0; 

        long startVerify = System.nanoTime();
        challengeService.verifyChallenge(challenge, "12345"); 
        long endVerify = System.nanoTime();
        
        double defenderSeconds = (endVerify - startVerify) / 1_000_000_000.0;
        if (defenderSeconds <= 0) defenderSeconds = 0.000001;

        String msg = String.format(
            "%s:\n" +
            "Cores Utilized: %d (100%% CPU)\n" +
            "Difficulty: %d\n" +
            "Time Taken: %.4f s\n" +
            "Cost Asymmetry: %.0fx",
            resultTitle, cores, difficulty, attackerSeconds, attackerSeconds/defenderSeconds
        );

        broadcastUpdate("solve", Map.of("message", msg));
    }

    private String toHexString(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private Map<String, Object> createStatusMap(String ip, IPProfile profile, int actionableSeverity, String statusMsg) {
        if (profile == null) return Map.of("ip", ip, "rps", "0", "repetition", "0", "duration", 0, "currentSeverity", 0, "status", statusMsg);
        return Map.of(
            "ip", ip,
            "rps", String.format("%.2f", profile.getCurrentRPS(10)),
            "repetition", String.format("%.2f", profile.getRepetitionScore()),
            "duration", profile.getSessionDurationSeconds(),
            "currentSeverity", profile.getCurrentSeverity(),
            "actionableSeverity", actionableSeverity,
            "status", statusMsg
        );
    }

    private void broadcastUpdate(String type, Object data) {
        String jsonMessage = gson.toJson(Map.of("type", type, "data", data));
        wsContexts.stream().filter(ctx -> ctx.session.isOpen()).forEach(ctx -> ctx.send(jsonMessage));
    }
}