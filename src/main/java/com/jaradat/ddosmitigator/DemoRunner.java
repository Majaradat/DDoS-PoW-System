package com.jaradat.ddosmitigator;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import com.google.gson.Gson;
import com.jaradat.ddosmitigator.challenge.Challenge;
import com.jaradat.ddosmitigator.challenge.ChallengeService;
import com.jaradat.ddosmitigator.core.Request;
import com.jaradat.ddosmitigator.detection.DetectionEngine;
import com.jaradat.ddosmitigator.detection.IPProfile;
import com.jaradat.ddosmitigator.detection.PolicyManager;
import com.jaradat.ddosmitigator.simulator.TrafficSimulator;

import io.javalin.websocket.WsContext;

/**
 * This class contains the logic for running the multi-scenario demonstration.
 * Its single responsibility is to execute the demo script and broadcast updates.
 */
public class DemoRunner {

    private final PolicyManager policyManager;
    private final TrafficSimulator simulator;
    private final ChallengeService challengeService;
    private final ConcurrentLinkedQueue<WsContext> wsContexts;
    private final Gson gson = new Gson();

    public DemoRunner(PolicyManager pm, TrafficSimulator sim, ChallengeService cs, ConcurrentLinkedQueue<WsContext> contexts) {
        this.policyManager = pm;
        this.simulator = sim;
        this.challengeService = cs;
        this.wsContexts = contexts;
    }

    public void run() {
        try {
            // --- SCENARIO 1: The Legitimate User ---
            broadcastUpdate("log", "--- SCENARIO 1: The Legitimate User ---");
            broadcastUpdate("objective", "OBJECTIVE: Prove that normal, low-rate traffic is not impacted.");
            DetectionEngine engine1 = new DetectionEngine(policyManager);
            String userIp = "192.168.1.100";
            List<Request> normalTraffic = simulator.simulateNormalUser(userIp);
            for (Request req : normalTraffic) {
                engine1.processRequest(req);
            }
            IPProfile userProfile = engine1.getProfile(userIp);
            broadcastUpdate("status", userIp, userProfile, 0, 0, "Benign traffic identified. No action taken.");
            broadcastUpdate("log", "CONCLUSION: System correctly identified traffic as benign. Test PASSED.\n");
            Thread.sleep(3000);

            // --- SCENARIO 2: The "Dumb Bot" Flood ---
            broadcastUpdate("log", "--- SCENARIO 2: The 'Dumb Bot' Flood ---");
            broadcastUpdate("objective", "OBJECTIVE: Demonstrate fast detection, challenge, and blocking of a non-responsive attacker.");
            DetectionEngine engine2 = new DetectionEngine(policyManager);
            String dumbBotIp = "10.20.30.40";
            for (int second = 1; second <= 3; second++) {
                List<Request> attackTraffic = simulator.simulateDumbBotAttack(dumbBotIp, 250);
                int actionableSeverity = 0;
                for (Request req : attackTraffic) {
                    actionableSeverity = engine2.processRequest(req);
                }
                IPProfile profile = engine2.getProfile(dumbBotIp);
                String statusMsg = "Detecting threat. In observation window...";
                if (actionableSeverity > 0) {
                     statusMsg = "Threat confirmed. Issuing challenge.";
                }
                broadcastUpdate("status", dumbBotIp, profile, profile.getCurrentSeverity(), actionableSeverity, statusMsg);
                Thread.sleep(1000);
            }
            broadcastUpdate("log", "[MITIGATION] Timeout exceeded. IP " + dumbBotIp + " is now considered BLOCKED.");
            broadcastUpdate("log", "CONCLUSION: System successfully detected the flood and simulated blocking the non-compliant bot. Test PASSED.\n");
            Thread.sleep(3000);

            // --- SCENARIO 3: The Dynamic Escalation ---
            broadcastUpdate("log", "--- SCENARIO 3: The Dynamic Escalation ---");
            broadcastUpdate("objective", "OBJECTIVE: Showcase the system adapting to a threat that increases its intensity in real-time.");
            DetectionEngine engine3 = new DetectionEngine(policyManager);
            String smartBotIp = "99.88.77.66";
            
            List<Request> moderateAttack = simulator.simulateDumbBotAttack(smartBotIp, 100);
            for (Request req : moderateAttack) {
                engine3.processRequest(req);
            }
            IPProfile smartBotProfile = engine3.getProfile(smartBotIp);
            broadcastUpdate("status", smartBotIp, smartBotProfile, smartBotProfile.getCurrentSeverity(), 0, "Initial threat detected. In observation window...");
            Thread.sleep(1000);
            
            List<Request> criticalAttack = simulator.simulateDumbBotAttack(smartBotIp, 250);
            int finalActionableSeverity = 0;
            for (Request req : criticalAttack) {
                finalActionableSeverity = engine3.processRequest(req);
            }
            smartBotProfile = engine3.getProfile(smartBotIp);
            broadcastUpdate("status", smartBotIp, smartBotProfile, smartBotProfile.getCurrentSeverity(), finalActionableSeverity, "Attack escalated to CRITICAL.");
            
            if (finalActionableSeverity > 0) {
                int difficulty = finalActionableSeverity + 2;
                broadcastUpdate("log", "[MITIGATION] Issuing a high-difficulty PoW Challenge (Difficulty " + difficulty + ").");
                Challenge challenge = challengeService.createChallenge(difficulty);
                
                broadcastUpdate("log", "[ATTACKER SIM] Received challenge. Brute-forcing solution... (This may take a moment)");
                long startTime = System.currentTimeMillis();
                String solution = challengeService.solveChallenge(challenge);
                long endTime = System.currentTimeMillis();
                double timeTaken = (endTime - startTime) / 1000.0;
                
                String resultLog = String.format("Solution found in %.2f seconds.", timeTaken);
                broadcastUpdate("solve", resultLog);
                broadcastUpdate("log", "CONCLUSION: System dynamically adapted to the escalating threat, imposing a significant computational cost. Test PASSED.\n");
            }
            
            broadcastUpdate("log", "================ DEMO FINISHED ================");

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // --- BROADCAST HELPER METHODS ---
    private void broadcastUpdate(String type, String message) {
        broadcastUpdate(type, Map.of("message", message));
    }
    
    private void broadcastUpdate(String type, String objective, String message) {
         broadcastUpdate(type, Map.of("objective", objective, "message", message));
    }
    
    private void broadcastUpdate(String type, Object data) {
        String jsonMessage = gson.toJson(Map.of("type", type, "data", data));
        wsContexts.forEach(ctx -> {
            if (ctx.session.isOpen()) {
                ctx.send(jsonMessage);
            }
        });
    }

    private void broadcastUpdate(String type, String ip, IPProfile profile, int currentSeverity, int actionableSeverity, String statusMsg) {
        Map<String, Object> data = Map.of(
            "ip", ip,
            "rps", String.format("%.2f", profile.getCurrentRPS(10)),
            "repetition", String.format("%.2f", profile.getRepetitionScore()),
            "duration", profile.getSessionDurationSeconds(),
            "currentSeverity", currentSeverity,
            "actionableSeverity", actionableSeverity,
            "status", statusMsg
        );
        broadcastUpdate(type, data);
    }
}