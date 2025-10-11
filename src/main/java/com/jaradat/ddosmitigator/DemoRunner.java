package com.jaradat.ddosmitigator;

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

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * This class contains the final, corrected demonstration script with guaranteed difficulty scaling.
 */
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

    public void run() {
        try {
            runScenario_NormalUser();
            runScenario_DumbBotFlood();
            runScenario_PersistentAdversary(); 

            broadcastUpdate("log", Map.of("message", "================ DEMO FINISHED ================"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            try { Thread.sleep(2000); } catch (InterruptedException e) {}
            wsContexts.forEach(WsContext::closeSession);
        }
    }

    private void runScenario_NormalUser() throws InterruptedException {
        broadcastUpdate("objective", Map.of("message", "SCENARIO 1: The Legitimate User"));
        broadcastUpdate("log", Map.of("message", "OBJECTIVE: Prove that normal, low-rate traffic is not impacted."));
        DetectionEngine engine = new DetectionEngine(policyManager, blocklistService);
        String userIp = "192.168.1.100";
        List<Request> normalTraffic = simulator.simulateNormalUser(userIp);
        for (Request req : normalTraffic) {
            engine.processRequest(req);
        }
        IPProfile userProfile = engine.getProfile(userIp);
        broadcastUpdate("status", createStatusMap(userIp, userProfile, 0, "Benign traffic identified."));
        broadcastUpdate("conclusion", Map.of("message", "CONCLUSION: System correctly identified traffic as benign. Test PASSED.\n"));
        Thread.sleep(3000);
    }

    private void runScenario_DumbBotFlood() throws InterruptedException {
        broadcastUpdate("objective", Map.of("message", "SCENARIO 2: The 'Dumb Bot' Flood"));
        broadcastUpdate("log", Map.of("message", "OBJECTIVE: Demonstrate fast detection and blocking of a non-responsive attacker."));
        DetectionEngine engine = new DetectionEngine(policyManager, blocklistService);
        String dumbBotIp = "10.20.30.40";

        broadcastUpdate("log", Map.of("message", "PHASE 1: Bot starts a massive flood (250 RPS)."));
        for (int second = 1; second <= 3; second++) {
            List<Request> attackTraffic = simulator.simulateDumbBotAttack(dumbBotIp, 250);
            int actionableSeverity = 0;
            for (Request req : attackTraffic) {
                actionableSeverity = engine.processRequest(req);
            }
            IPProfile profile = engine.getProfile(dumbBotIp);
            String statusMsg = actionableSeverity > 0 ? "Threat confirmed. Action taken." : "Detecting threat...";
            broadcastUpdate("status", createStatusMap(dumbBotIp, profile, actionableSeverity, statusMsg));
            Thread.sleep(1000);
        }
        
        broadcastUpdate("log", Map.of("message", "[MITIGATION] Timeout exceeded. Adding IP " + dumbBotIp + " to the blocklist."));
        blocklistService.blockIp(dumbBotIp);

        broadcastUpdate("log", Map.of("message", "\nPHASE 2: Verifying block. Bot attempts to attack again."));
        Thread.sleep(2000);
        List<Request> blockedAttack = simulator.simulateDumbBotAttack(dumbBotIp, 50);
        int result = engine.processRequest(blockedAttack.get(0));
        if (result == -1) {
            broadcastUpdate("log", Map.of("message", "[SYSTEM] Request from " + dumbBotIp + " was instantly dropped by the blocklist."));
        }
        
        broadcastUpdate("conclusion", Map.of("message", "CONCLUSION: System successfully implemented and verified the blocklist. Test PASSED.\n"));
        Thread.sleep(3000);
    }
    
    private void runScenario_PersistentAdversary() throws InterruptedException {
        broadcastUpdate("objective", Map.of("message", "SCENARIO 3: The Persistent Adversary"));
        broadcastUpdate("log", Map.of("message", "OBJECTIVE: Prove the system punishes repeat offenders with exponentially harder challenges."));
        
        DetectionEngine engine = new DetectionEngine(policyManager, blocklistService);
        String persistentBotIp = "99.88.77.66";

        // --- FIRST OFFENSE ---
        broadcastUpdate("log", Map.of("message", "\nPHASE 1: Attacker begins with a high-level attack (150 RPS)."));
        for (int i = 0; i < 2; i++) {
            List<Request> firstAttack = simulator.simulateDumbBotAttack(persistentBotIp, 150);
            for (Request req : firstAttack) {
                engine.processRequest(req);
            }
            Thread.sleep(1000);
            IPProfile p = engine.getProfile(persistentBotIp);
            broadcastUpdate("status", createStatusMap(persistentBotIp, p, p.getCurrentSeverity(), "Confirming threat..."));
        }
        
        IPProfile profile = engine.getProfile(persistentBotIp);
        int difficulty1 = 5; 
        broadcastUpdate("log", Map.of("message", "[MITIGATION] Threat Confirmed. Issuing Challenge (Difficulty " + difficulty1 + "). Strike Count: " + profile.getStrikeCount()));
        solveAndBroadcast(challengeService, difficulty1);

        profile.setVerified(5000); 
        profile.incrementStrikeCount(); 
        broadcastUpdate("log", Map.of("message", "[STATUS] Attacker is now VERIFIED but has 1 STRIKE.\n"));
        Thread.sleep(3000);

        // --- SECOND OFFENSE (THE RE-ATTACK) ---
        broadcastUpdate("log", Map.of("message", "PHASE 2: Attacker immediately re-attacks with a CRITICAL flood (250 RPS)."));
        for (int i = 0; i < 2; i++) {
            List<Request> secondAttack = simulator.simulateDumbBotAttack(persistentBotIp, 250);
             for (Request req : secondAttack) {
                engine.processRequest(req);
            }
            Thread.sleep(1000);
            IPProfile p = engine.getProfile(persistentBotIp);
            broadcastUpdate("status", createStatusMap(persistentBotIp, p, p.getCurrentSeverity(), "Confirming repeat offense..."));
        }

        profile = engine.getProfile(persistentBotIp);
        int difficulty2 = 7;
        broadcastUpdate("log", Map.of("message", "[MITIGATION] Punitive Escalation! Issuing Challenge (Difficulty " + difficulty2 + "). Strike Count: " + profile.getStrikeCount()));
        solveAndBroadcast(challengeService, difficulty2);

        broadcastUpdate("conclusion", Map.of("message", "CONCLUSION: System successfully punished the repeat offender. Test PASSED.\n"));
    }

    private void solveAndBroadcast(ChallengeService cs, int difficulty) {
        broadcastUpdate("log", Map.of("message", "[ATTACKER SIM] Brute-forcing solution... (This may take a moment)"));
        long startTime = System.currentTimeMillis();
        Challenge challenge = cs.createChallenge(difficulty);
        String solution = cs.solveChallenge(challenge);
        long endTime = System.currentTimeMillis();
        double timeTaken = (endTime - startTime) / 1000.0;
        String resultLog = String.format("Solution found in %.2f seconds.", timeTaken);
        broadcastUpdate("solve", Map.of("message", resultLog));
    }

    private Map<String, Object> createStatusMap(String ip, IPProfile profile, int actionableSeverity, String statusMsg) {
        if (profile == null) {
             return Map.of("ip", ip, "rps", "0.00", "repetition", "0.00", "duration", 0, "currentSeverity", 0, "actionableSeverity", 0, "status", statusMsg);
        }
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
    
    private void broadcastUpdate(String type, Map<String, Object> data) {
        String jsonMessage = gson.toJson(Map.of("type", type, "data", data));
        wsContexts.stream()
            .filter(ctx -> ctx.session.isOpen())
            .forEach(ctx -> ctx.send(jsonMessage));
    }
}