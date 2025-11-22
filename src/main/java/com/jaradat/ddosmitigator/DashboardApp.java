package com.jaradat.ddosmitigator;

import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import com.google.gson.Gson;
import com.jaradat.ddosmitigator.challenge.ChallengeService;
import com.jaradat.ddosmitigator.detection.PolicyManager;
import com.jaradat.ddosmitigator.mitigation.BlocklistService;
import com.jaradat.ddosmitigator.simulator.TrafficSimulator;

import io.javalin.Javalin;
import io.javalin.websocket.WsContext;

public class DashboardApp {

    private static final ConcurrentLinkedQueue<WsContext> wsContexts = new ConcurrentLinkedQueue<>();
    private static final Gson gson = new Gson();

    public static void main(String[] args) {
        // --- Initialize Core Components ---
        PolicyManager policyManager = new PolicyManager();
        TrafficSimulator simulator = new TrafficSimulator();
        ChallengeService challengeService = new ChallengeService();
        BlocklistService blocklistService = new BlocklistService();

        // --- Start Web Server ---
        Javalin app = Javalin.create(config -> {
            config.staticFiles.add("/public"); 
        }).start(7070);

        // --- Handle WebSocket (Command & Control) ---
        app.ws("/dashboard-updates", ws -> {
            
            ws.onConnect(ctx -> {
                System.out.println("[WebSocket] Dashboard connected: " + ctx.sessionId());
                wsContexts.add(ctx);
            });

            ws.onMessage(ctx -> {
                // 1. Parse the incoming command from the Dashboard
                String msg = ctx.message();
                System.out.println("[CMD] Received: " + msg);
                
                try {
                    Map<String, Object> command = gson.fromJson(msg, Map.class);
                    String action = (String) command.get("action");
                    
                    if ("start_simulation".equals(action)) {
                        String mode = (String) command.get("mode");
                        // Handle difficulty being a Double (Gson default for numbers)
                        int difficulty = ((Double) command.getOrDefault("difficulty", 5.0)).intValue();

                        // 2. Run the specific scenario in a separate thread to avoid freezing the server
                        DemoRunner runner = new DemoRunner(policyManager, simulator, challengeService, blocklistService, wsContexts);
                        new Thread(() -> runner.runScenario(mode, difficulty)).start();
                    }
                } catch (Exception e) {
                    System.err.println("Error parsing command: " + e.getMessage());
                }
            });

            ws.onClose(ctx -> {
                System.out.println("[WebSocket] Dashboard disconnected: " + ctx.sessionId());
                wsContexts.remove(ctx);
            });
        });

        System.out.println("--------------------------------------------------");
        System.out.println("DDoS SOC Dashboard running at: http://localhost:7070");
        System.out.println("--------------------------------------------------");
    }
}