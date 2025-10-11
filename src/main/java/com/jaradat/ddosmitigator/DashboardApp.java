package com.jaradat.ddosmitigator;

import java.util.concurrent.ConcurrentLinkedQueue;

import com.jaradat.ddosmitigator.challenge.ChallengeService;
import com.jaradat.ddosmitigator.detection.PolicyManager; // Import the new service
import com.jaradat.ddosmitigator.mitigation.BlocklistService;
import com.jaradat.ddosmitigator.simulator.TrafficSimulator;

import io.javalin.Javalin;
import io.javalin.websocket.WsContext;

public class DashboardApp {

    private static final ConcurrentLinkedQueue<WsContext> wsContexts = new ConcurrentLinkedQueue<>();

    public static void main(String[] args) {
        // --- Initialize all the core components of our system ---
        PolicyManager policyManager = new PolicyManager();
        TrafficSimulator simulator = new TrafficSimulator();
        ChallengeService challengeService = new ChallengeService();
        BlocklistService blocklistService = new BlocklistService(); // Create the new service

        // --- Start the web server ---
        Javalin app = Javalin.create(config -> {
            config.staticFiles.add("/public"); 
        }).start(7070);

        // --- Handle WebSocket connections ---
        app.ws("/dashboard-updates", ws -> {
            ws.onConnect(ctx -> {
                System.out.println("[WebSocket] New dashboard connected: " + ctx.sessionId());
                wsContexts.add(ctx);
                
                // Pass the new blocklist service to the DemoRunner
                DemoRunner demo = new DemoRunner(policyManager, simulator, challengeService, blocklistService, wsContexts);
                new Thread(demo::run).start();
            });

            ws.onClose(ctx -> {
                System.out.println("[WebSocket] Dashboard disconnected: " + ctx.sessionId());
                wsContexts.remove(ctx);
            });
        });

        System.out.println("Dashboard is running at: http://localhost:7070");
        System.out.println("Open this URL in your browser to see the live demo.");
    }
}