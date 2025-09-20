package com.jaradat.ddosmitigator.detection;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class PolicyManager {

    private List<PolicyRule> rules;

    // The constructor is called when a new PolicyManager is created.
    public PolicyManager() {
        loadPolicies("config.json");
    }

    /**
     * Reads and parses the specified JSON file from the resources folder.
     */
    private void loadPolicies(String fileName) {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(fileName)) {
            if (is == null) {
                System.err.println("Policy file not found: " + fileName);
                this.rules = Collections.emptyList(); // Assign an empty list to avoid errors
                return;
            }
            
            InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8);

            // Use Gson to parse the JSON structure into our Java objects
            Gson gson = new Gson();
            Type type = new TypeToken<Map<String, List<PolicyRule>>>() {}.getType();
            Map<String, List<PolicyRule>> data = gson.fromJson(reader, type);
            
            this.rules = data.get("policies");

            System.out.println("Successfully loaded " + rules.size() + " policies.");

        } catch (Exception e) {
            e.printStackTrace(); // Print the error for debugging
            this.rules = Collections.emptyList();
        }
    }

    /**
     * Allows other parts of the program to get the loaded rules.
     */
    public List<PolicyRule> getRules() {
        return this.rules;
    }
}