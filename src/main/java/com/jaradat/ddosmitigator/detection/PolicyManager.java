package com.jaradat.ddosmitigator.detection;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Comparator; // <-- ADD THIS IMPORT
import java.util.List;
import java.util.Map; 

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class PolicyManager {

    private List<PolicyRule> rules;

    public PolicyManager() {
        loadPolicies("config.json");
        // ADD THIS BLOCK TO SORT THE RULES
        if (this.rules != null) {
            // This sorts the list so that Level 1 is at the start and Level 4 is at the end.
            this.rules.sort(Comparator.comparingInt(rule -> rule.level));
        }
    }

    private void loadPolicies(String fileName) {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(fileName)) {
            if (is == null) {
                System.err.println("Policy file not found: " + fileName);
                this.rules = Collections.emptyList();
                return;
            }
            
            InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8);
            Gson gson = new Gson();
            Type type = new TypeToken<Map<String, List<PolicyRule>>>() {}.getType();
            Map<String, List<PolicyRule>> data = gson.fromJson(reader, type);
            this.rules = data.get("policies");

            System.out.println("Successfully loaded " + rules.size() + " policies.");

        } catch (Exception e) {
            e.printStackTrace();
            this.rules = Collections.emptyList();
        }
    }

    public List<PolicyRule> getRules() {
        return this.rules;
    }
}