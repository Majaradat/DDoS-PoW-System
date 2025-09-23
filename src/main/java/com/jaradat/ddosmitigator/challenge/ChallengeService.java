package com.jaradat.ddosmitigator.challenge;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class ChallengeService {

    private final MessageDigest digest;

    public ChallengeService() {
        try {
            // Using SHA-256 for our cryptographic hash
            this.digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // This should not happen with a standard algorithm like SHA-256
            throw new RuntimeException("Could not initialize hashing algorithm", e);
        }
    }

    /**
     * Creates a new PoW challenge with a random string and a given difficulty.
     */
    public Challenge createChallenge(int difficulty) {
        String randomString = UUID.randomUUID().toString();
        return new Challenge(randomString, difficulty);
    }

    /**
     * Verifies if a given nonce is the correct solution for a challenge.
     * This is the real, non-simulated cryptographic verification.
     */
    public boolean verifyChallenge(Challenge challenge, String nonce) {
        String target = "0".repeat(challenge.getDifficulty());
        String dataToHash = challenge.getChallengeString() + nonce;

        byte[] hashBytes = digest.digest(dataToHash.getBytes(StandardCharsets.UTF_8));
        String hashString = toHexString(hashBytes);

        return hashString.startsWith(target);
    }

    /**
     * Helper method to convert a byte array (the hash) into a hexadecimal string.
     */
    private String toHexString(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}