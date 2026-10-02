package phishingdetector;

public class PhishingDetector {

    // Rule 1: Check if URL uses HTTP
    public static boolean usesHttp(String url) {
        return url.startsWith("http://");
    }

    // Rule 2: Check if URL contains an IP address
    public static boolean hasIPAddress(String url) {

        String ipPattern =
                ".*\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b.*";

        return url.matches(ipPattern);
    }

    // Rule 3: Check if URL contains @ symbol
    public static boolean hasAtSymbol(String url) {
        return url.contains("@");
    }

    // Rule 4: Check for too many subdomains
    public static boolean hasTooManySubdomains(String url) {

        String[] parts = url.split("\\.");

        return parts.length > 4;
    }

    // Rule 5: Check for too many hyphens
    public static boolean hasTooManyHyphens(String url) {

        int count = 0;

        for (int i = 0; i < url.length(); i++) {

            if (url.charAt(i) == '-') {
                count++;
            }
        }

        return count > 3;
    }
    
    public static String[] getSuspiciousWords(String url) {

        String[] suspiciousWords = {
            "login",
            "verify",
            "verification",
            "account",
            "update",
            "password",
            "secure",
            "bank"
        };

        String[] foundWords = new String[suspiciousWords.length];

        int count = 0;

        for (String word : suspiciousWords) {

            if (url.toLowerCase().contains(word)) {

                foundWords[count] = word;

                count++;
            }
        }

        String[] result = new String[count];

        for (int i = 0; i < count; i++) {

            result[i] = foundWords[i];
        }

        return result;
    }
    
    // Rule 6: Check if URL is unusually long
    public static boolean isLongURL(String url) {

        return url.length() > 75;
    }
    
    public static int calculateRiskScore(String url) {

        int riskScore = 0;

        // Rule 1: HTTP
        if (usesHttp(url)) {
            riskScore = riskScore + 10;
        }

        // Rule 2: IP address
        if (hasIPAddress(url)) {
            riskScore = riskScore + 25;
        }

        // Rule 3: @ symbol
        if (hasAtSymbol(url)) {
            riskScore = riskScore + 20;
        }

        // Rule 4: Suspicious words
        String[] foundWords = getSuspiciousWords(url);

        for (String word : foundWords) {
            riskScore = riskScore + 5;
        }

        // Rule 5: Long URL
        if (isLongURL(url)) {
            riskScore = riskScore + 10;
        }

        // Rule 6: Too many subdomains
        if (hasTooManySubdomains(url)) {
            riskScore = riskScore + 10;
        }

        // Rule 7: Too many hyphens
        if (hasTooManyHyphens(url)) {
            riskScore = riskScore + 10;
        }

        return riskScore;
    }
    
    // Determine risk level
    public static String getRiskLevel(int riskScore) {

        if (riskScore <= 30) {
            return "LOW RISK";
        } 
        else if (riskScore <= 60) {
            return "MEDIUM RISK";
        } 
        else {
            return "HIGH RISK";
        }
    }
    
 // Give recommendation based on risk level
    public static String getRecommendation(int riskScore) {

        if (riskScore <= 30) {
            return "The URL appears to have low risk. Still verify the website before entering personal information.";
        }
        else if (riskScore <= 60) {
            return "Be cautious. The URL contains some suspicious characteristics. Verify the website before proceeding.";
        }
        else {
            return "High risk detected. Avoid opening the URL or entering any personal information.";
        }
    }
    
}