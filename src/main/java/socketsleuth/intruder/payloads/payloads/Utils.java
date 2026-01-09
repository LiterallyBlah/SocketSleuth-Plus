package socketsleuth.intruder.payloads.payloads;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Utils {

    public static java.util.List<String> extractPayloadPositions(String input) {
        java.util.List<String> extractedTextList = new ArrayList<>();
        Pattern pattern = Pattern.compile("§(.*?)§");
        Matcher matcher = pattern.matcher(input);

        int lastEnd = 0;
        while (matcher.find()) {
            int start = matcher.start(1);
            int end = matcher.end(1);

            if (start < lastEnd) {
                throw new IllegalStateException("Unclosed match found.");
            }

            lastEnd = end;
            extractedTextList.add(matcher.group(1));
        }

        return extractedTextList;
    }

    private Utils() {}
}
