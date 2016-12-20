package burp;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Collections;


public class Utilities {
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    public Utilities(final IBurpExtenderCallbacks incallbacks) {
        callbacks = incallbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
    }

    public static void out(String message) {
        stdout.println(message);
    }
    public static void err(String message) {
        stderr.println(message);
    }


    public static byte[] addOrReplaceHeader(byte[] request, String header, String value) {
        try {
            int i = 0;
            int end = request.length;
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            while (i < end) {
                int line_start = i;
                while (i < end && request[i++] != ' ') {
                }
                byte[] header_name = Arrays.copyOfRange(request, line_start, i - 2);
                int headerValueStart = i;
                while (i < end && request[i++] != '\n') {
                }
                if (i == end) {
                    break;
                }

                String header_str = helpers.bytesToString(header_name);
                out(header_str);

                if (header.equals(header_str)) {

                    outputStream.write(Arrays.copyOfRange(request, 0, headerValueStart));
                    outputStream.write(helpers.stringToBytes(value));
                    outputStream.write(Arrays.copyOfRange(request, i-2, end));
                    return outputStream.toByteArray();
                }
            }
            outputStream.write(Arrays.copyOfRange(request, 0, end-2));
            outputStream.write(helpers.stringToBytes(header + ": " + value+"\r\n\r\n"));
            return outputStream.toByteArray();

        } catch (IOException e) {
            throw new RuntimeException("Request creation unexpectedly failed");
        }
    }

}
