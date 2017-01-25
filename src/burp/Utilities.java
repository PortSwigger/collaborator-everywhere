package burp;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
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

    public static byte[] replaceRequestLine(byte[] request, String payload) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            int i = 0;
            while (request[i++] != '\n') {
            }

            outputStream.write(payload.getBytes());
            outputStream.write(Arrays.copyOfRange(request, i-2, request.length));
        }
        catch (IOException e) {
                throw new RuntimeException("Request creation unexpectedly failed");
        }
        return outputStream.toByteArray();
    }

    public static String getPath(byte[] request) {
        int i = 0;
        String out = "";
        while (request[i++] != ' ') {
        }
        while (request[i] != ' ' && request[i] != '?') {
            out += (char) request[i];
            i++;
        }
        return out.substring(0, out.lastIndexOf('/'));
    }


    public static String getHeader(byte[] request, String header) {
        int[] offsets = getHeaderOffsets(request, header);
        String value = helpers.bytesToString(Arrays.copyOfRange(request, offsets[1], offsets[2]));
        return value;
    }

    public static int[] getHeaderOffsets(byte[] request, String header) {
        int i = 0;
        int end = request.length;
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

            if (i + 2 < end && request[i] == '\r' && request[i + 1] == '\n') {
                break;
            }

            String header_str = helpers.bytesToString(header_name);

            if (header.equals(header_str)) {
                int[] offsets = {line_start, headerValueStart, i - 2};
                return offsets;
            }
        }
        return null;
    }

    // this is why hackxor2 is using python
    // todo refactor to use getHeaderOffsets
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

                if(i+2<end && request[i] == '\r' && request[i+1] == '\n') {
                    outputStream.write(Arrays.copyOfRange(request, 0, i));
                    outputStream.write(helpers.stringToBytes(header + ": " + value+"\r\n"));
                    outputStream.write(Arrays.copyOfRange(request, i, end));
                    return outputStream.toByteArray();
                }

                String header_str = helpers.bytesToString(header_name);

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

class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;
    private String remediation;

    CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.confidence = confidence;
        this.remediation = remediation;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public String getHost() {
        return null;
    }

    @Override
    public int getPort() {
        return 0;
    }

    @Override
    public String getProtocol() {
        return null;
    }

}