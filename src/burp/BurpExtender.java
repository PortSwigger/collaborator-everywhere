package burp;

import burp.*;
import com.sun.xml.internal.messaging.saaj.util.Base64;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;

public class BurpExtender implements IBurpExtender {
    private static final String name = "Collaborator Everywhere";
    private static final String version = "0.1";


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        new Utilities(callbacks);
        callbacks.setExtensionName(name);

        Correlator collab = new Correlator();

        Monitor collabMonitor = new Monitor(collab);
        new Thread(collabMonitor).start();
        callbacks.registerExtensionStateListener(collabMonitor);

        callbacks.registerProxyListener(new Injector(collab));

        Utilities.out("Loaded " + name + " v" + version);
    }
}

class Monitor implements Runnable, IExtensionStateListener {
    private Correlator collab;
    private boolean stop = false;

    Monitor(Correlator collab) {
        this.collab = collab;
    }

    public void extensionUnloaded() {
        Utilities.out("Extension unloading - triggering abort");
        stop = true;
        Thread.currentThread().interrupt();
    }

    public void run() {
        try {
            while (!stop) {
                Thread.sleep(10000);
                Utilities.out("Polling!");

                collab.poll().forEach(e -> processInteraction(e));
            }
        }
        catch (InterruptedException e) {
            Utilities.out("Interrupted");
        }

        Utilities.out("Shutting down collaborator monitor thread");
    }

    private void processInteraction(IBurpCollaboratorInteraction interaction) {
        String id = interaction.getProperty("interaction_id");
        Utilities.out("Got an interaction:"+interaction.getProperties());
        MetaRequest metaReq = collab.getRequest(id);
        IHttpRequestResponse req = metaReq.getRequest();
        String type = collab.getType(id);

        String detail = interaction.getProperty("request");
        if (detail == null) {
            detail = interaction.getProperty("conversation");
        }

        if (detail == null) {
            detail = interaction.getProperty("raw_query");
        }

        String message = "The payload was sent at "+new Date(metaReq.getTimestamp()).toString() + " and received on " + interaction.getProperty("time_stamp");

        try {
            long interactionTime = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss z").parse(interaction.getProperty("time_stamp")).getTime();
            long mill = interactionTime - metaReq.getTimestamp();
            int seconds = (int) (mill / 1000) % 60;
            int minutes = (int) ((mill / (1000 * 60)) % 60);
            int hours = (int) ((mill / (1000 * 60 * 60)) % 24);
            message += " indicating a delay of " + String.format("%d hours, %d minutes and %d seconds.", hours, minutes, seconds) + "<br/><br/>";
        }
        catch (java.text.ParseException e) {
            message += e.toString();
        }

        if (interaction.getProperty("client_ip").equals(collab.getClientIp())) {
            message += "This interaction appears to have been issued by your IP address<br/>";
        }

        detail = message + "<pre>"+Base64.base64Decode(detail).replace("<", "&lt;")+"</pre><br/><br/>";


        Utilities.callbacks.addScanIssue(
                new CustomScanIssue(req.getHttpService(), req.getUrl(), new IHttpRequestResponse[]{req}, "Collaborator Pingback ("+interaction.getProperty("type")+"): "+type, detail+interaction.getProperties().toString(), "Information", "Certain", "Panic"));

    }

}

class MetaRequest {
    private IHttpRequestResponse request;
    private int burpId;
    private long timestamp;

    MetaRequest(IInterceptedProxyMessage proxyMessage) {
        request = proxyMessage.getMessageInfo();
        burpId = proxyMessage.getMessageReference();
        timestamp = System.currentTimeMillis();
    }

    public void addResponse(byte[] response) {
        request.setResponse(response);
    }

    public void overwriteRequest(IHttpRequestResponse response) {
        request = response;
    }

    public IHttpRequestResponse getRequest() {
        return request;
    }

    public int getBurpId() {
        return burpId;
    }

    public long getTimestamp() {
        return timestamp;
    }
}

class Correlator {

    private IBurpCollaboratorClientContext collab;
    private HashMap<String, Integer> idToRequestID;
    private HashMap<String, String> idToType;
    private HashMap<Integer, MetaRequest> requests;
    private HashMap<Integer, Integer> burpIdToRequestID;
    private String ip = "";
    private int count = 0;

    Correlator() {
        idToRequestID = new HashMap<>();
        requests = new HashMap<>();
        idToType = new HashMap<>();
        burpIdToRequestID = new HashMap<>();
        collab = Utilities.callbacks.createBurpCollaboratorClientContext();

        try {
            String pollPayload = collab.generatePayload(true);
            Utilities.callbacks.makeHttpRequest(pollPayload, 80, false, ("GET / HTTP/1.1\r\nHost: " + pollPayload + "\r\n\r\n").getBytes());
            for (IBurpCollaboratorInteraction interaction: collab.fetchCollaboratorInteractionsFor(pollPayload)) {
                if (interaction.getProperty("type").equals("HTTP")) {
                    ip = interaction.getProperty("client_ip");
                }
            }
            Utilities.out("Calculated your IP: "+ip);
        }
        catch (NullPointerException e) {
            Utilities.out("Unable to calculate client IP - collaborator may not be functional");
        }

    }

    java.util.List<IBurpCollaboratorInteraction> poll() {
        return collab.fetchAllCollaboratorInteractions();
    }

    Integer addRequest(MetaRequest req) {
        Integer requestCode = count++;
        requests.put(requestCode, req);
        burpIdToRequestID.put(req.getBurpId(), requestCode);
        return requestCode;
    }

    String generateCollabId(int requestCode, String type) {
        String id = collab.generatePayload(false);
        idToRequestID.put(id, requestCode);
        idToType.put(id, type);
        return id+"."+collab.getCollaboratorServerLocation();
    }

    String getLocation() {
        return collab.getCollaboratorServerLocation();
    }

    String getClientIp(){
        return ip;
    }

    MetaRequest getRequest(String collabId) {
        int requestId = idToRequestID.get(collabId);
        return requests.get(requestId);
    }

    void updateResponse(int burpId, IHttpRequestResponse response) {
        if (burpIdToRequestID.containsKey(burpId)) {
            requests.get(burpIdToRequestID.get(burpId)).overwriteRequest(response);
        }
    }

    String getType(String collabid) {
        return idToType.get(collabid);
    }
}

class Injector implements IProxyListener {

    private Correlator collab;

    Injector(Correlator collab) {
        this.collab = collab;
    }

    public byte[] injectPayloads(byte[] request, Integer requestCode) {
        byte[] fixed;

        IParameter param = Utilities.helpers.buildParameter("u", "http://"+collab.generateCollabId(requestCode, "u param")+"/u", IParameter.PARAM_URL);
        fixed = Utilities.helpers.addParameter(request, param);

        fixed = Utilities.addOrReplaceHeader(fixed, "User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36 http://"+collab.generateCollabId(requestCode, "User-Agent")+"/ua");

        fixed = Utilities.addOrReplaceHeader(fixed, "Referer", "http://"+collab.generateCollabId(requestCode, "Referer")+"/ref");

        fixed = Utilities.addOrReplaceHeader(fixed, "X-Wap-Profile", "http://"+collab.generateCollabId(requestCode, "WAP")+"/wap.xml");

        fixed = Utilities.addOrReplaceHeader(fixed, "Contact", "user@"+collab.generateCollabId(requestCode, "Contact"));

        fixed = Utilities.addOrReplaceHeader(fixed, "X-Arbitrary", "http://"+collab.generateCollabId(requestCode, "Arbitrary")+"/");

        //fixed = Utilities.addOrReplaceHeader(fixed, "X-Forwarded-Host", collab.generateCollabId(requestCode, "XFH"));

        fixed = Utilities.addOrReplaceHeader(fixed, "Origin", "http://"+collab.generateCollabId(requestCode, "Origin"));

        return fixed;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage proxyMessage) {
        if (!messageIsRequest) {
            collab.updateResponse(proxyMessage.getMessageReference(), proxyMessage.getMessageInfo());
            return;
        }

        IHttpRequestResponse messageInfo = proxyMessage.getMessageInfo();

        // don't tamper with requests already heading to the collaborator
        if (messageInfo.getHost().endsWith(collab.getLocation())) {
            return;
        }

        MetaRequest req = new MetaRequest(proxyMessage);
        Integer requestCode = collab.addRequest(req);

        messageInfo.setRequest(injectPayloads(messageInfo.getRequest(), requestCode));


    }

}