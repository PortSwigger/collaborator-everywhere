package burp;

import com.sun.xml.internal.messaging.saaj.util.Base64;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Scanner;

public class BurpExtender implements IBurpExtender {
    private static final String name = "Collaborator Everywhere";
    private static final String version = "0.11";

    // provides potentially useful info but increases memory usage
    static final boolean SAVE_RESPONSES = false;


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
        String severity = "High";

        String rawDetail = interaction.getProperty("request");
        if (rawDetail == null) {
            rawDetail = interaction.getProperty("conversation");
        }

        if (rawDetail == null) {
            severity = "Medium";
            rawDetail = interaction.getProperty("raw_query");
        }

        String message = "The collaborator was contacted by <b>" + interaction.getProperty("client_ip") +"</b>";

        try {
            long interactionTime = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss z").parse(interaction.getProperty("time_stamp")).getTime();
            long mill = interactionTime - metaReq.getTimestamp();
            int seconds = (int) (mill / 1000) % 60;
            int minutes = (int) ((mill / (1000 * 60)) % 60);
            int hours = (int) ((mill / (1000 * 60 * 60)) % 24);
            message += " after a delay of <b>" + String.format("%02d:%02d:%02d", hours, minutes, seconds) + "</b>:<br/><br/>";
        }
        catch (java.text.ParseException e) {
            message += e.toString();
        }

        if (collab.isClientIP(interaction.getProperty("client_ip"))) {
            message += "<b>This interaction appears to have been issued by your IP address</b><br/><br/>";
            severity = "Low";
        }

        message += "<pre>    "+Base64.base64Decode(rawDetail).replace("<", "&lt;").replace("\n", "\n    ")+"</pre>";

        message += "The payload was sent at "+new Date(metaReq.getTimestamp()).toString() + " and received on " + interaction.getProperty("time_stamp") +"<br/><br/>";

        Utilities.callbacks.addScanIssue(
                new CustomScanIssue(req.getHttpService(), req.getUrl(), new IHttpRequestResponse[]{req}, "Collaborator Pingback ("+interaction.getProperty("type")+"): "+type, message+interaction.getProperties().toString(), severity, "Certain", "Panic"));

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
    private HashSet<String> client_ips;
    private int count = 0;

    Correlator() {
        idToRequestID = new HashMap<>();
        requests = new HashMap<>();
        idToType = new HashMap<>();
        burpIdToRequestID = new HashMap<>();
        collab = Utilities.callbacks.createBurpCollaboratorClientContext();
        client_ips = new HashSet<>();

        try {
            String pollPayload = collab.generatePayload(true);
            Utilities.callbacks.makeHttpRequest(pollPayload, 80, false, ("GET / HTTP/1.1\r\nHost: " + pollPayload + "\r\n\r\n").getBytes());
            for (IBurpCollaboratorInteraction interaction: collab.fetchCollaboratorInteractionsFor(pollPayload)) {
                client_ips.add(interaction.getProperty("client_ip"));
            }
            Utilities.out("Calculated your IPs: "+ client_ips.toString());
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

    boolean isClientIP(String ip){
        return client_ips.contains(ip);
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
    HashSet<String[]> injectionPoints = new HashSet<>();


    Injector(Correlator collab) {
        this.collab = collab;

        Scanner s = new Scanner(getClass().getResourceAsStream("/injections"));
        while (s.hasNext()) {
            String injection = s.next();
            if (injection.charAt(0) == '#') {
                continue;
            }
            injectionPoints.add(injection.split(",", 2));
        }
        s.close();

    }

    public byte[] injectPayloads(byte[] request, Integer requestCode) {

        for (String[] injection: injectionPoints) {
            switch ( injection[0] ){
                case "param":
                    IParameter param = Utilities.helpers.buildParameter(injection[1], "http://"+collab.generateCollabId(requestCode, injection[1]+" param"), IParameter.PARAM_URL);
                    request = Utilities.helpers.removeParameter(request, param);
                    request = Utilities.helpers.addParameter(request, param);
                    break;

                case "email":
                    request = Utilities.addOrReplaceHeader(request, injection[1], "user@"+collab.generateCollabId(requestCode, injection[1]));
                    break;
                case "url":
                    request = Utilities.addOrReplaceHeader(request, injection[1], "http://"+collab.generateCollabId(requestCode, injection[1])+"/");
                    break;
                case "domain":
                    request = Utilities.addOrReplaceHeader(request, injection[1], collab.generateCollabId(requestCode, injection[1]));
                    break;
                default:
                    Utilities.out("Unrecognised injection type: " + injection[0]);
            }
            
        }

        return request;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage proxyMessage) {
        if (!messageIsRequest) {
            if (BurpExtender.SAVE_RESPONSES) {
                collab.updateResponse(proxyMessage.getMessageReference(), proxyMessage.getMessageInfo());
            }
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