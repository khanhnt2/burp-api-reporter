package burp;

import org.apache.commons.codec.binary.Base64;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.logging.Logger;

public class TypeInformation {
    public static final String REQUEST_URL = "REQUEST_URL";
    public static final String REQUEST_METHOD = "REQUEST_METHOD";
    public static final String REQUEST_PARAMS = "REQUEST_PARAMS";
    public static final String REQUEST_PATH = "REQUEST_PATH";
    public static final String RESPONSE_BODY = "RESPONSE_BODY";
    public static final String REQUEST_BYTES = "REQUEST_BYTES";
    public static final String REQUEST_PORT = "REQUEST_PORT";
    public static final String REQUEST_HOST = "REQUEST_HOST";
    public static final String REQUEST_PROTOCOL = "REQUEST_PROTOCOL";
    public static final String DATE_NOW = "DATE_NOW";
    private final IRequestInfo req;
    private final IResponseInfo res;
    private final IHttpRequestResponse message;
    private final IExtensionHelpers helpers;
    private Logger logger = Logger.getLogger(BurpExtender.EXTENSION_NAME);
    private final URL url;

    public TypeInformation(IHttpRequestResponse message, IExtensionHelpers helpers) {
        this.helpers = helpers;
        this.message = message;
        this.req = helpers.analyzeRequest(message);
        this.url = this.req.getUrl();
        if (message.getResponse() != null) {
            this.res = helpers.analyzeResponse(message.getResponse());
        }
        else {
            this.res = null;
        }
    }

    public String getValue(String type) {
        String result = "";
        if (type == null || type.isEmpty()) {
//            logger.info("Type is null or empty");
            return "";
        }
        try {
            // Use reflection to get method and invoke it
            Field field = this.getClass().getField(type);
            String methodName = field.get(this).toString();
            Method method = this.getClass().getDeclaredMethod(methodName);
            logger.info("Invoking method " + methodName);
            result = method.invoke(this).toString();
        } catch (NoSuchFieldException ex) {
            logger.severe("NoSuchFieldException: couldn't find " + type + " " + this.url.toString());
        } catch (IllegalArgumentException ex) {
            logger.severe("IllegalArgumentException" + " " + this.url.toString());
        } catch (IllegalAccessException ex) {
            logger.severe("IllegalAccessException: cannot access " + type + " " + this.url.toString());
        } catch (NoSuchMethodException ex) {
            logger.severe("NoSuchMethodException: " + type + " is not a method" + " " + this.url.toString());
        } catch (InvocationTargetException ex) {
            logger.severe("InvocationTargetException: calling " + type + " error" + " " + this.url.toString());
        } catch (ExceptionInInitializerError ex) {
            logger.severe("ExceptionInInitializerError type " + type + " " + this.url.toString());
        } catch (NullPointerException ex) {
            logger.severe("NullPointerException type " + type + " " + this.url.toString());
        } catch (Exception ex) {
            logger.severe("Unknown exception " + ex.getMessage() + " " + this.url.toString());
        }
        return result;
    }

    private String REQUEST_URL() {
        return this.url.toString();
    }

    private String REQUEST_PATH() {
        return this.url.getPath();
    }

    private String REQUEST_METHOD() {
        return this.req.getMethod();
    }

    private String DATE_NOW() {
        LocalDate date = LocalDate.now();
        return date.format(DateTimeFormatter.ofPattern("dd/MM/yyyy"));
    }

    private String REQUEST_BYTES() {
        return Base64.encodeBase64String(this.message.getRequest());
    }

    private String REQUEST_HOST() {
        return this.message.getHttpService().getHost();
    }

    private String REQUEST_PORT() {
        return String.valueOf(this.message.getHttpService().getPort());
    }

    private String REQUEST_PROTOCOL() {
        return this.message.getHttpService().getProtocol();
    }

    private String REQUEST_PARAMS() {
//        logger.info(String.valueOf(this.req.getBodyOffset()) + " - " + this.message.getRequest().length);
        if (this.url.getQuery() == null) {
            String request = new String(this.message.getRequest());
            return request.substring(this.req.getBodyOffset());
        }

        return this.url.getQuery();
    }

    private String RESPONSE_BODY() {
        // Check the body is empty
        if (this.res == null || this.message.getResponse() == null)
            return "";
        if (this.res.getBodyOffset() == this.message.getResponse().length)
            return "";

        String response = new String(this.message.getResponse());
        return response.substring(this.res.getBodyOffset());
    }
}

