#include "WiFi.h"
#include "SSLLineNotify.h"
#include "errno.h"

extern "C" {
    #include "wl_definitions.h"
    #include "wl_types.h"
    #include "string.h"
}


char HOST[] = "notify-api.line.me"; //# 伺服器網址，不可動
int PORT = 443;
char API_URL[] = "/api/notify"; //# 連線對象URL，不可動
//char Linetoken[] = "Wp97BOXf2BKyiZZbyfs8XrX6cN2xvfeFnxUA7sM7kco"; //# 資料平台裝置的存取權限碼

String CopyHTTPS = "POST /api/notify HTTP/1.1\r\nHost: notify-api.line.me\r\nAuthorization: Bearer Wp97BOXf2BKyiZZbyfs8XrX6cN2xvfeFnxUA7sM7kco\r\nContent-Length: 134\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"message\"\r\n\r\n111\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n";

/*
char *print_utf8_zh_code(char *words)
{
	char temp[4];
	for (int i = 0; i < (int)strlen(words); i++) {
		sprintf(temp,"%02X ",words[i]);
		Serial.print(temp);
	}
	//Serial.println();
}
*/
LineNotify::LineNotify() {
    _is_connected = false;
    _sock = -1;

    sslclient.socket = -1;
    sslclient.ssl = NULL;
    sslclient.recvTimeout = 3000;

    sslclient.ssl = NULL;
    sslclient.conf = NULL;

    _rootCABuff = NULL;
    _cli_cert = NULL;
    _cli_key = NULL;
    _psKey = NULL;
    _pskIdent = NULL;
    _sni_hostname = NULL;
}

LineNotify::LineNotify(uint8_t sock) {
    _sock = sock;

    sslclient.socket = -1;
    sslclient.ssl = NULL;
    sslclient.recvTimeout = 3000;

//    if(sock >= 0) {
//        _is_connected = true;
//    }
    _is_connected = true;

    _rootCABuff = NULL;
    _cli_cert = NULL;
    _cli_key = NULL;
    _psKey = NULL;
    _pskIdent = NULL;
    _sni_hostname = NULL;
}

uint8_t LineNotify::connected() {
    if (sslclient.socket < 0) {
        _is_connected = false;
        return 0;
    } else {
        if (_is_connected) {
            return 1;
        } else {
            stop();
            return 0;
        }
    }
}

int LineNotify::available() {
    int ret = 0;
    int err;

    if (!_is_connected) {
        return 0;
    }
    if (sslclient.socket >= 0) {
        ret = ssldrv.availData(&sslclient);
        if (ret > 0) {
            return 1;
        } else {
            err = ssldrv.getLastErrno(&sslclient);
            if ((err > 0) && (err != EAGAIN)) {
                _is_connected = false;
            }
        }
        return 0;
    }

    return 0;
}

int LineNotify::read() {
    int ret;
    int err;
    uint8_t b[1];

    if (!available()) {
        return -1;
    }

    ret = ssldrv.getData(&sslclient, b);
    if (ret > 0) {
        return b[0];
    } else {
        err = ssldrv.getLastErrno(&sslclient);
        if ((err > 0) && (err != EAGAIN)) {
            _is_connected = false;
        }
    }
    return -1;
}

int LineNotify::read(uint8_t* buf, size_t size) {
    uint16_t _size = size;
    int ret;
    int err;

    ret = ssldrv.getDataBuf(&sslclient, buf, _size);
    if (ret <= 0) {
        err = ssldrv.getLastErrno(&sslclient);
        if ((err > 0) && (err != EAGAIN)) {
            _is_connected = false;
        }
    }
    return ret;
}

void LineNotify::stop() {

    if (sslclient.socket < 0) {
        return;
    }

    ssldrv.stopClient(&sslclient);
    _is_connected = false;

    sslclient.socket = -1;
    _sock = -1;
}

size_t LineNotify::write(uint8_t b) {
    return write(&b, 1);
}

size_t LineNotify::write(const uint8_t *buf, size_t size) {
    if (sslclient.socket < 0) {
        setWriteError();
        return 0;
    }
    if (size == 0) {
        setWriteError();
        return 0;
    }

    if (!ssldrv.sendData(&sslclient, buf, size)) {
        setWriteError();
        _is_connected = false;
        return 0;
    }

    return size;
}

LineNotify::operator bool() {
    return (sslclient.socket >= 0);
}

int LineNotify::connect(IPAddress ip, uint16_t port) {
    if (_psKey != NULL && _pskIdent != NULL)
        return connect(ip, port, _pskIdent, _psKey);
    return connect(ip, port, _rootCABuff, _cli_cert, _cli_key);
}

int LineNotify::connect(const char *host, uint16_t port) {
	printf("connect host\r\n");
    if (_sni_hostname == NULL) {
        _sni_hostname = (char*)host;
    }

    if (_psKey != NULL && _pskIdent != NULL)
        return connect(host, port, _pskIdent, _psKey);
    printf("connect host--\r\n");
    return connect(host, port, _rootCABuff, _cli_cert, _cli_key);
}

int LineNotify::connect(const char* host, uint16_t port, unsigned char* rootCABuff, unsigned char* cli_cert, unsigned char* cli_key) {
    IPAddress remote_addr;

    if (_sni_hostname == NULL) {
        _sni_hostname = (char*)host;
    }

    if (WiFi.hostByName(host, remote_addr)) {
        return connect(remote_addr, port, rootCABuff, cli_cert, cli_key);
    }
    return 0;
}

int LineNotify::connect(IPAddress ip, uint16_t port, unsigned char* rootCABuff, unsigned char* cli_cert, unsigned char* cli_key) {
    int ret = 0;

    ret = ssldrv.startClient(&sslclient, ip, port, rootCABuff, cli_cert, cli_key, NULL, NULL, _sni_hostname);

    if (ret < 0) {
        _is_connected = false;
        return 0;
    } else {
        _is_connected = true;
    }

    return 1;
}

int LineNotify::connect(const char *host, uint16_t port, unsigned char* pskIdent, unsigned char* psKey) {
    IPAddress remote_addr;

    if (_sni_hostname == NULL) {
        _sni_hostname = (char*)host;
    }

    if (WiFi.hostByName(host, remote_addr)) {
        return connect(remote_addr, port, pskIdent, psKey);
    }
    return 0;
}

int LineNotify::connect(IPAddress ip, uint16_t port, unsigned char* pskIdent, unsigned char* psKey) {
    int ret = 0;

    ret = ssldrv.startClient(&sslclient, ip, port, NULL, NULL, NULL, pskIdent, psKey, _sni_hostname);

    if (ret < 0) {
        _is_connected = false;
        return 0;
    } else {
        _is_connected = true;
    }

    return 1;
}

int LineNotify::peek() {
    uint8_t b;

    if (!available()) {
        return -1;
    }

    ssldrv.getData(&sslclient, &b, 1);

    return b;
}
void LineNotify::flush() {
    while (available()) {
        read();
    }
}

void LineNotify::multisend(char *msg, char *imageThumbnail, char *imageFullsize, char *imageFile, int stickerPackageId, int stickerId, bool notificationDisabled) {
	String header;
	String message_str="";
	String content_len2str;	
	//char test_msg[] = "\x31\x32\x33\x34\x35\x36";
	//int bundary_header_length = strlen(line_notify_str_24) + strlen(line_notify_bundary) + strlen(line_notify_str_18) + strlen(line_notify_str_19) + strlen(line_notify_str_25);
	//int bundary_end_length = strlen(line_notify_str_24) + strlen(line_notify_str_24) + strlen(line_notify_bundary) + strlen(line_notify_str_4);
	//printf("strlen(line_notify_bundary) %d, strlen(line_notify_str_18) %d\r\n", strlen(line_notify_bundary), strlen(line_notify_str_18));
	//printf("bundary_header_length %d, bundary_end_length %d, strlen(test_msg) = %d\r\n", bundary_header_length, bundary_end_length, String(test_msg).length());
	//content_len2str = String(String(msg).length() + bundary_end_length + bundary_header_length);
	content_len2str = String(137);
	
	message_str += line_notify_str_5;	//"POST /api/notify HTTP/1.1";
    message_str += line_notify_str_4;	//"\r\n"
    message_str += line_notify_str_11;	//"Host: "
    message_str += line_notify_str_1;	//"notify-api.line.me";
    message_str += line_notify_str_4;	//"\r\n"
    message_str += line_notify_str_7;	//"Authorization: Bearer ";
    message_str += _LineToken;			//Token
    message_str += line_notify_str_4;	//"\r\n"
    
    message_str += line_notify_str_47;	//"Content-Length: ";
    message_str += content_len2str;
    message_str += line_notify_str_4;	//"\r\n"
    
    message_str += line_notify_str_8;	//"Content-Type: multipart/form-data; boundary=";
    message_str += line_notify_bundary;
    message_str += line_notify_str_4;
    message_str += line_notify_str_4;
    //println(header);
    
    //body
    message_str += line_notify_str_24;
	message_str += line_notify_bundary;
	message_str += line_notify_str_4;
    
    message_str += line_notify_str_18;
    message_str += line_notify_str_19;
    message_str += line_notify_str_25;
    message_str += line_notify_str_4;
    message_str += line_notify_str_4;
	
	message_str += msg;
	message_str += line_notify_str_4;
	//end
	message_str += line_notify_str_24;
	message_str += line_notify_bundary;
	message_str += line_notify_str_24;
	message_str += line_notify_str_4;
	// Make a HTTP request:
	//println(message_str.c_str());
	println(message_str);
	
	//message_str = CopyHTTPS;
    printf("^^^^^^^^^^^^^^^^^^^^^^^^\r\n%s^^^^^^^^^^^^^^^^^^^^^^^^",  message_str.c_str());

    	
}

void LineNotify::send(char *msg, bool notificationDisabled) {
	String message_str;
	String content_len2str;
	//char utf8str[200];
	//*utf8str = print_utf8_zh_code(msg);
	
	if (notificationDisabled)
		content_len2str = String(34 + strlen(msg));		//34 = "message=" + "&notificationDisabled=" + "true"
	else
		content_len2str = String(35 + strlen(msg));		//35 = "message=" + "&notificationDisabled=" + "false"
	
	message_str += line_notify_str_5;	//"POST /api/notify HTTP/1.1";
    message_str += line_notify_str_4;	//"\r\n"
    message_str += line_notify_str_11;	//"Host: "
    message_str += line_notify_str_1;	//"notify-api.line.me";
    message_str += line_notify_str_4;	//"\r\n"
    message_str += line_notify_str_7;	//"Authorization: Bearer ";
    message_str += _LineToken;			//Token
    message_str += line_notify_str_4;	//"\r\n"
    //message_str += line_notify_str_14;	//"content-length: ";
    message_str += line_notify_str_47;	//"content-length: ";
    message_str += content_len2str;		//length
    message_str += line_notify_str_4;	//"\r\n"
    
    message_str += line_notify_str_17;	//"Content-Type: ";
    message_str += line_notify_str_69;	//"application/x-www-form-urlencoded";
    message_str += line_notify_str_4;	//"\r\n"
    message_str += line_notify_str_4;	//"\r\n"
    message_str += line_notify_str_19;	//"message"
    message_str += line_notify_str_70;	//"="
    
    message_str += msg;
    //message_str += full_message; 
    message_str += line_notify_str_71;
    message_str += line_notify_str_57;
    message_str += line_notify_str_70;
    if (notificationDisabled)
    {
    	message_str += line_notify_str_58;	//"true";
    }
    else
    {
    	message_str += line_notify_str_59;	//"false";
    }  
	  
    printf("------------------------\r\n%s\r\n------------------------\r\n", message_str.c_str());
    // Make a HTTP request:
    println(message_str);	
/*	
    message_str += "POST ";
    message_str += API_URL;
    message_str += " HTTP/1.1\r\n";
    message_str += "Host: ";
    message_str += HOST;
    message_str += "\r\n";
    message_str += "Authorization: Bearer ";
    message_str += _LineToken;
    message_str += "\r\n";
    message_str += "Content-Length: ";
    message_str += String(strlen(full_message));
    message_str += "\r\n";
    message_str += "Content-Type: application/x-www-form-urlencoded\r\n\r\n";
    message_str += full_message; 
    message_str += "\r\n";
    printf("msg %s\r\n", message_str.c_str());
    // Make a HTTP request:
    println(message_str);	
    */
}

void LineNotify::setLineToken(char *charLineToken) {
    _LineToken = charLineToken;
}

void LineNotify::setRootCA(unsigned char *rootCA) {
    _rootCABuff = rootCA;
}

void LineNotify::setClientCertificate(unsigned char *client_ca, unsigned char *private_key) {
    _cli_cert = client_ca;
    _cli_key = private_key;
}

void LineNotify::setPreSharedKey(unsigned char *pskIdent, unsigned char *psKey) {
    _psKey = psKey;
    _pskIdent = pskIdent;
}

int LineNotify::setRecvTimeout(int timeout) {
    sslclient.recvTimeout = timeout;
    if (connected()) {
        ssldrv.setSockRecvTimeout(sslclient.socket, sslclient.recvTimeout);
    }

    return 0;
}
