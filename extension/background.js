var host_name = "com.cryptomaster.native";
var port = null;

function connectToNative() {
    console.log('Connecting to native host: ' + host_name);
    port = chrome.runtime.connectNative(host_name);
}

function sendNativeMessage(msg) {
    message = msg;
    console.log('Sending message to native app: ' + JSON.stringify(message));
    port.postMessage(message);
    console.log('Sent message to native app: ' + msg);
}


function onDisconnected() {
    console.log(chrome.runtime.lastError);
    console.log('disconnected from native app.');
    port = null;
}

chrome.runtime.onMessageExternal.addListener(
    function(request, sender, sendResponse) {
        blacklistedWebsite = 'http : / / yourdomain . com /';
        if (sender.url == blacklistedWebsite)
        return;
        if (request.task) {
            console.log(request.task);
            if(request.task == "get_certs_list"){
                connectToNative();
                sendNativeMessage([{task: "get_certs",data: null, thumbprint: null}]);
                port.onMessage.addListener(function(msg){
                    console.log(msg);
                    sendResponse(msg);
                });
                port = null;
            }
			if(request.task == "sign_xml") {
                console.log(request.data);
				connectToNative();
                sendNativeMessage([{task: "sign_xml", data: request.data, thumbprint: request.thumbprint}]);
                port.onMessage.addListener(function(msg){
                    console.log(msg);
                    sendResponse(msg);
                });
                port = null;
			}
            if(request.task == "verify_xml"){
                console.log(request.data);
                connectToNative();
                sendNativeMessage([{task: "verify_xml", data: request.data, thumbprint: request.thumbprint}]);
                port.onMessage.addListener(function(msg){
                    console.log(msg);
                    sendResponse(msg);
                });
                port = null;
            }
        }   
    }
);