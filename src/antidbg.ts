import { log } from "./util"

export function bypassTracerPid_fgets() {
    log("bypassTracerPid_fgets");
    let fgetsPtr = Module.findExportByName("libc.so", "fgets");
    let fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);

    Interceptor.replace(fgetsPtr, new NativeCallback(function(buffer:NativePointer, size:number, fp:NativePointer) {
        let retval = fgets(buffer, size, fp);
        let bufstr:string
        try {
            bufstr = buffer.readUtf8String();
            // log(bufstr)
        }catch(e) {
            // log("catch(e): " + e)
            bufstr = buffer.readCString();
            // log(bufstr)
        }
        
        if (bufstr.indexOf("TracerPid:") > -1) {
            buffer.writeUtf8String("TracerPid:\t0");
            log("TracerPid replaced: " + buffer.readUtf8String());
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']));
};

export function bypassFridaXposed_strstr() {
    log("bypassFrida_strstr");
    Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {

        onEnter: function(args) {
            let haystack = args[0].toString();
            let needle = args[1].toString();
            this.frida = Boolean(0);

            if (needle.indexOf("frida") !== -1 || needle.indexOf("xposed") !== -1) {
                // log("bypassFrida_strstr catched")
                // log("haystack " + haystack)
                // log("needle " + needle)
                this.frida = Boolean(1);
            }
        },

        onLeave: function(retval) {
            if (this.frida) {
                retval.replace(null);
            }
            return retval;
        }
    });
}

export function bypassIsDebuggerConnected() {
    log("bypassIsDebuggerConnected");
    let jclsDebug = Java.use("android.os.Debug")

    jclsDebug.isDebuggerConnected.implementation = function() {
        log('jclsDebug.isDebuggerConnected original result ' + this.isDebuggerConnected())
        return false
    }

}

export function bypassAll() {
    bypassTracerPid_fgets()
    bypassFridaXposed_strstr()
    bypassIsDebuggerConnected()
}