import * as _ from "./util"
import * as antidbg from "./antidbg"
import * as jni from "./jni"

Java.perform(function() {
    antidbg.bypassAll()

    let fpMuxAqhmrDS = Module.findExportByName("liblogin_encrypt.so", "Java_com_ximalaya_ting_android_loginservice_LoginEncryptUtil_MuxAqhmrDS");
    Interceptor.attach(fpMuxAqhmrDS, {
        onEnter(args) {
            _.log("onEnter ####################################################################")
            jni.traceAll()
        },
        onLeave(retval) {
            jni.untraceAll()
            _.log("onLeave ####################################################################")
            let retvalStr = Java.cast(retval, _.jclsString)
            _.log("retval: " + retvalStr)
            return retval
        }
    })
})
