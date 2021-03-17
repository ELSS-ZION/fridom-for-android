// https://android.googlesource.com/platform/libnativehelper/+/master/include_jni/jni.h

import { log, jclsString, clsByteArray, hexStringFromByteArray } from "./util"

export class FuncSig {
    argsTypes: string[]
    returnType: string
    name: string
    jclassConsultIndex: number|undefined
    jobjectConsultIndex: number|undefined
    indexOfJniStruct: number|undefined
    listener: InvocationListener|undefined
}

const funcSignatures = [
    // "reserved0",
    // "reserved1",
    // "reserved2",
    // "reserved3",
    "jint        GetVersion(JNIEnv *)",
    "jclass      DefineClass(JNIEnv*, const char*, jobject, const jbyte*, jsize)",
    "jclass      FindClass(JNIEnv*, const char*)",
    "jmethodID   FromReflectedMethod(JNIEnv*, jobject)",
    "jfieldID    FromReflectedField(JNIEnv*, jobject)",
    "jobject     ToReflectedMethod(JNIEnv*, jclass, jmethodID, jboolean)",
    "jclass      GetSuperclass(JNIEnv*, jclass)",
    "jboolean    IsAssignableFrom(JNIEnv*, jclass, jclass)",
    "jobject     ToReflectedField(JNIEnv*, jclass, jfieldID, jboolean)",
    "jint        Throw(JNIEnv*, jthrowable)",
    "jint        ThrowNew(JNIEnv *, jclass, const char *)",
    "jthrowable  ExceptionOccurred(JNIEnv*)",
    "void        ExceptionDescribe(JNIEnv*)",
    "void        ExceptionClear(JNIEnv*)",
    "void        FatalError(JNIEnv*, const char*)",
    "jint        PushLocalFrame(JNIEnv*, jint)",
    "jobject     PopLocalFrame(JNIEnv*, jobject)",
    "jobject     NewGlobalRef(JNIEnv*, jobject)",
    "void        DeleteGlobalRef(JNIEnv*, jobject)",
    "void        DeleteLocalRef(JNIEnv*, jobject)",
    "jboolean    IsSameObject(JNIEnv*, jobject, jobject)",
    "jobject     NewLocalRef(JNIEnv*, jobject)",
    "jint        EnsureLocalCapacity(JNIEnv*, jint)",
    "jobject     AllocObject(JNIEnv*, jclass)",
    "jobject     NewObject(JNIEnv*, jclass, jmethodID, ...)",
    "jobject     NewObjectV(JNIEnv*, jclass, jmethodID, va_list)",
    "jobject     NewObjectA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "jclass      GetObjectClass(JNIEnv*, jobject)",
    "jboolean    IsInstanceOf(JNIEnv*, jobject, jclass)",
    "jmethodID   GetMethodID(JNIEnv*, jclass, const char*, const char*)",
    "jobject     CallObjectMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jobject     CallObjectMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jobject     CallObjectMethodA(JNIEnv*, jobject, jmethodID, const jvalue*)",
    "jboolean    CallBooleanMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jboolean    CallBooleanMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jboolean    CallBooleanMethodA(JNIEnv*, jobject, jmethodID, const jvalue*)",
    "jbyte       CallByteMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jbyte       CallByteMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jbyte       CallByteMethodA(JNIEnv*, jobject, jmethodID, const jvalue*)",
    "jchar       CallCharMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jchar       CallCharMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jchar       CallCharMethodA(JNIEnv*, jobject, jmethodID, const jvalue*)",
    "jshort      CallShortMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jshort      CallShortMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jshort      CallShortMethodA(JNIEnv*, jobject, jmethodID, const jvalue*)",
    "jint        CallIntMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jint        CallIntMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jint        CallIntMethodA(JNIEnv*, jobject, jmethodID, const jvalue*)",
    "jlong       CallLongMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jlong       CallLongMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jlong       CallLongMethodA(JNIEnv*, jobject, jmethodID, const jvalue*)",
    "jfloat      CallFloatMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jfloat      CallFloatMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jfloat      CallFloatMethodA(JNIEnv*, jobject, jmethodID, const jvalue*)",
    "jdouble     CallDoubleMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jdouble     CallDoubleMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jdouble     CallDoubleMethodA(JNIEnv*, jobject, jmethodID, const jvalue*)",
    "void        CallVoidMethod(JNIEnv*, jobject, jmethodID, ...)",
    "void        CallVoidMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "void        CallVoidMethodA(JNIEnv*, jobject, jmethodID, const jvalue*)",
    "jobject     CallNonvirtualObjectMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jobject     CallNonvirtualObjectMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jobject     CallNonvirtualObjectMethodA(JNIEnv*, jobject, jclass, jmethodID, const jvalue*)",
    "jboolean    CallNonvirtualBooleanMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jboolean    CallNonvirtualBooleanMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jboolean    CallNonvirtualBooleanMethodA(JNIEnv*, jobject, jclass, jmethodID, const jvalue*)",
    "jbyte       CallNonvirtualByteMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jbyte       CallNonvirtualByteMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jbyte       CallNonvirtualByteMethodA(JNIEnv*, jobject, jclass, jmethodID, const jvalue*)",
    "jchar       CallNonvirtualCharMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jchar       CallNonvirtualCharMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jchar       CallNonvirtualCharMethodA(JNIEnv*, jobject, jclass, jmethodID, const jvalue*)",
    "jshort      CallNonvirtualShortMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jshort      CallNonvirtualShortMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jshort      CallNonvirtualShortMethodA(JNIEnv*, jobject, jclass, jmethodID, const jvalue*)",
    "jint        CallNonvirtualIntMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jint        CallNonvirtualIntMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jint        CallNonvirtualIntMethodA(JNIEnv*, jobject, jclass, jmethodID, const jvalue*)",
    "jlong       CallNonvirtualLongMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jlong       CallNonvirtualLongMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jlong       CallNonvirtualLongMethodA(JNIEnv*, jobject, jclass, jmethodID, const jvalue*)",
    "jfloat      CallNonvirtualFloatMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jfloat      CallNonvirtualFloatMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jfloat      CallNonvirtualFloatMethodA(JNIEnv*, jobject, jclass, jmethodID, const jvalue*)",
    "jdouble     CallNonvirtualDoubleMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jdouble     CallNonvirtualDoubleMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jdouble     CallNonvirtualDoubleMethodA(JNIEnv*, jobject, jclass, jmethodID, const jvalue*)",
    "void        CallNonvirtualVoidMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "void        CallNonvirtualVoidMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "void        CallNonvirtualVoidMethodA(JNIEnv*, jobject, jclass, jmethodID, const jvalue*)",
    "jfieldID    GetFieldID(JNIEnv*, jclass, const char*, const char*)",
    "jobject     GetObjectField(JNIEnv*, jobject, jfieldID)",
    "jboolean    GetBooleanField(JNIEnv*, jobject, jfieldID)",
    "jbyte       GetByteField(JNIEnv*, jobject, jfieldID)",
    "jchar       GetCharField(JNIEnv*, jobject, jfieldID)",
    "jshort      GetShortField(JNIEnv*, jobject, jfieldID)",
    "jint        GetIntField(JNIEnv*, jobject, jfieldID)",
    "jlong       GetLongField(JNIEnv*, jobject, jfieldID)",
    "jfloat      GetFloatField(JNIEnv*, jobject, jfieldID)",
    "jdouble     GetDoubleField(JNIEnv*, jobject, jfieldID)",
    "void        SetObjectField(JNIEnv*, jobject, jfieldID, jobject)",
    "void        SetBooleanField(JNIEnv*, jobject, jfieldID, jboolean)",
    "void        SetByteField(JNIEnv*, jobject, jfieldID, jbyte)",
    "void        SetCharField(JNIEnv*, jobject, jfieldID, jchar)",
    "void        SetShortField(JNIEnv*, jobject, jfieldID, jshort)",
    "void        SetIntField(JNIEnv*, jobject, jfieldID, jint)",
    "void        SetLongField(JNIEnv*, jobject, jfieldID, jlong)",
    "void        SetFloatField(JNIEnv*, jobject, jfieldID, jfloat)",
    "void        SetDoubleField(JNIEnv*, jobject, jfieldID, jdouble)",
    "jmethodID   GetStaticMethodID(JNIEnv*, jclass, const char*, const char*)",
    "jobject     CallStaticObjectMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jobject     CallStaticObjectMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jobject     CallStaticObjectMethodA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "jboolean    CallStaticBooleanMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jboolean    CallStaticBooleanMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jboolean    CallStaticBooleanMethodA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "jbyte       CallStaticByteMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jbyte       CallStaticByteMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jbyte       CallStaticByteMethodA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "jchar       CallStaticCharMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jchar       CallStaticCharMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jchar       CallStaticCharMethodA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "jshort      CallStaticShortMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jshort      CallStaticShortMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jshort      CallStaticShortMethodA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "jint        CallStaticIntMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jint        CallStaticIntMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jint        CallStaticIntMethodA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "jlong       CallStaticLongMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jlong       CallStaticLongMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jlong       CallStaticLongMethodA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "jfloat      CallStaticFloatMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jfloat      CallStaticFloatMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jfloat      CallStaticFloatMethodA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "jdouble     CallStaticDoubleMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jdouble     CallStaticDoubleMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jdouble     CallStaticDoubleMethodA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "void        CallStaticVoidMethod(JNIEnv*, jclass, jmethodID, ...)",
    "void        CallStaticVoidMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "void        CallStaticVoidMethodA(JNIEnv*, jclass, jmethodID, const jvalue*)",
    "jfieldID    GetStaticFieldID(JNIEnv*, jclass, const char*, const char*)",
    "jobject     GetStaticObjectField(JNIEnv*, jclass, jfieldID)",
    "jboolean    GetStaticBooleanField(JNIEnv*, jclass, jfieldID)",
    "jbyte       GetStaticByteField(JNIEnv*, jclass, jfieldID)",
    "jchar       GetStaticCharField(JNIEnv*, jclass, jfieldID)",
    "jshort      GetStaticShortField(JNIEnv*, jclass, jfieldID)",
    "jint        GetStaticIntField(JNIEnv*, jclass, jfieldID)",
    "jlong       GetStaticLongField(JNIEnv*, jclass, jfieldID)",
    "jfloat      GetStaticFloatField(JNIEnv*, jclass, jfieldID)",
    "jdouble     GetStaticDoubleField(JNIEnv*, jclass, jfieldID)",
    "void        SetStaticObjectField(JNIEnv*, jclass, jfieldID, jobject)",
    "void        SetStaticBooleanField(JNIEnv*, jclass, jfieldID, jboolean)",
    "void        SetStaticByteField(JNIEnv*, jclass, jfieldID, jbyte)",
    "void        SetStaticCharField(JNIEnv*, jclass, jfieldID, jchar)",
    "void        SetStaticShortField(JNIEnv*, jclass, jfieldID, jshort)",
    "void        SetStaticIntField(JNIEnv*, jclass, jfieldID, jint)",
    "void        SetStaticLongField(JNIEnv*, jclass, jfieldID, jlong)",
    "void        SetStaticFloatField(JNIEnv*, jclass, jfieldID, jfloat)",
    "void        SetStaticDoubleField(JNIEnv*, jclass, jfieldID, jdouble)",
    "jstring     NewString(JNIEnv*, const jchar*, jsize)",
    "jsize       GetStringLength(JNIEnv*, jstring)",
    "const jchar* GetStringChars(JNIEnv*, jstring, jboolean*)",
    "void        ReleaseStringChars(JNIEnv*, jstring, const jchar*)",
    "jstring     NewStringUTF(JNIEnv*, const char*)",
    "jsize       GetStringUTFLength(JNIEnv*, jstring)",
    "const char* GetStringUTFChars(JNIEnv*, jstring, jboolean*)",
    "void        ReleaseStringUTFChars(JNIEnv*, jstring, const char*)",
    "jsize       GetArrayLength(JNIEnv*, jarray)",
    "jobjectArray NewObjectArray(JNIEnv*, jsize, jclass, jobject)",
    "jobject     GetObjectArrayElement(JNIEnv*, jobjectArray, jsize)",
    "void        SetObjectArrayElement(JNIEnv*, jobjectArray, jsize, jobject)",
    "jbooleanArray NewBooleanArray(JNIEnv*, jsize)",
    "jbyteArray    NewByteArray(JNIEnv*, jsize)",
    "jcharArray    NewCharArray(JNIEnv*, jsize)",
    "jshortArray   NewShortArray(JNIEnv*, jsize)",
    "jintArray     NewIntArray(JNIEnv*, jsize)",
    "jlongArray    NewLongArray(JNIEnv*, jsize)",
    "jfloatArray   NewFloatArray(JNIEnv*, jsize)",
    "jdoubleArray  NewDoubleArray(JNIEnv*, jsize)",
    "jboolean*   GetBooleanArrayElements(JNIEnv*, jbooleanArray, jboolean*)",
    "jbyte*      GetByteArrayElements(JNIEnv*, jbyteArray, jboolean*)",
    "jchar*      GetCharArrayElements(JNIEnv*, jcharArray, jboolean*)",
    "jshort*     GetShortArrayElements(JNIEnv*, jshortArray, jboolean*)",
    "jint*       GetIntArrayElements(JNIEnv*, jintArray, jboolean*)",
    "jlong*      GetLongArrayElements(JNIEnv*, jlongArray, jboolean*)",
    "jfloat*     GetFloatArrayElements(JNIEnv*, jfloatArray, jboolean*)",
    "jdouble*    GetDoubleArrayElements(JNIEnv*, jdoubleArray, jboolean*)",
    "void        ReleaseBooleanArrayElements(JNIEnv*, jbooleanArray, jboolean*, jint)",
    "void        ReleaseByteArrayElements(JNIEnv*, jbyteArray, jbyte*, jint)",
    "void        ReleaseCharArrayElements(JNIEnv*, jcharArray, jchar*, jint)",
    "void        ReleaseShortArrayElements(JNIEnv*, jshortArray, jshort*, jint)",
    "void        ReleaseIntArrayElements(JNIEnv*, jintArray, jint*, jint)",
    "void        ReleaseLongArrayElements(JNIEnv*, jlongArray, jlong*, jint)",
    "void        ReleaseFloatArrayElements(JNIEnv*, jfloatArray, jfloat*, jint)",
    "void        ReleaseDoubleArrayElements(JNIEnv*, jdoubleArray, jdouble*, jint)",
    "void        GetBooleanArrayRegion(JNIEnv*, jbooleanArray, jsize, jsize, jboolean*)",
    "void        GetByteArrayRegion(JNIEnv*, jbyteArray, jsize, jsize, jbyte*)",
    "void        GetCharArrayRegion(JNIEnv*, jcharArray, jsize, jsize, jchar*)",
    "void        GetShortArrayRegion(JNIEnv*, jshortArray, jsize, jsize, jshort*)",
    "void        GetIntArrayRegion(JNIEnv*, jintArray, jsize, jsize, jint*)",
    "void        GetLongArrayRegion(JNIEnv*, jlongArray, jsize, jsize, jlong*)",
    "void        GetFloatArrayRegion(JNIEnv*, jfloatArray, jsize, jsize, jfloat*)",
    "void        GetDoubleArrayRegion(JNIEnv*, jdoubleArray, jsize, jsize, jdouble*)",
    "void        SetBooleanArrayRegion(JNIEnv*, jbooleanArray, jsize, jsize, const jboolean*)",
    "void        SetByteArrayRegion(JNIEnv*, jbyteArray, jsize, jsize, const jbyte*)",
    "void        SetCharArrayRegion(JNIEnv*, jcharArray, jsize, jsize, const jchar*)",
    "void        SetShortArrayRegion(JNIEnv*, jshortArray, jsize, jsize, const jshort*)",
    "void        SetIntArrayRegion(JNIEnv*, jintArray, jsize, jsize, const jint*)",
    "void        SetLongArrayRegion(JNIEnv*, jlongArray, jsize, jsize, const jlong*)",
    "void        SetFloatArrayRegion(JNIEnv*, jfloatArray, jsize, jsize, const jfloat*)",
    "void        SetDoubleArrayRegion(JNIEnv*, jdoubleArray, jsize, jsize, const jdouble*)",
    "jint        RegisterNatives(JNIEnv*, jclass, const JNINativeMethod*, jint)",
    "jint        UnregisterNatives(JNIEnv*, jclass)",
    "jint        MonitorEnter(JNIEnv*, jobject)",
    "jint        MonitorExit(JNIEnv*, jobject)",
    "jint        GetJavaVM(JNIEnv*, JavaVM**)",
    "void        GetStringRegion(JNIEnv*, jstring, jsize, jsize, jchar*)",
    "void        GetStringUTFRegion(JNIEnv*, jstring, jsize, jsize, char*)",
    "void*       GetPrimitiveArrayCritical(JNIEnv*, jarray, jboolean*)",
    "void        ReleasePrimitiveArrayCritical(JNIEnv*, jarray, void*, jint)",
    "const jchar* GetStringCritical(JNIEnv*, jstring, jboolean*)",
    "void        ReleaseStringCritical(JNIEnv*, jstring, const jchar*)",
    "jweak       NewWeakGlobalRef(JNIEnv*, jobject)",
    "void        DeleteWeakGlobalRef(JNIEnv*, jweak)",
    "jboolean    ExceptionCheck(JNIEnv*)",
    "jobject     NewDirectByteBuffer(JNIEnv*, void*, jlong)",
    "void*       GetDirectBufferAddress(JNIEnv*, jobject)",
    "jlong       GetDirectBufferCapacity(JNIEnv*, jobject)",
    "jobjectRefType GetObjectRefType(JNIEnv*, jobject)"
]

let funcSigs:FuncSig[] = []

funcSignatures.forEach((element, i) => {
    let funcSig = parseFuncSignature(element)
    funcSig.indexOfJniStruct = i + 4
    funcSigs.push(funcSig)
});

export function isReleaseFunc(funcName: string) : boolean {
    return funcName.match(/(Delete|Release)/) != null
}

export function getJNIFunctionAdress(funcName: string) : NativePointer|null {
    let jnienv_addr:NativePointer = Java.vm.getEnv().handle.readPointer()
    let index = -1
    funcSigs.forEach((sig, i) => {
        if (sig.name == funcName) {
            index = sig.indexOfJniStruct
        }
    })
    if (index == -1) {
        return null
    }
    let offset = index * Process.pointerSize
    return jnienv_addr.add(offset).readPointer()
}

export function parseFuncSignature(funcSignature: string) : FuncSig | null {
    let reg = /([0-9a-zA-Z_$*]+)\W+([0-9a-zA-Z_$]+)\((.*)\)/g
    let matches = reg.exec(funcSignature)
    
    if (matches == null) {
        return null
    }

    let funcSig = new FuncSig()
    let argsTypes: string[] = matches[3].split(",")
    let returnType: string = matches[1]
    let name: string = matches[2]
    let jclassConsultIndex: number|undefined = undefined
    let jobjectConsultIndex: number|undefined = undefined

    for (let i = 0; i < argsTypes.length; i++) {
        let type = argsTypes[i].trim()
        if (type == "jclass") {
            jclassConsultIndex = i
        } else if (type == "jobject") {
            jobjectConsultIndex = i
        }
        argsTypes[i] = type
    }
    
    funcSig.returnType = returnType
    funcSig.name = name
    funcSig.argsTypes = argsTypes
    funcSig.jclassConsultIndex = jclassConsultIndex
    funcSig.jobjectConsultIndex = jobjectConsultIndex
    return funcSig
}

function classNameFromJclass(jcls: NativePointer) : string|null {
    let mid_getClass = GetMethodID(Java.vm.getEnv().handle, jcls, pstr_getClass, pstr_getClassMethodSig)
    if (mid_getClass == 0) {
        return null
    }
    let jobj_cls = CallObjectMethod(Java.vm.getEnv().handle, jcls, mid_getClass)
    let mid_getName = GetMethodID(Java.vm.getEnv().handle, jobj_cls, pstr_getName, pstr_getNameMethodSig)
    let jobjclassName = CallObjectMethod(Java.vm.getEnv().handle, jcls, mid_getName)
    let strClassName = Java.vm.getEnv().getStringUtfChars(jobjclassName, null).readCString()

    DeleteLocalRef(Java.vm.getEnv().handle, mid_getClass)
    DeleteLocalRef(Java.vm.getEnv().handle, jobj_cls)
    DeleteLocalRef(Java.vm.getEnv().handle, mid_getName)
    DeleteLocalRef(Java.vm.getEnv().handle, jobjclassName)
    return strClassName
}

function argTypesFromMethodSig(methodSig: string) {
    let matches = methodSig.match(/\((.*)\)/)
    let argsTypes: string[] = matches[1].split(",")

    let hasArgs = matches[1].trim().length != 0
    if (hasArgs == false) {
        return []
    }

    argsTypes.forEach((type, i) => {
        argsTypes[i] = argsTypes[i].trim()
    })
    return argsTypes
}

function getMethodSig(jmethodID: NativePointer, args: any[], funcSig: FuncSig) : string|null {
    let jclass: NativePointer
    let jobjMethod: NativePointer
    let isStatic = funcSig.name.match("Static") != null? 1:0

    if (funcSig.jclassConsultIndex != undefined) {
        jclass = args[funcSig.jclassConsultIndex]
        jobjMethod = <NativePointer>ToReflectedMethod(Java.vm.getEnv().handle, jclass, jmethodID, isStatic)
    }else {
        let jobject = args[funcSig.jobjectConsultIndex]
        jclass = <NativePointer>GetObjectClass(Java.vm.getEnv().handle, jobject)
        jobjMethod = <NativePointer>ToReflectedMethod(Java.vm.getEnv().handle, jclass, jmethodID, isStatic)
        DeleteLocalRef(Java.vm.getEnv().handle, jclass)
    }
    
    try {
        let clsMethod = Java.use("java.lang.reflect.Method")
        let method = Java.cast(jobjMethod, clsMethod)
        DeleteLocalRef(Java.vm.getEnv().handle, jobjMethod)
        return "" + method
    } catch(e) {
        if (e.toString() == "Error: Cast from 'java.lang.reflect.Constructor' to 'java.lang.reflect.Method' isn't possible") {
            let clsConstructor = Java.use("java.lang.reflect.Constructor")
            let constructor = Java.cast(jobjMethod, clsConstructor)
            return "" + constructor
        }else {
            log(e)
            return null
        }
    }
}

function hexStringFromPointer(pointer: NativePointer) : string {
    return pointer.toString(16).padStart(Process.pointerSize * 2, '0')
}

// typeIndex == -1 means return value type
function formatData(data: NativePointer, typeIndex: number, args: any[], funcSig: FuncSig) : string {
    let type: string
    let str: string = hexStringFromPointer(data)

    if (typeIndex == -1) {
        type = funcSig.returnType
    }else {
        type = funcSig.argsTypes[typeIndex]
    }

    if (data.toInt32() == 0) {
        return str
    }

    if (type == "jstring")
    {
        str += " " + Java.vm.getEnv().getStringUtfChars(data, null).readCString()
    } else if(type.match(/char\s*\*/) != null) {
        str += " " + data.readCString()
    } else if(type == "jclass") {
        let jcls = data
        let className = classNameFromJclass(jcls)
        str += " " + className
    } else if(type == "jobject") {
        let jobj = data
        if (isReleaseFunc(funcSig.name)) {
            return str
        }
        let jcls = <NativePointer>GetObjectClass(Java.vm.getEnv().handle, jobj)
        let className = classNameFromJclass(jcls)
        DeleteLocalRef(Java.vm.getEnv().handle, jcls)

        if (className == null) {
            className = '<UnknownClass>: classNameFromJclass Fail: mid_getClass == 0'
        }else if (className == "java.lang.String") {
            let str = Java.cast(jobj, jclsString)
            className += '\t"' + str + '"'
        }
        str += ` jobject of ${className}`
        if (className == "[B") {
            let jclsByteArray = Java.use('[B')
            let bytes = Java.cast(data, jclsByteArray)
            let byteArray = Java.array('byte', <any>bytes)
            str += " " + hexStringFromByteArray(byteArray)
        }
    } else if(type.match(/JNIEnv\s*\*/) != null) {
        str += " JNIEnv*"
    } else if(type == "jfieldID") {
        let isStatic = funcSig.name.match("Static") != null? 1:0
        let jclass: NativePointer
        let jobjField: NativePointer

        if (funcSig.jclassConsultIndex != undefined) {
            jclass = args[funcSig.jclassConsultIndex]
            jobjField = <NativePointer>ToReflectedField(Java.vm.getEnv().handle, jclass, data, isStatic)
        }else {
            let jobject = args[funcSig.jobjectConsultIndex]
            jclass = <NativePointer>GetObjectClass(Java.vm.getEnv().handle, jobject)
            jobjField = <NativePointer>ToReflectedField(Java.vm.getEnv().handle, jclass, data, isStatic)
            DeleteLocalRef(Java.vm.getEnv().handle, jclass)
        }
        
        let clsField = Java.use("java.lang.reflect.Field")
        let field = Java.cast(jobjField, clsField)
        DeleteLocalRef(Java.vm.getEnv().handle, jobjField)
        str += " " + field
    } else if(type == "jmethodID") {
        let methodSig = getMethodSig(data, args, funcSig)
        if (methodSig != null) {
            str += " " + methodSig
        }else {
            str += " <UnKnownMethod>: getMethodSig fail"
        }
    } else if ((type == '...' || type == 'va_list' || type.matchAll(/const\s+jvalue\s*\*/g) != null) && funcSig.argsTypes[typeIndex - 1] == 'jmethodID') {
        let methodSig = getMethodSig(args[typeIndex - 1], args, funcSig)
        if (methodSig != null) {
            let methodArgTypes = argTypesFromMethodSig(methodSig)
            let subArgObjs = []

            methodArgTypes.forEach((subArgType, i) => {
                let subArg: NativePointer
                if (type == '...') {
                    subArg = <NativePointer>args[typeIndex + i]
                } else if (type == 'va_list' || type.matchAll(/const\s+jvalue\s*\*/g) != null) {
                    let va_list = <NativePointer>args[typeIndex]
                    subArg = va_list.add(i * Process.pointerSize).readPointer()
                }

                let value = hexStringFromPointer(subArg)
                let subArgDescriptor = {}

                subArgDescriptor["type"] = subArgType
                subArgDescriptor["value"] = value

                if (subArg.toInt32() != 0) {
                    try {
                        if (subArgType == "byte[]") {
                            let obj = Java.cast(subArg, clsByteArray)
                            let bytes = Java.array("byte", <any>obj)
                            subArgDescriptor["_toString"] = hexStringFromByteArray(bytes)
                        } else {
                            let cls = Java.use(subArgType)
                            let jobj = Java.cast(subArg, cls)
                            subArgDescriptor["_toString"] = "" + jobj
                        }
                    }catch (e) {
                        // log(e)
                    }
                }
                
                subArgObjs.push(subArgDescriptor)
            })
            str += " " + JSON.stringify(subArgObjs)
        }
    }
    return str
}

export function trace(funcName: string) {
    funcSigs.forEach(sig => {
        if (sig.name == funcName) {
            traceWithFuncSig(sig)
        }
    });
}

export function untrace(funcName: string) {
    funcSigs.forEach(sig => {
        if (sig.name == funcName) {
            untraceWithFuncSig(sig)
        }
    })
}

function untraceWithFuncSig(funcSig: FuncSig) {
    if (funcSig.listener == undefined) {
        return
    }
    funcSig.listener.detach()
    funcSig.listener = undefined
    Interceptor.flush()
}

function traceWithFuncSig(funcSig: FuncSig) {
    let func_addr = getJNIFunctionAdress(funcSig.name)
    
    if (funcSig.listener != undefined) {
        return
    }

    let listener = Interceptor.attach(func_addr, {
        onEnter: function(args) {
            this.args = []
            for (let i = 0; i < funcSig.argsTypes.length + 8; i++) {
                this.args[i] = args[i]
            }
        },
        onLeave: function(retval) {
            if (isHandlingHook) {
                return retval
            }

            isHandlingHook = true

            log("\n" + funcSignatures[funcSig.indexOfJniStruct-4])
            
            for (let i = 0; i < funcSig.argsTypes.length; i++) {
                let str = formatData(this.args[i], i, this.args, funcSig)
                log(`\targ[${i}]: \t${str}`)
            }
            let str = formatData(retval, -1, this.args, funcSig)
            log(`\tretval: \t${str}`)

            let moduleMap = new ModuleMap()
            let retModule = moduleMap.find(this.returnAddress)
            let retAddrHexStr = hexStringFromPointer(this.returnAddress)
            let retAddrModuleOffsetHexStr = hexStringFromPointer(this.returnAddress.sub(retModule.base))

            log(`\tretaddr: \t${retAddrHexStr} -- ${retAddrModuleOffsetHexStr} ${JSON.stringify(retModule)}`)

            isHandlingHook = false
            return retval;
        }
    })
    funcSig.listener = listener
    Interceptor.flush()
}

export function traceAll(isTraceReleaseFunc: boolean = false) {
    funcSigs.forEach(sig => {
        if (isTraceReleaseFunc == false && isReleaseFunc(sig.name)) {
            return
        }
        traceWithFuncSig(sig)
    });
}

export function untraceAll() {
    funcSigs.forEach(sig => {
        untraceWithFuncSig(sig)
    })
}

let isHandlingHook = false

let pstr_getName = Memory.allocUtf8String("getName")
let pstr_getClass = Memory.allocUtf8String("getClass")
let pstr_getNameMethodSig = Memory.allocUtf8String("()Ljava/lang/String;")
let pstr_getClassMethodSig = Memory.allocUtf8String("()Ljava/lang/Class;")

let fpFindClass = getJNIFunctionAdress("FindClass")
export let FindClass = new NativeFunction(fpFindClass, 'pointer', ['pointer', 'pointer'])

let fpGetMethodID = getJNIFunctionAdress("GetMethodID")
export let GetMethodID = new NativeFunction(fpGetMethodID, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'])

let fpCallObjectMethod = getJNIFunctionAdress("CallObjectMethod")
export let CallObjectMethod = new NativeFunction(fpCallObjectMethod, 'pointer', ['pointer', 'pointer', 'pointer'])

let fpGetObjectClass = getJNIFunctionAdress("GetObjectClass")
export let GetObjectClass = new NativeFunction(fpGetObjectClass, 'pointer', ['pointer', 'pointer'])

let fpToReflectedField = getJNIFunctionAdress("ToReflectedField")
export let ToReflectedField = new NativeFunction(fpToReflectedField, 'pointer', ['pointer', 'pointer', 'pointer', 'uint8'])

let fpToReflectedMethod = getJNIFunctionAdress("ToReflectedMethod")
export let ToReflectedMethod = new NativeFunction(fpToReflectedMethod, 'pointer', ['pointer', 'pointer', 'pointer', 'uint8'])

let fpDeleteLocalRef = getJNIFunctionAdress("DeleteLocalRef")
export let DeleteLocalRef = new NativeFunction(fpDeleteLocalRef, 'void', ['pointer', 'pointer'])

let fpNewStringUTF = getJNIFunctionAdress("NewStringUTF")
export let NewStringUTF = new NativeFunction(fpNewStringUTF, 'pointer', ['pointer', 'pointer'])
