export let jclsString = Java.use("java.lang.String")
export let jclsHashMap = Java.use("java.util.HashMap")
export let clsByteArray = Java.use("[B")

export function log(message: any): void {
    send(message)
}

export function hexStringFromByteArray(byteArray: number[]) : string {
    return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
      }).join('')
}

export function setBreakPoint(addr: NativePointer, size: number, pattern: string) {
    Process.setExceptionHandler(function(details) {
        /*
                type: string specifying one of:
                        abort
                        access-violation
                        guard-page
                        illegal-instruction
                        stack-overflow
                        arithmetic
                        breakpoint
                        single-step
                        system
                address: address where the exception occurred, as a NativePointer
                memory: if present, is an object containing:
                        operation: the kind of operation that triggered the exception, as a string specifying either read,  write, or execute
                        address: address that was accessed when the exception occurred, as a NativePointer
                context: object with the keys pc and sp, which are NativePointer objects specifying EIP/RIP/PC and ESP/RSP/SP, respectively, for ia32/x64/arm. Other processor-specific keys are also available, e.g. eax, rax, r0, x0, etc. You may also update register values by assigning to these keys.
                nativeContext: address of the OS and architecture-specific CPU context struct, as a NativePointer. This is only exposed as a last resort for edge-cases where context isn’t providing enough details. We would however discourage using this and rather submit a pull-request to add the missing bits needed for your use-case.               
        */
        log("Break at: " + details.address)
        Memory.protect(addr, size, 'rwx')
        return true;
    })
    Memory.protect(addr, size, pattern)
}