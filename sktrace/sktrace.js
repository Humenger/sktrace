

const arm64CM = new CModule(`
#include <gum/gumstalker.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void on_message(const gchar *message);
static void log(const gchar *format, ...);
static void on_arm64_before(GumCpuContext *cpu_context, gpointer user_data);
static void on_arm64_after(GumCpuContext *cpu_context, gpointer user_data);

void hello() {
    on_message("Hello form CModule");
}

gpointer shared_mem[] = {0, 0};

gpointer 
get_shared_mem() 
{
    return shared_mem;
}


static void
log(const gchar *format, ...)
{
    gchar *message;
    va_list args;

    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);

    on_message(message);
    g_free(message);
}


void transform(GumStalkerIterator *iterator,
               GumStalkerOutput *output,
               gpointer user_data)
{
    cs_insn *insn;

    gpointer base = *(gpointer*)user_data;
    gpointer end = *(gpointer*)(user_data + sizeof(gpointer));
    
    while (gum_stalker_iterator_next(iterator, &insn))
    {
        gboolean in_target = (gpointer)insn->address >= base && (gpointer)insn->address < end;
        if(in_target)
        {
            log("%p\t%s\t%s", (gpointer)insn->address, insn->mnemonic, insn->op_str);
            gum_stalker_iterator_put_callout(iterator, on_arm64_before, (gpointer) insn->address, NULL);
        }
        gum_stalker_iterator_keep(iterator);
        if(in_target) 
        {
            gum_stalker_iterator_put_callout(iterator, on_arm64_after, (gpointer) insn->address, NULL);
        }
    }
}


const gchar * cpu_format = "
    0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x
    ";

static void
on_arm64_before(GumCpuContext *cpu_context,
        gpointer user_data)
{

}

static void
on_arm64_after(GumCpuContext *cpu_context,
        gpointer user_data)
{

}

`, {
    on_message: new NativeCallback(messagePtr => {
        const message = messagePtr.readUtf8String();
        console.log(message)
        // send(message)
      }, 'void', ['pointer']),
});


const userData = Memory.alloc(Process.pageSize);
function stalkerTraceRangeC(tid, base, size) {
    // const hello = new NativeFunction(cm.hello, 'void', []);
    // hello();
    userData.writePointer(base)
    const pointerSize = Process.pointerSize;
    userData.add(pointerSize).writePointer(base.add(size))
    
    Stalker.follow(tid, {
        transform: arm64CM.transform,
        // onEvent: cm.process,
        data: userData /* user_data */
    })
}


function stalkerTraceRange(tid, base, size) {
    const modMap=new ModuleMap();
    Stalker.follow(tid, {
        transform: (iterator) => {
            const instruction = iterator.next();
            const startAddress = instruction.address;
            const isModuleCode = startAddress.compare(base) >= 0 && 
                startAddress.compare(base.add(size)) < 0;
            const module=modMap.find(startAddress);
            // const isModuleCode = true;
            do {
                iterator.keep();
                if (isModuleCode) {
                    send({
                        type: 'inst',
                        tid: tid,
                        block: startAddress,
                        module: module.name,
                        offset: startAddress.sub(module.base),
                        val: JSON.stringify(instruction)
                    })
                    iterator.putCallout((context) => {
                            send({
                                type: 'ctx',
                                tid: tid,
                                val: JSON.stringify(context)
                            })
                    })
                }
            } while (iterator.next() !== null);
        }
    })
}


function traceAddr(addr) {
    let moduleMap = new ModuleMap();    
    let targetModule = moduleMap.find(addr);
    console.log(JSON.stringify(targetModule))
    let exports = targetModule.enumerateExports();
    let symbols = targetModule.enumerateSymbols();
    // send({
    //     type: "module", 
    //     targetModule
    // })
    // send({
    //     type: "sym",
    

    // })
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.tid = Process.getCurrentThreadId()
            // stalkerTraceRangeC(this.tid, targetModule.base, targetModule.size)
            stalkerTraceRange(this.tid, targetModule.base, targetModule.size)
        },
        onLeave: function(ret) {
            Stalker.unfollow(this.tid);
            Stalker.garbageCollect()
            send({
                type: "fin",
                tid: this.tid
            })
        }
    })
}


function traceSymbol(symbol) {

}

/**
 * from jnitrace-egine
 */
function watcherLib(libname, callback) {
    const dlopenRef = Module.findExportByName(null, "dlopen");
    const dlsymRef = Module.findExportByName(null, "dlsym");
    const dlcloseRef = Module.findExportByName(null, "dlclose");

    if (dlopenRef !== null && dlsymRef !== null && dlcloseRef !== null) {
        const dlopen = new NativeFunction(dlopenRef, "pointer", ["pointer", "int"]);
        Interceptor.replace(dlopen, new NativeCallback((filename, mode) => {
            const path = filename.readCString();
            const retval = dlopen(filename, mode);
    
            if (path !== null) {
                if (checkLibrary(path)) {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    trackedLibs.set(retval.toString(), true);
                } else {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    libBlacklist.set(retval.toString(), true);
                }
            }

            return retval;
        }, "pointer", ["pointer", "int"]));
    }
}
//refs:https://awakened1712.github.io/hacking/hacking-frida/
function waitForLoadLibrary(libName,callback){
    Java.perform(function () {
        const System = Java.use('java.lang.System');
        const Runtime = Java.use('java.lang.Runtime');
        const VMStack = Java.use('dalvik.system.VMStack');

        console.log("Process.platform:", Process.platform);

        // @ts-ignore
        System.loadLibrary.implementation = function (library) {
            try {
                console.log('System.loadLibrary("' + library + '")');
                Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
                if (("lib"+library+".so") !== libName) return;
                console.log("find so:", library);
                callback();
            } catch (ex) {
                console.log(ex);
            }
        };

        // @ts-ignore
        System.load.implementation = function (library) {
            try {
                console.log('System.load("' + library + '")');
                Runtime.getRuntime().nativeLoad(library, VMStack.getCallingClassLoader());
            } catch (ex) {
                console.log(ex);
            }
        };
    });

}
//refs:https://github.com/lasting-yang/frida_dump/blob/3a6f78d4b6f0cfac96708f665ea25032527cb067/dump_dex.js#L117C1-L117C1
function waitForLoadLibraryNative(libName,callback){
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function(args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                console.log("dlopen:", path);
                if (path.indexOf(libName) >= 0) {
                    this.findedLib = true;
                    console.log("[dlopen:]", path);
                }
            }
        },
        onLeave: function(retval) {
            if (this.findedLib) {
               if(callback){
                   callback();
                   callback=null;
               }
            }
        }
    })

    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function(args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                console.log("android_dlopen_ext:", path);
                if (path.indexOf(libName) >= 0) {
                    this.findedLib = true;
                    console.log("[android_dlopen_ext:]", path);
                }
            }
        },
        onLeave: function(retval) {
            if (this.findedLib) {
                if(callback){
                    callback();
                    callback=null;
                }
            }
        }
    });
}
(() => {

    console.log(`----- start trace -----`);

    recv("config", (msg) => {
        const payload = msg.payload;
        console.log(JSON.stringify(payload))
        const libname = payload.libname;
        console.log(`libname:${libname}`)
        function startTrace(){
            const targetModule = Process.getModuleByName(libname);
            let targetAddress = null;
            if("symbol" in payload) {
                targetAddress = targetModule.findExportByName(payload.symbol);
            } else if("offset" in payload) {
                targetAddress = targetModule.base.add(ptr(payload.offset));
            }
            traceAddr(targetAddress)
        }
        if(payload.spawn) {
            waitForLoadLibraryNative(libname,startTrace)
        } else {
            startTrace();
        }
    })
})()