// Hooks for the POSIX dynamic memory allocation routines.
//
// void free(void *ptr);
// void *calloc(size_t nelem, size_t elsize);
// void *realloc(void *ptr, size_t size);
// void *malloc(size_t size);

// Resolve the address of the functions.
var malloc_addr = Module.findExportByName(null, "malloc");
var free_addr = Module.findExportByName(null, "free");
var calloc_addr = Module.findExportByName(null, "calloc");
var realloc_addr = Module.findExportByName(null, "realloc");

console.log("malloc @ " + malloc_addr.toString());
console.log("free @ " + free_addr.toString());
console.log("calloc @ " + calloc_addr.toString());
console.log("realloc @ " + realloc_addr.toString());

var malloc_hook = {
    onEnter: function (args) {
        this.size = args[0];
    },

    onLeave: function (retval) {
        var message = {
            "tid": this.threadId,
            "event": {
                "name": "malloc",
                "size": this.size,
                "ret": retval
            }
        };

        console.log(JSON.stringify(message));
    }
};

var free_hook = {
    onEnter: function (args) {
        this.pointer = args[0]
    },

    onLeave: function (retval) {
        // Skip noisy free(0).
        if (!this.pointer.isNull()) {
            var message = {
                "tid": this.threadId,
                "event": {
                    "name": "free",
                    "size": this.pointer,
                    "ret": null
                }
            };

            console.log(JSON.stringify(message));
        }
    }
};

var calloc_hook = {
    onEnter: function (args) {
        this.nelem = args[0];
        this.size = args[1];
    },

    onLeave: function (retval) {
        var message = {
            "tid": this.threadId,
            "event": {
                "name": "calloc",
                "nelem": this.nelem,
                "size": this.size,
                "ret": retval
            }
        };

        console.log(JSON.stringify(message));
    }
};

var realloc_hook = {
    onEnter: function (args) {
        this.ptr = args[0];
        this.size = args[1];
    },

    onLeave: function (retval) {
        var message = {
            "tid": this.threadId,
            "event": {
                "name": "realloc",
                "ptr": this.ptr,
                "size": this.size,
                "ret": retval
            }
        };

        console.log(JSON.stringify(message));
    }
};

Interceptor.attach(malloc_addr, malloc_hook);
Interceptor.attach(free_addr, free_hook);
Interceptor.attach(calloc_addr, calloc_hook);
Interceptor.attach(realloc_addr, realloc_hook);