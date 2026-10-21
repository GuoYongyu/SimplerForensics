"use strict";
const MAX_STRINGS=5000, MAX_IMPORTS=3000, MAX_SECTIONS=96;
const u16=(v,o)=>v.getUint16(o,true), u32=(v,o)=>v.getUint32(o,true);
const hex=n=>"0x"+Number(n).toString(16).toUpperCase();
const ascii=(b,o,n)=>String.fromCharCode(...b.subarray(o,o+n));
const cstr=(b,o,limit=4096)=>{let e=o;while(e<b.length&&e-o<limit&&b[e])e++;return new TextDecoder("utf-8",{fatal:false}).decode(b.subarray(o,e));};
function md5(data){
 const bitLen=data.length*8, padded=((data.length+9+63)>>6)<<6, msg=new Uint8Array(padded);
 msg.set(data);msg[data.length]=128;
 const dv=new DataView(msg.buffer);dv.setUint32(padded-8,bitLen>>>0,true);dv.setUint32(padded-4,Math.floor(bitLen/4294967296),true);
 const shifts=[7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21], k=new Int32Array(64);
 for(let i=0;i<64;i++)k[i]=Math.floor(Math.abs(Math.sin(i+1))*4294967296)|0;
 let a0=0x67452301|0,b0=0xefcdab89|0,c0=0x98badcfe|0,d0=0x10325476|0;
 for(let off=0;off<padded;off+=64){
  const m=new Int32Array(16);for(let j=0;j<16;j++)m[j]=dv.getInt32(off+j*4,true);
  let a=a0,b=b0,c=c0,d=d0;
  for(let i=0;i<64;i++){let f,g,s;
   if(i<16){f=(b&c)|(~b&d);g=i;s=shifts[i&3];}
   else if(i<32){f=(d&b)|(~d&c);g=(5*i+1)&15;s=shifts[4+(i&3)];}
   else if(i<48){f=b^c^d;g=(3*i+5)&15;s=shifts[8+(i&3)];}
   else{f=c^(b|~d);g=(7*i)&15;s=shifts[12+(i&3)];}
   const x=(a+f+k[i]+m[g])|0, rot=(x<<s)|(x>>>(32-s));
   a=d;d=c;c=b;b=(b+rot)|0;
  }
  a0=(a0+a)|0;b0=(b0+b)|0;c0=(c0+c)|0;d0=(d0+d)|0;
 }
 const out=new Uint8Array(16),o=new DataView(out.buffer);
 [a0,b0,c0,d0].forEach((x,i)=>o.setInt32(i*4,x,true));
 return [...out].map(x=>x.toString(16).padStart(2,"0")).join("");
}
function entropy(bytes){
 if(!bytes.length)return 0;const counts=new Uint32Array(256);
 for(const x of bytes)counts[x]++;
 let h=0;for(const n of counts)if(n){const p=n/bytes.length;h-=p*Math.log2(p);}
 return Math.round(h*100)/100;
}
function parsePE(b){
 const v=new DataView(b.buffer,b.byteOffset,b.byteLength);
 const fail=reason=>({valid:false,reason});
 if(b.length<64||b[0]!==0x4d||b[1]!==0x5a)return fail("文件不含有效的 MZ DOS 头。");
 const peOff=u32(v,0x3c);
 if(peOff<64||peOff+24>b.length)return fail("PE 头偏移超出文件范围。");
 if(u32(v,peOff)!==0x00004550)return fail("未找到 PE\\0\\0 签名。");
 const coff=peOff+4,machine=u16(v,coff),numSections=u16(v,coff+2),timestamp=u32(v,coff+4),optSize=u16(v,coff+16),characteristics=u16(v,coff+18),opt=coff+20;
 if(numSections>MAX_SECTIONS)return fail("节区数量超过安全解析上限。");
 if(opt+optSize>b.length||optSize<2)return fail("Optional Header 不完整或越界。");
 const magic=u16(v,opt),is64=magic===0x20b;
 if(!is64&&magic!==0x10b)return fail("Optional Header Magic 不是 PE32/PE32+。");
 const ddBase=opt+(is64?112:96),numDirsOffset=opt+(is64?108:92);
 const dirCount=Math.min(numDirsOffset+4<=opt+optSize?u32(v,numDirsOffset):0,16);
 const dir=(idx)=>{const at=ddBase+idx*8;return at+8<=opt+optSize?{rva:u32(v,at),size:u32(v,at+4)}:{rva:0,size:0};};
  const findRich=()=>{
   const start=Math.max(0x40,peOff-4096);let rich=-1;
   for(let i=start;i+8<=peOff;i++)if(ascii(b,i,4)==="Rich"){rich=i;break;}
   if(rich<0)return {present:false,entries:[]};
   const key=u32(v,rich+4);let dans=-1;
   for(let i=0x40;i+16<=rich;i+=4)if(((u32(v,i)^key)>>>0)===0x536e6144){dans=i;break;}
   if(dans<0)return {present:true,offset:rich,key:hex(key),entries:[]};
   const entries=[];
   for(let i=dans+16;i+8<=rich;i+=8){
    const product=u32(v,i)^key,count=u32(v,i+4)^key;
    entries.push({productId:product&0xffff,build:product>>>16,count});
   }
   return {present:true,offset:rich,key:hex(key),entries:entries.slice(0,64)};
  };
  const richHeader=findRich();
 const sectionsAt=opt+optSize,sections=[];
 for(let i=0;i<numSections;i++){
  const o=sectionsAt+i*40;if(o+40>b.length)break;
  const name=ascii(b,o,8).replace(/\0.*$/,"").trim()||"(无名称)";
  const virtualSize=u32(v,o+8),virtualAddress=u32(v,o+12),rawSize=u32(v,o+16),rawPointer=u32(v,o+20),flags=u32(v,o+36);
  const start=rawPointer,end=Math.min(b.length,rawPointer+rawSize);
  sections.push({name,virtualSize,virtualAddress,rawSize,rawPointer,characteristics:hex(flags),readable:!!(flags&0x40000000),writable:!!(flags&0x80000000),executable:!!(flags&0x20000000),entropy:start<b.length?entropy(b.subarray(start,end)):0,rangeValid:rawPointer<=b.length&&rawPointer+rawSize<=b.length});
 }
 const rvaToOffset=rva=>{
  if(rva<sectionsAt-sectionsAt+opt+optSize)return rva<b.length?rva:-1;
  for(const s of sections){const size=Math.max(s.virtualSize,s.rawSize);if(rva>=s.virtualAddress&&rva<s.virtualAddress+size){const off=s.rawPointer+(rva-s.virtualAddress);return off<b.length?off:-1;}}
  return -1;
 };
 const imports=[], impDir=dir(1);let importNames=[];
 if(impDir.rva&&impDir.size){
  let off=rvaToOffset(impDir.rva),guard=0;
  while(off>=0&&off+20<=b.length&&guard++<512){
   const oft=u32(v,off),nameRva=u32(v,off+12),ft=u32(v,off+16);
   if(!oft&&!nameRva&&!ft)break;
   const no=rvaToOffset(nameRva),dll=no>=0?cstr(b,no,512):"(无效 DLL 名)";
   const thunkRva=oft||ft,thunkOff=rvaToOffset(thunkRva),names=[];
   if(thunkOff>=0){
    const step=is64?8:4,high=is64?0x8000000000000000n:0x80000000n;
    for(let j=0;j<512&&thunkOff+j*step+step<=b.length;j++){
     let val=is64?v.getBigUint64(thunkOff+j*step,true):BigInt(u32(v,thunkOff+j*step));
     if(val===0n)break;
     let symbol;
     if(val&high)symbol="Ordinal "+String(val&0xffffn);
     else{const hn=rvaToOffset(Number(val));symbol=hn>=0&&hn+2<b.length?cstr(b,hn+2,512):"Hint/Name 无效";}
     names.push(symbol);if(imports.length<MAX_IMPORTS)imports.push({dll,name:symbol});
    }
   }
   importNames.push({dll,names:names.slice(0,100)});
   off+=20;
  }
 }
 const exports=[],expDir=dir(0);
 if(expDir.rva&&expDir.size){
  const e=rvaToOffset(expDir.rva);
  if(e>=0&&e+40<=b.length){
   const nameRva=u32(v,e+12),base=u32(v,e+16),nf=Math.min(u32(v,e+20),1024),nn=Math.min(u32(v,e+24),1024),funcs=rvaToOffset(u32(v,e+28)),names=rvaToOffset(u32(v,e+32)),ords=rvaToOffset(u32(v,e+36)),mod=nameRva?rvaToOffset(nameRva):-1;
   for(let i=0;i<nf&&funcs>=0&&funcs+i*4+4<=b.length;i++){
    const r=u32(v,funcs+i*4);if(!r)continue;let n="",ordinal=base+i;
    if(ords>=0&&names>=0){for(let j=0;j<nn&&ords+j*2+2<=b.length;j++)if(u16(v,ords+j*2)===i){const no=rvaToOffset(u32(v,names+j*4));if(no>=0)n=cstr(b,no,512);break;}}
    exports.push({ordinal,name:n||"(序号导出)",rva:hex(r)});
   }
   if(mod>=0&&exports.length===0)exports.push({module:cstr(b,mod,512)});
  }
 }
 const entry=u32(v,opt+16),imageBase=is64?Number(v.getBigUint64(opt+24,true)):u32(v,opt+28);
  let pdbPath=null;
  const debugDir=dir(6),debugOff=debugDir.rva?rvaToOffset(debugDir.rva):-1;
  if(debugOff>=0){const count=Math.min(Math.floor(debugDir.size/28),64);for(let i=0;i<count;i++){const at=debugOff+i*28;if(at+28>b.length)break;const type=u32(v,at+12),size=u32(v,at+16),raw=u32(v,at+24);if(type===2&&size>=24&&raw+24<=b.length&&ascii(b,raw,4)==="RSDS"){pdbPath=cstr(b,raw+24,1024);break;}}}
 const compileDate=timestamp===0||timestamp===0xffffffff?null:new Date(timestamp*1000).toISOString();
 const sectionEnd=Math.min(b.length,sectionsAt+numSections*40);
 const overlayStart=Math.max(sectionEnd,...sections.map(s=>s.rawPointer+s.rawSize),0);
 const directories={export:dir(0),import:dir(1),resource:dir(2),security:dir(4),debug:dir(6),clr:dir(14)};
 const warnings=[];
 if(timestamp===0||timestamp===0xffffffff)warnings.push("PE 时间戳为特殊值，不代表有效日期。");
 if(sections.some(s=>!s.rangeValid))warnings.push("至少一个节区声明范围超出文件长度。");
 if(sections.some(s=>s.writable&&s.executable))warnings.push("存在同时可写和可执行的节区；这是一项结构提示，不单独证明恶意。");
 if(overlayStart<b.length)warnings.push("检测到 PE 结构末尾后的附加数据 (Overlay)。");
  return {valid:true,format:"PE",architecture:machine===0x14c?"x86":machine===0x8664?"x64":machine===0xaa64?"ARM64":hex(machine),machine:hex(machine),is64,sectionsCount:numSections,compileDate,timestamp,entryPointRva:hex(entry),imageBase:hex(imageBase),subsystem:u16(v,opt+68),characteristics:hex(characteristics),fileAlignment:u32(v,opt+36),sectionAlignment:u32(v,opt+32),sizeOfImage:u32(v,opt+56),sections,imports,importNames,exports,directories,richHeader,pdbPath,overlayBytes:overlayStart<b.length?b.length-overlayStart:0,warnings,peOffset:peOff,optionalMagic:hex(magic)};
}
function extractStrings(b){
 const out=[],seen=new Set();
 const add=(value,offset,encoding)=>{value=value.replace(/\0/g,"").trim();if(value.length<5||seen.has(encoding+":"+offset+":"+value))return;seen.add(encoding+":"+offset+":"+value);out.push({value:value.slice(0,512),offset,encoding});};
 for(let i=0;i<b.length&&out.length<MAX_STRINGS;){
  if(b[i]>=0x20&&b[i]<=0x7e){const s=i;while(i<b.length&&b[i]>=0x20&&b[i]<=0x7e)i++;if(i-s>=5)add(ascii(b,s,i-s),s,"ASCII");}
  else i++;
 }
 for(let i=0;i+10<b.length&&out.length<MAX_STRINGS;){
  if(b[i]>=0x20&&b[i]<=0x7e&&b[i+1]===0){const s=i,chars=[];while(i+1<b.length&&b[i]>=0x20&&b[i]<=0x7e&&b[i+1]===0){chars.push(b[i]);i+=2;}if(chars.length>=5)add(String.fromCharCode(...chars),s,"UTF-16LE");}
  else i++;
 }
 out.sort((a,b)=>a.offset-b.offset);
 return out;
}
const BUILTIN_RULES=[
 {id:"PE-001",title:"PE 文件包含可执行且可写节区",kind:"structure"},
 {id:"PE-002",title:"节区熵值较高",kind:"structure"},
 {id:"PE-003",title:"PE 结构后存在 Overlay 数据",kind:"structure"},
 {id:"PE-004",title:"节区名称带有常见 UPX 标记",kind:"structure"},
 {id:"API-001",title:"导入表包含进程注入相关 API",kind:"imports"},
 {id:"API-002",title:"导入表包含凭据/进程访问相关 API",kind:"imports"},
 {id:"API-003",title:"导入表同时出现文件枚举和加密 API",kind:"imports"},
 {id:"STR-001",title:"字符串包含 PowerShell 编码命令线索",kind:"strings"},
 {id:"STR-002",title:"字符串包含启动项注册表路径",kind:"strings"},
 {id:"STR-003",title:"字符串包含 URL 或 IP 地址",kind:"strings"},
 {id:"STR-004",title:"字符串包含疑似勒索说明文本",kind:"strings"},
 {id:"STR-005",title:"检测到嵌入的 MZ/PE 文件头",kind:"bytes"}
];
function scanRules(b,pe,strings,customRules=[]){
 const hits=[],text=strings.map(x=>x.value).join("\n"),lower=text.toLowerCase(),imps=new Set((pe?.imports||[]).map(x=>x.name.toLowerCase())),sec=pe?.sections||[];
 const add=(id,evidence,offset=null,severity="info")=>{const r=BUILTIN_RULES.find(x=>x.id===id);hits.push({id,title:r?.title||id,severity,evidence,offset});};
 if(pe?.valid){
  if(sec.some(s=>s.writable&&s.executable))add("PE-001","至少一个节区同时具备写入和执行属性。",null,"warning");
  const high=sec.filter(s=>s.entropy>=7.2);
  for(const s of high.slice(0,5))add("PE-002",s.name+" 节区熵值 "+s.entropy+" bits/byte。",s.rawPointer,"info");
  if(pe.overlayBytes)add("PE-003","文件尾存在 "+pe.overlayBytes+" 字节未纳入常规节区范围的数据。",null,"info");
  for(const s of sec)if(/upx[0-9]|upx!/i.test(s.name))add("PE-004","发现节区名 "+s.name+"。",s.rawPointer,"info");
 }
 const hasAny=names=>names.some(n=>imps.has(n.toLowerCase()));
 if(hasAny(["WriteProcessMemory","VirtualAllocEx","CreateRemoteThread","NtWriteVirtualMemory"])&&hasAny(["OpenProcess","VirtualAllocEx","CreateRemoteThread","NtCreateThreadEx"]))add("API-001","导入表命中多个进程操作 API："+["WriteProcessMemory","VirtualAllocEx","CreateRemoteThread","NtWriteVirtualMemory","OpenProcess","NtCreateThreadEx"].filter(n=>imps.has(n.toLowerCase())).join(", ")+".",null,"warning");
 if(hasAny(["OpenProcess","MiniDumpWriteDump","ReadProcessMemory","NtReadVirtualMemory"]))add("API-002","导入表出现进程访问或内存读取 API。",null,"info");
 const enc=hasAny(["CryptEncrypt","BCryptEncrypt","CryptAcquireContextW","BCryptGenerateSymmetricKey"]),enumf=hasAny(["FindFirstFileW","FindNextFileW","NtQueryDirectoryFile"]);
 if(enc&&enumf)add("API-003","同时导入文件枚举和加密相关 API。",null,"warning");
 if(/powershell(?:\.exe)?[\s\S]{0,80}-(?:enc|encodedcommand)\b/i.test(text)||lower.includes("frombase64string"))add("STR-001","字符串中出现 PowerShell 编码参数或 Base64 解码线索。",strings.find(x=>/powershell|frombase64string/i.test(x.value))?.offset||null,"warning");
 const runKey=/software\\microsoft\\windows\\currentversion\\run(?:once)?/i.exec(text);
 if(runKey)add("STR-002","字符串包含 Windows Run/RunOnce 注册表路径。",strings.find(x=>runKey[0]&&x.value.toLowerCase().includes(runKey[0].toLowerCase()))?.offset||null,"info");
 const urls=strings.filter(x=>/(?:https?|ftp):\/\/|(?:\b\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/i.test(x.value)).slice(0,8);
 for(const x of urls)add("STR-003",x.value.slice(0,180),x.offset,"info");
 const ransom=strings.find(x=>/your files (?:have been|are) encrypted|decrypt your files|personal files.*encrypted/i.test(x.value));
 if(ransom)add("STR-004",ransom.value.slice(0,180),ransom.offset,"warning");
 const mz=[];for(let i=1;i+1<b.length&&mz.length<8;i++)if(b[i]===0x4d&&b[i+1]===0x5a)mz.push(i);
 for(const off of mz)add("STR-005","文件内部偏移 "+hex(off)+" 发现 MZ 标记；可能是嵌入数据，也可能是偶然匹配。",off,"info");
 for(const rule of (Array.isArray(customRules)?customRules:[]).slice(0,100)){
  const patterns=(Array.isArray(rule.strings)?rule.strings:[]).filter(x=>typeof x==="string"&&x.length>0&&x.length<=256).slice(0,20);
  if(!patterns.length)continue;
  const sensitive=!!rule.caseSensitive;
  const found=patterns.map(pattern=>strings.find(item=>sensitive?item.value.includes(pattern):item.value.toLowerCase().includes(pattern.toLowerCase()))||null);
  const condition=rule.condition==="all"?"all":"any",matched=condition==="all"?found.every(Boolean):found.some(Boolean);
  if(matched){const matches=found.filter(Boolean);hits.push({id:String(rule.id||"CUSTOM").slice(0,80),title:String(rule.title||"本地自定义规则").slice(0,160),severity:rule.severity==="warning"?"warning":"info",evidence:matches.map(item=>item.value.slice(0,160)).join(" | "),offset:matches[0]?.offset??null});}
 }
 return hits;
}
function detectLanguage(b,pe,strings){
 const corpus=strings.map(x=>x.value).join("\n"),lower=corpus.toLowerCase(),sections=(pe?.sections||[]).map(s=>s.name.toLowerCase()),dlls=(pe?.importNames||[]).map(x=>x.dll.toLowerCase());
 const scores=new Map(),evidence=new Map(),compiler=[];
 const hit=(lang,score,why)=>{scores.set(lang,(scores.get(lang)||0)+score);if(!evidence.has(lang))evidence.set(lang,[]);evidence.get(lang).push(why);};
 if(pe?.directories?.clr?.rva){hit(".NET 托管语言",6,"PE 的 CLR Runtime Header 目录非空");}
 if(/mscoree\.dll|mscorlib|system\.private\.corelib/.test(lower)||dlls.some(x=>/mscoree|mscorlib/.test(x)))hit(".NET 托管语言",3,"发现 CLR/.NET 运行时标记");
 if(/go buildid|gopclntab|runtime\.morestack|runtime\.gopanic|go\.buildinfo/.test(lower)||sections.some(x=>x===".gopclntab"||x===".go.buildinfo"))hit("Go",5,"发现 Go runtime/build 元数据或典型节区");
 if(/rustc version|rust_begin_unwind|rust_eh_personality|core::panicking|alloc::/.test(lower)||sections.some(x=>x===".rustc"))hit("Rust",5,"发现 Rust runtime/编译器符号或节区线索");
 if(/vcruntime\d*\.dll|msvcp\d+\.dll|msvcr\d+\.dll|msvcrt\.dll|ucrtbase\.dll|api-ms-win-crt-|__cxxframehandler|microsoft visual c\+\+/.test(lower)||dlls.some(x=>/^(?:vcruntime|msvcp|msvcr|ucrtbase|api-ms-win-crt)/.test(x)))hit("C/C++ (Microsoft CRT/MSVC 工具链线索)",3,"发现 Microsoft C/C++ 运行库或相关符号");
 if(pe?.richHeader?.present){hit("C/C++ (MSVC 工具链线索)",2,"发现 PE Rich Header 编译器记录；它反映构建工具痕迹，不单独证明源代码语言");}
 if(pe?.pdbPath&&/(?:visual studio|msvc|\\bcl\\.exe\\b)/i.test(pe.pdbPath))hit("C/C++ (MSVC 工具链线索)",2,"CodeView 调试目录包含 PDB 路径："+pe.pdbPath);
 if(/libstdc\+\+|libgcc_s|mingw|g\+\+/.test(lower)||dlls.some(x=>/libstdc\+\+|libgcc/.test(x)))hit("C/C++ (GCC/MinGW 工具链线索)",3,"发现 GCC/MinGW 运行库标记");
 if(/borland|delphi|tform|system\.classes|@(?:system|vcl)\./.test(lower)||sections.some(x=>x===".bss"&&lower.includes("borland")))hit("Delphi/Pascal",4,"发现 Delphi/Borland 运行库或符号线索");
 if(/visual basic|msvbvm\d+|vba6|vbrun\d+/.test(lower)||dlls.some(x=>/msvbvm|vbrun/.test(x)))hit("Visual Basic",4,"发现 Visual Basic 运行库标记");
 if(/pyinstaller|python\d+\.dll|py_initialize|pyimod\d+/.test(lower)||dlls.some(x=>/^python\d+/.test(x)))hit("Python 打包程序",4,"发现 Python 运行时或打包器标记");
 if(/autoit|aut2exe/.test(lower)||sections.some(x=>/^(?:\.itext|\.script)$/.test(x)))hit("AutoIt",3,"发现 AutoIt 运行时或节区线索");
 if(/electron|node\.dll|nodejs/.test(lower)||dlls.some(x=>x==="node.dll"))hit("JavaScript/Node.js 打包程序",3,"发现 Node.js/Electron 运行时线索");
 if(pe?.valid){
  if(dlls.some(x=>/^(?:vcruntime|msvcp|msvcr|ucrtbase|api-ms-win-crt)/.test(x)))compiler.push("Microsoft C/C++ Runtime");
  if(pe.richHeader?.present)compiler.push("PE Rich Header（MSVC 系构建痕迹）");
  if(pe.pdbPath)compiler.push("CodeView PDB："+pe.pdbPath);
  if(dlls.some(x=>/libstdc\+\+|libgcc/.test(x)))compiler.push("GCC / MinGW 运行库");
  if(dlls.some(x=>/mscoree/.test(x))||pe.directories.clr.rva)compiler.push(".NET CLR");
 }
 const ranked=[...scores.entries()].map(([language,score])=>({language,score,evidence:evidence.get(language)||[]})).sort((a,b)=>b.score-a.score);
 let result;
 if(!ranked.length)result={language:"无法确定",confidence:"低",candidates:[],note:"文件中未发现足够的编译语言或运行时证据。"};
 else{
  const best=ranked[0],confidence=best.score>=6?"高":best.score>=4?"中":"低";
  result={language:best.language,confidence,candidates:ranked.slice(0,4),compiler:[...new Set(compiler)],note:"语言识别依据可见的静态特征；混合语言、裁剪、加壳和自定义工具链可能导致漏报或误报。"};
 }
 return result;
}
async function hashes(b){
 const out={MD5:md5(b)};
 for(const alg of ["SHA-1","SHA-256","SHA-384","SHA-512"]){
  const digest=await crypto.subtle.digest(alg,b);
  out[alg]=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,"0")).join("");
 }
 return out;
}
self.onmessage=async event=>{
 const {file,id,rules:customRules=[]}=event.data||{};
 if(!file)return;
 try{
  if(file.size>128*1024*1024)throw new Error("单文件上限为 128 MiB。");
  self.postMessage({id,type:"progress",value:5,label:"读取文件"});
  const buf=await file.arrayBuffer(),bytes=new Uint8Array(buf);
  self.postMessage({id,type:"progress",value:15,label:"计算哈希"});
  const fileHashes=await hashes(bytes);
  self.postMessage({id,type:"progress",value:42,label:"解析 PE 结构"});
  const pe=parsePE(bytes);
  self.postMessage({id,type:"progress",value:58,label:"提取字符串"});
  const strings=extractStrings(bytes);
  self.postMessage({id,type:"progress",value:80,label:"识别语言并扫描本地规则"});
  const language=detectLanguage(bytes,pe,strings),rules=scanRules(bytes,pe,strings,customRules);
  const iocs=strings.filter(x=>/(?:https?|ftp):\/\/|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b|\\registry\\|software\\microsoft\\windows\\currentversion\\run|\b(?:cmd|powershell|rundll32|regsvr32|schtasks)\.exe\b/i.test(x.value)).slice(0,200);
  self.postMessage({id,type:"result",result:{file:{name:file.name,size:file.size,lastModified:file.lastModified?new Date(file.lastModified).toISOString():null},hashes:fileHashes,pe,language,strings:strings.slice(0,1200),stringsTotal:strings.length,iocs,rules}});
 }catch(e){self.postMessage({id,type:"error",error:e?.message||String(e)});}
};
