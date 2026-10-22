(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const state = { rows: [], duplicates: 0, invalid: 0, sources: [], visible: 100, busy: false };
  const EXTENSIONS = new Set(['txt','csv','tsv','vcf','vcard','ldif','json','jsonl','ndjson','xml','html','htm','mhtml','eml','mbox','sql','log','md','yaml','yml','ini','conf','properties','xlsx','xlsm','xltx','xls','ods','ots','db','sqlite','sqlite3','db3','s3db','mdb','accdb','dbf','docx','odt','rtf','pdf','zip','epub','ics','bak','dat','contact','ab','addressbook','vcf3']);
  const KNOWN_ZIP_TEXT = /\.(?:xml|rels|txt|csv|json|html|htm|vcf|vcard|ldif|sql|md|yaml|yml|eml)$/i;
  const PHONE_HEADERS = /(?:^|[^a-z])(mobile|cell|phone|telephone|tel|contact|号码|手机|电话|联系电话|手机号|移动电话)(?:$|[^a-z])/i;
  const carrierNames = { 1:'中国移动',2:'中国联通',3:'中国电信',4:'中国广电',5:'铁通',6:'天音移动',7:'小米移动',8:'星美通讯',9:'星美通信',10:'长江时代',11:'海航通信',12:'国美极信',13:'民生通讯',14:'朗玛移动',15:'迪信通',16:'京东通信',17:'分享在线',18:'话机通信',19:'话机世界',20:'用友通信',21:'三五互联',22:'联想懂的',23:'连连科技',24:'丰信通信',25:'乐语通信',26:'爱施德',27:'虚拟运营商',28:'中兴视通',29:'中邮世纪',30:'世纪互联',31:'银盛通信',32:'中邮普泰',33:'华翔联信',34:'苏宁互联',35:'鹏博士移动',36:'国美通信',37:'优友互联',38:'博元讯息',39:'阿里通信',40:'中期移动',41:'远特信时空',42:'广东恒大',43:'红豆集团',44:'星美生活',45:'网信移动',46:'分享通信',47:'无限互联',48:'日日顺通信',49:'北纬通信',50:'远特通信',51:'长城移动',52:'中麦通信',53:'巴士在线',54:'普泰移动',55:'蜗牛移动',56:'全民优打',57:'豆电信',58:'优酷移动',59:'华云互联' };
  const virtualPrefixToBase = {165:1,1703:1,1705:1,1706:1,167:2,1704:2,1707:2,1708:2,1709:2,1710:2,1711:2,1712:2,1713:2,1714:2,1715:2,1716:2,1717:2,1718:2,1719:2,162:3,1700:3,1701:3,1702:3};
  let phoneDb = null;

  function parseDatabase(encoded) {
    const binary = atob(encoded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const view = new DataView(bytes.buffer);
    const decoder = new TextDecoder('utf-8');
    if (decoder.decode(bytes.subarray(0,4)) !== 'JPHN' || view.getUint16(4,true) !== 2) throw Error('归属地数据库格式或版本不受支持。');
    const count = view.getUint32(8,true), indexOffset = view.getUint32(12,true), indexLength = view.getUint32(16,true), dictOffset = view.getUint32(20,true), dictLength = view.getUint32(24,true), cityCount = view.getUint32(28,true);
    if (count > 1000000 || indexLength !== count * 10 || indexOffset + indexLength > bytes.length || dictOffset + dictLength > bytes.length || cityCount > 100000) throw Error('归属地数据库结构校验失败。');
    const cities = new Array(cityCount); let cursor = dictOffset;
    const readString = () => { if (cursor + 2 > dictOffset + dictLength) throw Error('地区字典已截断。'); const len = view.getUint16(cursor,true); cursor += 2; if (cursor + len > dictOffset + dictLength) throw Error('地区字典长度无效。'); const s = decoder.decode(bytes.subarray(cursor,cursor+len)); cursor += len; return s; };
    for (let i=0;i<cityCount;i++) cities[i] = { province:readString(), city:readString() };
    return { bytes, view, count, indexOffset, cities };
  }
  try {
    if (window.PHONE_LOOKUP_DATA) { phoneDb = parseDatabase(window.PHONE_LOOKUP_DATA); $('db-badge').textContent = `${phoneDb.count.toLocaleString()} 条号段 · 2026.05`; }
    else throw Error('未找到随页面提供的离线号段数据。');
  } catch (error) { $('db-badge').textContent = '号段数据库不可用'; $('db-badge').classList.add('warning-chip'); $('single-result').textContent = error.message; }

  function lookup(number) {
    if (!phoneDb) return null;
    const n = Number(number.slice(0,7)); let left=0,right=phoneDb.count-1;
    while (left <= right) {
      const mid = (left + right) >>> 1, offset = phoneDb.indexOffset + mid * 10, prefix = phoneDb.view.getUint32(offset,true);
      if (prefix === n) { const cityId=phoneDb.view.getUint32(offset+4,true), carrierId=phoneDb.view.getUint16(offset+8,true);if(cityId>=phoneDb.cities.length)return null;const rawCarrier=carrierNames[carrierId]||'未知运营商',base=virtualPrefixToBase[Number(number.slice(0,4))]||virtualPrefixToBase[Number(number.slice(0,3))];return { ...phoneDb.cities[cityId], carrierId, operator:carrierId>=5?(carrierNames[base]||'虚拟运营商'):rawCarrier, virtual:carrierId>=5?rawCarrier:'' }; }
      if (prefix < n) left=mid+1; else right=mid-1;
    }
    return null;
  }
  function normalizePhone(raw) {
    let value = String(raw).trim().replace(/[\u200e\u200f\u202a-\u202e]/g,'');
    value = value.replace(/^(?:\+?86|0086)[\s().\-－—]*/, '');
    const digits = value.replace(/\D/g,'');
    return /^(?:1[3-9]\d{9}|1[3-9]\d{5})$/.test(digits) ? digits : null;
  }
  function findPhones(text, source, opts={}) {
    const found=[]; const re=/(?:\+?86|0086)?[\s().\-－—]*1[3-9](?:[\s().\-－—]*\d){9}/g;
    let m;
    while ((m=re.exec(text))) {
      const before=text[m.index-1]||'', after=text[m.index+m[0].length]||'';
      if (/\d/.test(before) || /\d/.test(after)) continue;
      const number=normalizePhone(m[0]); if (!number) continue;
      const lineStart=text.lastIndexOf('\n',m.index)+1, lineEnd=text.indexOf('\n',re.lastIndex);
      const context=text.slice(lineStart,lineEnd<0?Math.min(text.length,lineStart+240):lineEnd).replace(/\s+/g,' ').trim().slice(0,200);
      if (opts.preferPhoneColumns && context && !PHONE_HEADERS.test(context) && !/(?:TEL|PHONE|MOBILE|电话|手机|号码)\s*[;:=]/i.test(context)) continue;
      found.push({ number, source, context, _index:m.index });
    }
    return found;
  }
  async function findPhonesAsync(text, source) {
    const chunkSize=1024*1024;
    if(text.length<=chunkSize)return findPhones(text,source).map(({_index,...row})=>row);
    const found=[];
    for(let start=0;start<text.length;start+=chunkSize){
      const end=Math.min(text.length,start+chunkSize),from=Math.max(0,start-64),to=Math.min(text.length,end+64);
      for(const row of findPhones(text.slice(from,to),source)){const absolute=from+row._index;if(absolute>=start&&absolute<end){row.context=text.slice(Math.max(0,text.lastIndexOf('\n',absolute)+1),text.indexOf('\n',absolute)<0?Math.min(text.length,absolute+240):text.indexOf('\n',absolute)).replace(/\s+/g,' ').trim().slice(0,200);delete row._index;found.push(row);}}
      await new Promise(resolve=>setTimeout(resolve,0));
    }
    return found;
  }
  function decodeBytes(buffer) {
    const bytes=new Uint8Array(buffer); let encoding='utf-8', offset=0;
    if (bytes[0]===0xef&&bytes[1]===0xbb&&bytes[2]===0xbf) offset=3;
    else if(bytes[0]===0xff&&bytes[1]===0xfe){encoding='utf-16le';offset=2;}
    else if(bytes[0]===0xfe&&bytes[1]===0xff){encoding='utf-16be';offset=2;}
    try { return { text:new TextDecoder(encoding).decode(bytes.subarray(offset)), binary:false }; } catch {}
    try { return { text:new TextDecoder('gb18030').decode(bytes), binary:false }; } catch {}
    return { text:new TextDecoder('windows-1252').decode(bytes), binary:true };
  }
  function extractStructuredText(text, ext) {
    if (ext==='json'||ext==='jsonl'||ext==='ndjson') {
      try { const value=JSON.parse(text); const chunks=[]; const walk=(v,key='')=>{ if(v==null)return; if(typeof v==='string'||typeof v==='number'){if(PHONE_HEADERS.test(key)||String(v).match(/1[3-9]/))chunks.push(String(v));return;} if(Array.isArray(v)){v.forEach(x=>walk(x,key));return;} if(typeof v==='object')for(const [k,x] of Object.entries(v))walk(x,k);}; walk(value); return chunks.join('\n'); } catch { if(ext==='json') return text; }
    }
    if(ext==='xml'||ext==='html'||ext==='htm') {
      try { const doc=new DOMParser().parseFromString(text, ext==='xml'?'application/xml':'text/html'); if(doc.querySelector('parsererror'))return text; const vals=[]; doc.querySelectorAll('*').forEach(el=>{if(el.childElementCount===0&&el.textContent.trim()) vals.push(el.textContent);for(const a of el.attributes)vals.push(a.value);}); return vals.join('\n'); } catch { return text; }
    }
    if(ext==='ldif') {
      const lines=text.replace(/\r?\n[ \t]/g,'').split(/\r?\n/), values=[];
      for(const line of lines){const m=line.match(/^(?:mobile|telephoneNumber|homePhone|pager|facsimileTelephoneNumber|otherTelephone|phone|tel)\s*(:{1,2})\s*(.*)$/i); if(!m)continue; let v=m[2]; if(m[1]==='::')try{v=decodeBytes(Uint8Array.from(atob(v),c=>c.charCodeAt(0)).buffer).text;}catch{} values.push(v);}
      return values.join('\n')+'\n'+text;
    }
    return text;
  }
  function readU16(v,p){return v.getUint16(p,true);} function readU32(v,p){return v.getUint32(p,true);}
  async function inflateZipEntry(bytes, method) {
    if(method===0)return bytes;
    if(method!==8||typeof DecompressionStream==='undefined')throw Error('此浏览器不支持解压 ZIP / Office 文档。');
    const stream=new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    const out=new Uint8Array(await new Response(stream).arrayBuffer()); if(out.length>100*1024*1024)throw Error('解压内容超过 100 MiB 上限。'); return out;
  }
  async function readZipEntries(buffer) {
    const bytes=new Uint8Array(buffer), v=new DataView(buffer); let eocd=-1;
    for(let i=bytes.length-22;i>=Math.max(0,bytes.length-65558);i--)if(readU32(v,i)===0x06054b50){eocd=i;break;}
    if(eocd<0)throw Error('未找到 ZIP 中央目录。');
    const entries=readU16(v,eocd+10), dirOffset=readU32(v,eocd+16); let p=dirOffset; const out=[]; let expandedTotal=0;
    if(entries>10000)throw Error('压缩包文件数量超过 10,000 项上限。');
    for(let i=0;i<entries;i++){
      if(readU32(v,p)!==0x02014b50)break;
      const method=readU16(v,p+10), compressed=readU32(v,p+20), nameLen=readU16(v,p+28), extraLen=readU16(v,p+30), commentLen=readU16(v,p+32), local=readU32(v,p+42);
      const name=new TextDecoder().decode(bytes.subarray(p+46,p+46+nameLen)); p+=46+nameLen+extraLen+commentLen;
      if(!KNOWN_ZIP_TEXT.test(name))continue;
      if(readU32(v,local)!==0x04034b50)continue;
      const localName=readU16(v,local+26), localExtra=readU16(v,local+28), start=local+30+localName+localExtra;
      const data=await inflateZipEntry(bytes.subarray(start,start+compressed),method);
      expandedTotal+=data.length;if(expandedTotal>100*1024*1024)throw Error('压缩包可读文本超过 100 MiB 上限。');
      out.push({name,text:decodeBytes(data.buffer.slice(data.byteOffset,data.byteOffset+data.byteLength)).text});
    }
    return out;
  }
  function xlsxText(entries) {
    const files=new Map(entries.map(e=>[e.name,e.text])); const shared=[];
    const strings=files.get('xl/sharedStrings.xml');
    if(strings){const doc=new DOMParser().parseFromString(strings,'application/xml'); doc.querySelectorAll('si').forEach(si=>shared.push(Array.from(si.getElementsByTagName('t')).map(x=>x.textContent).join('')));}
    const chunks=[];
    for(const [name,xml] of files){if(!/^xl\/worksheets\/sheet\d+\.xml$/i.test(name))continue;const doc=new DOMParser().parseFromString(xml,'application/xml');doc.querySelectorAll('c').forEach(cell=>{const t=cell.getAttribute('t'),v=cell.getElementsByTagName('v')[0],inline=cell.getElementsByTagName('is')[0];if(t==='s'&&v)chunks.push(shared[Number(v.textContent)]||'');else if(inline)chunks.push(Array.from(inline.getElementsByTagName('t')).map(x=>x.textContent).join(''));else if(v)chunks.push(v.textContent);});}
    return chunks.join('\n');
  }
  function odsText(entries) { const content=entries.find(e=>e.name==='content.xml');if(!content)return entries.map(e=>e.text).join('\n');try{const doc=new DOMParser().parseFromString(content.text,'application/xml');return Array.from(doc.getElementsByTagName('table:table-cell')).map(cell=>cell.textContent).join('\n');}catch{return content.text;} }
  function readXls(buffer) {
    const b=new Uint8Array(buffer),v=new DataView(buffer),sig=[0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1]; if(!sig.every((x,i)=>b[i]===x))throw Error('不是可识别的 OLE / XLS 文件。');
    const sectorSize=1<<readU16(v,30),miniSize=1<<readU16(v,32),firstDir=readU32(v,48),miniCut=readU32(v,56),firstMiniFat=readU32(v,60),miniFatCount=readU32(v,64),difatStart=readU32(v,68),difatCount=readU32(v,72);
    const sector=(id)=>b.subarray((id+1)*sectorSize,(id+2)*sectorSize); const difat=[]; for(let i=0;i<109;i++){const x=readU32(v,76+i*4);if(x<0xfffffffa)difat.push(x);} let ds=difatStart;for(let n=0;n<difatCount&&ds<0xfffffffa;n++){const s=sector(ds),sv=new DataView(s.buffer,s.byteOffset,s.byteLength);for(let p=0;p<sectorSize-4;p+=4){const x=sv.getUint32(p,true);if(x<0xfffffffa)difat.push(x);}ds=sv.getUint32(sectorSize-4,true);}
    const fat=[]; for(const id of difat){const s=sector(id),sv=new DataView(s.buffer,s.byteOffset,s.byteLength);for(let p=0;p<s.length;p+=4)fat.push(sv.getUint32(p,true));}
    const readChain=(start,table,max=100000)=>{const parts=[],seen=new Set();let id=start,total=0;while(id<0xfffffffa&&id<table.length&&parts.length<max&&!seen.has(id)){seen.add(id);const data=sector(id);parts.push(data);total+=data.length;id=table[id];if(total>128*1024*1024)throw Error('XLS 工作簿超过 128 MiB 上限。');}const out=new Uint8Array(total);let p=0;for(const part of parts){out.set(part,p);p+=part.length;}return out;};
    const directory=readChain(firstDir,fat), entries=[];for(let p=0;p+128<=directory.length;p+=128){const n=new DataView(directory.buffer,directory.byteOffset+p,128).getUint16(64,true);if(n>=2){const name=new TextDecoder('utf-16le').decode(directory.subarray(p,p+n-2));entries.push({name,type:directory[p+66],start:readU32(new DataView(directory.buffer,directory.byteOffset+p,128),116),size:Number(new DataView(directory.buffer,directory.byteOffset+p,128).getBigUint64(120,true))});}}
    const root=entries.find(e=>e.type===5), workbook=entries.find(e=>/^(Workbook|Book)$/.test(e.name));if(!workbook)throw Error('OLE 文件内未找到 BIFF 工作簿流。');
    const miniFatBytes=firstMiniFat<0xfffffffa&&miniFatCount?readChain(firstMiniFat,fat,miniFatCount):new Uint8Array(), miniFat=[];for(let p=0;p+4<=miniFatBytes.length;p+=4)miniFat.push(new DataView(miniFatBytes.buffer,miniFatBytes.byteOffset+p,4).getUint32(0,true));
    let stream;if(workbook.size<miniCut&&root){const rootBytes=readChain(root.start,fat);const parts=[],seen=new Set();let id=workbook.start,total=0;while(id<0xfffffffa&&id<miniFat.length&&!seen.has(id)&&total<workbook.size){seen.add(id);const start=id*miniSize;parts.push(rootBytes.subarray(start,start+miniSize));total+=miniSize;id=miniFat[id];}stream=new Uint8Array(Math.min(total,workbook.size));let at=0;for(const part of parts){stream.set(part.subarray(0,stream.length-at),at);at+=Math.min(part.length,stream.length-at);}}else stream=readChain(workbook.start,fat).subarray(0,workbook.size);
    const sv=new DataView(stream.buffer,stream.byteOffset,stream.byteLength), records=[];for(let p=0;p+4<=stream.length;){const id=sv.getUint16(p,true),len=sv.getUint16(p+2,true);if(p+4+len>stream.length)break;records.push({id,data:stream.subarray(p+4,p+4+len)});p+=4+len;}
    const all=[];for(const r of records){if([0x00fc,0x003c,0x0204,0x00d6].includes(r.id)){let ascii='';for(const ch of r.data){if(ch>=48&&ch<=57)ascii+=String.fromCharCode(ch);else{if(ascii.length>=11&&ascii.length<=16)all.push(ascii);ascii='';}}if(ascii.length>=11&&ascii.length<=16)all.push(ascii);}
      const d=r.data,dv=new DataView(d.buffer,d.byteOffset,d.byteLength);if(r.id===0x0203&&d.length>=14){const n=dv.getFloat64(6,true);if(Number.isInteger(n)&&n>=10000000000&&n<=19999999999)all.push(String(n));}
      if(r.id===0x027e&&d.length>=10){const raw=dv.getUint32(6,true),n=(raw&2)?((raw>>2)>>0):( (()=>{const x=new DataView(new ArrayBuffer(8));x.setUint32(4,raw&0xfffffffc,true);return x.getFloat64(0,true);})() );const value=raw&1?n/100:n;if(Number.isInteger(value)&&value>=10000000000&&value<=19999999999)all.push(String(value));}
      if(r.id===0x00bd&&d.length>=6){const lastCol=dv.getUint16(d.length-2,true),firstCol=dv.getUint16(2,true),cells=Math.min(256,lastCol-firstCol+1);for(let i=0;i<cells;i++){const pos=6+i*6,raw=pos+4<=d.length-2?dv.getUint32(pos,true):0,n=(raw&2)?(raw>>2):(()=>{const x=new DataView(new ArrayBuffer(8));x.setUint32(4,raw&0xfffffffc,true);return x.getFloat64(0,true);})();const value=raw&1?n/100:n;if(Number.isInteger(value)&&value>=10000000000&&value<=19999999999)all.push(String(value));}}
    }
    return [...new Set(all)].join('\n')+'\n'+new TextDecoder('utf-16le').decode(stream);
  }
  function addFindings(findings) {
    const map=new Map(state.rows.map(r=>[r.number,r]));
    for(const item of findings){if(map.has(item.number)){state.duplicates++;continue;}const info=lookup(item.number);const row={...item,...(info||{}), province:info?.province||'未命中',city:info?.city||'未命中',operator:info?.operator||'暂无号段记录',remark:info?.virtual?`虚拟运营商品牌：${info.virtual}`:info?'号段归属':'无号段记录'};map.set(item.number,row);state.rows.push(row);}
  }
  function setStatus(message,kind='success') { const el=$('batch-status');el.hidden=false;el.className=`status ${kind}`;el.textContent=message; }
  function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
  function render() {
    const rows=state.rows, matched=rows.filter(r=>r.province!=='未命中'), prov=new Map(), ops=new Map(), cities=new Map();
    for(const r of matched){prov.set(r.province,(prov.get(r.province)||0)+1);ops.set(r.operator,(ops.get(r.operator)||0)+1);const k=`${r.province} ${r.city}`;cities.set(k,(cities.get(k)||0)+1);}
    $('results').hidden=!rows.length; if(!rows.length)return;
    const counts=[['有效号码',rows.length,'已去重'],['命中归属地',matched.length,`${rows.length?Math.round(matched.length/rows.length*100):0}% 覆盖`],['重复号码',state.duplicates,'已自动合并'],['未命中号段',rows.length-matched.length,'数据未覆盖的号码']];
    $('metrics').innerHTML=counts.map(([label,value,note],i)=>`<article class="phone-metric ${i===1?'metric-accent':''}"><span>${label}</span><strong>${Number(value).toLocaleString()}</strong><small>${note}</small></article>`).join('');
    const bars=(map)=>[...map].sort((a,b)=>b[1]-a[1]).slice(0,8).map(([name,n])=>`<div class="dist-row"><span>${esc(name)}</span><div class="dist-track"><i style="width:${Math.max(3,n/Math.max(...map.values())*100)}%"></i></div><b>${n}</b></div>`).join('')||'<p class="subtle">暂无匹配数据</p>';
    $('distributions').innerHTML=`<div><h3>运营商</h3>${bars(ops)}</div><div><h3>省份</h3>${bars(prov)}</div><div class="dist-wide"><h3>城市（前 8）</h3>${bars(cities)}</div>`;
    const q=$('filter-results').value.trim().toLowerCase(), filtered=rows.filter(r=>!q||[r.number,r.province,r.city,r.operator,r.source,r.context].join(' ').toLowerCase().includes(q));
    $('table-count').textContent=filtered.length.toLocaleString();const shown=filtered.slice(0,state.visible);$('result-rows').innerHTML=shown.map(r=>`<tr><td class="mono">${esc(r.number)}</td><td>${esc(r.province)}</td><td>${esc(r.city)}</td><td>${esc(r.operator)}</td><td><span class="row-note">${esc(r.remark)}</span><small>${esc(r.source||'粘贴文本')}${r.context?` · ${esc(r.context)}`:''}</small></td></tr>`).join('');
    $('table-summary').textContent=`显示 ${shown.length.toLocaleString()} / ${filtered.length.toLocaleString()} 条`;$('toggle-rows').hidden=filtered.length<=state.visible;$('toggle-rows').setAttribute('aria-label',state.visible>=filtered.length?'收起到前 100 条':'显示全部号码');$('toggle-rows').setAttribute('aria-expanded',String(state.visible>=filtered.length));$('toggle-rows').classList.toggle('is-expanded',state.visible>=filtered.length);
    $('stats-caption').textContent=`按 ${matched.length.toLocaleString()} 条已命中号码统计`;
  }
  async function parseFile(file) {
    if(file.size>128*1024*1024)throw Error('文件超过 128 MiB 上限。');
    const ext=(file.name.split('.').pop()||'').toLowerCase();
    const buffer=await file.arrayBuffer(); let text='', note='';
    const signature=new Uint8Array(buffer,0,Math.min(buffer.byteLength,8));
    const zip=signature[0]===0x50&&signature[1]===0x4b;
    const ole=signature[0]===0xd0&&signature[1]===0xcf;
    if(zip){const entries=await readZipEntries(buffer);if(!entries.length)note='压缩容器中没有可读取的文本条目';else if(['xlsx','xlsm','xltx'].includes(ext))text=xlsxText(entries);else if(['ods','ots'].includes(ext))text=odsText(entries);else text=entries.map(e=>e.text).join('\n');}
    else if(['xls'].includes(ext)||ole){try{text=readXls(buffer);}catch(error){const decoded=decodeBytes(buffer);text=decoded.text+'\n'+new TextDecoder('utf-16le').decode(new Uint8Array(buffer));note=`OLE / XLS 结构读取不完整，已尽力扫描可读文本：${error.message}`;}}
    else {const decoded=decodeBytes(buffer);text=decoded.text;if(decoded.binary)note='按可读文本扫描二进制内容';if(['db','sqlite','sqlite3','db3','s3db','mdb','accdb','dbf','pdf'].includes(ext))note=note||'数据库 / 文档采用可读文本尽力扫描';if(!EXTENSIONS.has(ext))note=note||'扩展名不在内置列表，已按内容尝试扫描';text=extractStructuredText(text,ext);if(buffer.byteLength>=2){const le=new TextDecoder('utf-16le').decode(new Uint8Array(buffer));if(le.includes('\0')||le.match(/1[3-9]/))text+='\n'+le;}}
    const findings=await findPhonesAsync(text,file.name);
    return {findings, note, name:file.name, ext};
  }
  async function runFiles(files) {
    if(state.busy||!files.length)return;state.busy=true;$('progress-wrap').hidden=false;$('progress').value=0;setStatus(`正在读取 ${files.length} 个本地文件…`,'warning');
    const findings=[];const notes=[];const failed=[];let index=0;
    for(const file of files){index++;$('progress-label').textContent=`正在识别 ${file.name}（${index}/${files.length}）`;$('progress').value=(index-1)/files.length*100;try{const r=await parseFile(file);findings.push(...r.findings);state.sources.push(file.name);if(r.note)notes.push(`${r.name}：${r.note}`);}catch(e){failed.push(`${file.name}：${e.message}`);}await new Promise(resolve=>setTimeout(resolve,0));}
    $('progress').value=100;addFindings(findings);state.visible=100;render();state.busy=false;$('progress-wrap').hidden=true;
    let msg=`完成：从 ${files.length} 个文件中识别 ${findings.length} 个号码，去重后共 ${state.rows.length} 个。`;
    if(!findings.length)msg='未识别到符合大陆手机号格式的号码。可粘贴文本，或检查文件是否包含可读取的号码字段。';
    if(notes.length)msg+=` ${notes.slice(0,3).join('；')}${notes.length>3?'…':''}。`;
    if(failed.length)msg+=` ${failed.length} 个文件读取失败：${failed.slice(0,2).join('；')}`;
    setStatus(msg,failed.length?'warning':findings.length?'success':'warning');
  }
  async function analyzePaste() { const text=$('paste-numbers').value;if(!text.trim()){setStatus('请粘贴号码或包含号码的文本。','warning');return;}const findings=await findPhonesAsync(text,'粘贴文本');addFindings(findings);state.visible=100;render();setStatus(findings.length?`识别 ${findings.length} 个号码，新增 ${state.rows.length} 条去重结果。`:'没有找到符合格式的大陆手机号。',findings.length?'success':'warning'); }
  function lookupOne() { const raw=$('single-phone').value.trim(), number=normalizePhone(raw);if(!number){$('single-result').innerHTML='<div class="phone-empty-mark error-mark">!</div><div><strong>号码格式不正确</strong><span>请输入 11 位大陆手机号，或完整的前 7 位号段。</span></div>';return;}const info=lookup(number);if(!info){$('single-result').innerHTML=`<div class="phone-empty-mark error-mark">?</div><div><strong>${esc(number)} · 未找到号段</strong><span>当前内置数据未覆盖此前 7 位号段。</span></div>`;return;}$('single-result').innerHTML=`<div class="single-check">✓</div><div class="single-main"><strong>${esc(number)}</strong><span>${esc(info.province)} · ${esc(info.city)}</span></div><div class="single-operator"><span>号段归属运营商</span><strong>${esc(info.operator)}</strong>${info.virtual?`<small>虚拟品牌：${esc(info.virtual)}</small>`:''}</div>`; }
  $('lookup-one').addEventListener('click',lookupOne);$('single-phone').addEventListener('keydown',e=>{if(e.key==='Enter')lookupOne();});$('analyze-paste').addEventListener('click',analyzePaste);$('filter-results').addEventListener('input',render);$('toggle-rows').addEventListener('click',()=>{state.visible=state.visible>=state.rows.length?100:state.rows.length;render();});$('toggle-details').addEventListener('click',()=>{const button=$('toggle-details'),expanded=button.getAttribute('aria-expanded')==='true';button.setAttribute('aria-expanded',String(!expanded));button.setAttribute('aria-label',expanded?'展开号码明细':'收起号码明细');$('table-content').hidden=expanded;});
  $('sample-data').addEventListener('click',()=>{$('paste-numbers').value='张先生，138 0013 8000\n+86 132 1300 0000\n联系：020-88886666，手机 13900139000\n重复测试：13800138000';});
  $('clear-all').addEventListener('click',()=>{state.rows=[];state.duplicates=0;state.invalid=0;state.sources=[];$('results').hidden=true;$('paste-numbers').value='';$('batch-status').hidden=true;$('file-input').value='';});
  $('file-input').addEventListener('change',e=>runFiles([...e.target.files]));
  const zone=$('drop-zone');zone.addEventListener('dragover',e=>{e.preventDefault();zone.classList.add('dragover');});zone.addEventListener('dragleave',()=>zone.classList.remove('dragover'));zone.addEventListener('drop',e=>{e.preventDefault();zone.classList.remove('dragover');runFiles([...e.dataTransfer.files]);});zone.addEventListener('keydown',e=>{if(e.target===zone&&(e.key==='Enter'||e.key===' ')){$('file-input').click();e.preventDefault();}});
  $('export-results').addEventListener('click',()=>{const header=['号码','省份','城市','运营商','备注','来源文件','上下文'];const quote=v=>{let s=String(v??'');if(/^[\s\u0000]*[=+\-@]/.test(s))s="'"+s;return `"${s.replace(/"/g,'""')}"`;};const csv='\ufeff'+[header,...state.rows.map(r=>[r.number,r.province,r.city,r.operator,r.remark,r.source,r.context])].map(row=>row.map(quote).join(',')).join('\r\n');const url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download='手机号归属地查询结果.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);setStatus(`已导出 ${state.rows.length} 条号码结果。`,'success');});
})();
