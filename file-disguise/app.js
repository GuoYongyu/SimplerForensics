(() => {
  const $ = s => document.querySelector(s);
  const dropHint=$('#drop .hint');dropHint.textContent+=' 单文件上限 512 MiB；内部签名扫描分块运行，可取消。';
  const cancelButton=document.createElement('button');cancelButton.id='cancel-analysis';cancelButton.type='button';cancelButton.className='btn btn-danger';cancelButton.textContent='取消分析';cancelButton.disabled=true;
  const analysisProgress=document.createElement('progress');analysisProgress.id='analysis-progress';analysisProgress.className='hex-progress';analysisProgress.max=100;analysisProgress.value=0;analysisProgress.hidden=true;analysisProgress.setAttribute('aria-label','签名扫描进度');
  const analysisControls=document.createElement('div');analysisControls.className='button-row';analysisControls.append(cancelButton);
  $('#status').before(analysisControls,analysisProgress);
  const known = [
    {name:'JPEG 图像',ext:['jpg','jpeg'],hex:'FFD8FF',kind:'jpeg'},
    {name:'PNG 图像',ext:['png'],hex:'89504E470D0A1A0A',kind:'png'},
    {name:'GIF 图像',ext:['gif'],hex:'474946383761|474946383961'},
    {name:'WebP 图像',ext:['webp'],hex:'52494646',check:(b,o=0)=>ascii(b,o+8,4)==='WEBP',kind:'webp'},
    {name:'BMP 位图',ext:['bmp'],hex:'424D'},
    {name:'TIFF 图像',ext:['tif','tiff'],hex:'49492A00|4D4D002A'},
    {name:'PDF 文档',ext:['pdf'],hex:'255044462D'},
    {name:'ZIP 压缩包 / Office 文档',ext:['zip','docx','xlsx','pptx','odt','ods','odp','apk','jar'],hex:'504B0304|504B0506|504B0708'},
    {name:'RAR 压缩包',ext:['rar'],hex:'526172211A0700|526172211A070100'},
    {name:'7-Zip 压缩包',ext:['7z'],hex:'377ABCAF271C'},
    {name:'GZIP 压缩包',ext:['gz','tgz'],hex:'1F8B08'},
    {name:'XZ 压缩包',ext:['xz'],hex:'FD377A585A00'},
    {name:'BZIP2 压缩包',ext:['bz2'],hex:'425A68'},
    {name:'MP3 音频',ext:['mp3'],hex:'494433'},
    {name:'FLAC 音频',ext:['flac'],hex:'664C6143'},
    {name:'Ogg 音频/视频',ext:['ogg','oga','ogv'],hex:'4F676753'},
    {name:'WAV 音频',ext:['wav'],hex:'52494646',check:(b,o=0)=>ascii(b,o+8,4)==='WAVE'},
    {name:'AVI 视频',ext:['avi'],hex:'52494646',check:(b,o=0)=>ascii(b,o+8,4)==='AVI '},
    {name:'MP4 / ISO BMFF 音视频',ext:['mp4','m4a','m4v','mov','heic','heif','avif','3gp'],hex:'0000001866747970|0000002066747970|0000001466747970|0000001C66747970|0000002466747970',kind:'mp4'},
    {name:'Matroska / WebM 视频',ext:['mkv','webm'],hex:'1A45DFA3'},
    {name:'MPG / MPEG 视频',ext:['mpg','mpeg'],hex:'000001BA|000001B3'},
    {name:'Windows PE 可执行文件',ext:['exe','dll','sys'],hex:'4D5A'},
    {name:'ELF 可执行文件',ext:['elf','so'],hex:'7F454C46'},
    {name:'Mach-O 可执行文件',ext:['dylib','macho'],hex:'FEEDFACE|FEEDFACF|CEFAEDFE|CFFAEDFE'}
  ];
  let pngRawCache=null;
  let analysisRun=0;
  const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const ascii=(b,o,n)=>String.fromCharCode(...b.subarray(o,o+n));
  const hexBytes=s=>s.match(/../g).map(x=>parseInt(x,16));
  const fmt=n=>Number(n).toLocaleString('zh-CN');
  const extOf=name=>{const i=name.lastIndexOf('.');return i<0?'':name.slice(i+1).toLowerCase();};
  const sigMatch=(b,offset,sig)=>{const a=hexBytes(sig);return offset+a.length<=b.length&&a.every((v,i)=>b[offset+i]===v);};
  const u32be=(b,o)=>(b[o]*0x1000000+(b[o+1]<<16)+(b[o+2]<<8)+b[o+3])>>>0;
  const u32le=(b,o)=>(b[o]|b[o+1]<<8|b[o+2]<<16|b[o+3]<<24)>>>0;
  function findAt(b, sig, start, limit){const a=hexBytes(sig),end=Math.min(b.length-a.length,limit);for(let i=start;i<=end;i++){let ok=true;for(let j=0;j<a.length;j++)if(b[i+j]!==a[j]){ok=false;break;}if(ok)return i;}return -1;}
  function identify(b){
    const found=known.filter(k=>k.hex.split('|').some(s=>sigMatch(b,0,s))&&(!k.check||k.check(b)));
    if(b.length>=8&&ascii(b,4,4)==='ftyp'&&!found.some(k=>k.kind==='mp4'))found.push(known.find(k=>k.kind==='mp4'));
    return found;
  }
  async function scan(b,onProgress,isCancelled){
    const hits=[],byFirst=new Map();let hitLimitReached=false;
    for(const k of known)for(const s of k.hex.split('|')){const pattern={k,s,bytes:hexBytes(s)};const first=pattern.bytes[0];if(!byFirst.has(first))byFirst.set(first,[]);byFirst.get(first).push(pattern);}
    const chunkSize=1024*1024;
    for(let start=1;start<b.length;start+=chunkSize){
      if(isCancelled())return null;
      const end=Math.min(b.length,start+chunkSize);
      for(let i=start;i<end;i++){
        for(const p of byFirst.get(b[i])||[]){if(i+p.bytes.length>b.length)continue;let ok=true;for(let j=1;j<p.bytes.length;j++)if(b[i+j]!==p.bytes[j]){ok=false;break;}if(ok&&(!p.k.check||p.k.check(b,i)))hits.push({offset:i,name:p.k.name,hex:p.s,ext:p.k.ext[0]});}
        if(i>=5&&b[i]===0x66&&b[i+1]===0x74&&b[i+2]===0x79&&b[i+3]===0x70){const position=i-4;if(position>0)hits.push({offset:position,name:'MP4 / ISO BMFF 音视频',hex:'ftyp',ext:'mp4'});}
        if(hits.length>=1000){hitLimitReached=true;break;}
      }
      onProgress(Math.min(100,Math.round(end/Math.max(1,b.length)*100)));
      if(hits.length>=1000)break;
      await new Promise(resolve=>setTimeout(resolve,0));
    }
    hits.sort((a,b)=>a.offset-b.offset);
    const unique=[];for(const h of hits)if(!unique.some(x=>x.offset===h.offset&&x.name===h.name))unique.push(h);
    return {hits:unique.slice(0,80),hitLimitReached};
  }
  function dimensions(b,format){
    if(format==='PNG'&&b.length>=24)return `PNG IHDR 声明尺寸：${u32be(b,16)} × ${u32be(b,20)} px。`;
    if(format==='GIF'&&b.length>=10)return `GIF 逻辑画布尺寸：${b[6]|b[7]<<8} × ${b[8]|b[9]<<8} px。`;
    if(format==='BMP'&&b.length>=26){const w=u32le(b,18)|0,h=u32le(b,22)|0;return `BMP 头部声明尺寸：${Math.abs(w)} × ${Math.abs(h)} px。`;}
    if(format==='JPEG'){
      let p=2;while(p+4<b.length){while(b[p]===255)p++;if(p>=b.length)break;const m=b[p++];if(m===0xda||m===0xd9)break;if(m===0x01||(m>=0xd0&&m<=0xd7))continue;const n=b[p]*256+b[p+1];if(n<2||p+n>b.length)break;if([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(m))return `JPEG SOF 帧头声明尺寸：${b[p+5]*256+b[p+6]} × ${b[p+3]*256+b[p+4]} px。`;p+=n;}return '未找到完整的 JPEG SOF 帧尺寸字段。';
    }
    if(format==='WebP'&&b.length>=30){let p=12,rows=[];while(p+8<=b.length){const type=ascii(b,p,4),len=u32le(b,p+4),d=p+8;if(len<0||d+len>b.length)break;if(type==='VP8X'&&len>=10)rows.push(`VP8X 画布：${1+b[d+4]+(b[d+5]<<8)+(b[d+6]<<16)} × ${1+b[d+7]+(b[d+8]<<8)+(b[d+9]<<16)} px`);if(type==='VP8L'&&len>=5&&b[d]===0x2f)rows.push(`VP8L 码流：${1+b[d+1]+((b[d+2]&63)<<8)} × ${1+(b[d+2]>>6)+(b[d+3]<<2)+((b[d+4]&15)<<10)} px`);if(type==='VP8 '&&len>=10&&b[d+3]===0x9d&&b[d+4]===1&&b[d+5]===0x2a)rows.push(`VP8 码流：${(b[d+6]|b[d+7]<<8)&0x3fff} × ${(b[d+8]|b[d+9]<<8)&0x3fff} px`);p=d+len+(len&1);}return rows.length?`WebP 尺寸字段：${rows.join('；')}。画布和帧尺寸存在差异可能是正常的动画/裁切结构。`:'未找到可读取的 WebP 图像尺寸块。';}
    return '';
  }
  function inspectStructure(b,format){
    const notes=[];
    if(format==='PNG'){
      let p=8,end=null,broken=false;while(p+12<=b.length){const n=u32be(b,p);if(n>b.length-p-12){broken=true;break;}const t=ascii(b,p+4,4);p+=12+n;if(t==='IEND'){end=p;break;}}
      if(broken)notes.push('PNG 存在超出文件边界的块长度，文件可能截断或长度字段异常。');
      else if(end!==null&&end<b.length)notes.push(`PNG 的 IEND 结束于偏移 ${fmt(end)}；其后还有 ${fmt(b.length-end)} 字节尾随数据。`);
      else if(end===null)notes.push('未找到完整 PNG IEND 块，可能截断或结构异常。');
    } else if(format==='JPEG'){
      let end=-1;for(let i=2;i<b.length-1;i++)if(b[i]===255&&b[i+1]===217){end=i+2;break;}
      if(end>0&&end<b.length)notes.push(`JPEG 的第一个 EOI 标记结束于偏移 ${fmt(end)}；其后还有 ${fmt(b.length-end)} 字节尾随数据。`);
      else if(end<0)notes.push('未找到 JPEG EOI 结束标记，可能截断或结构异常。');
    } else if(['WebP','WAV','AVI'].includes(format)&&b.length>=8){
      const declared=u32le(b,4)+8;
      if(declared<b.length)notes.push(`RIFF 头声明总长度 ${fmt(declared)} 字节，实际 ${fmt(b.length)} 字节；多出 ${fmt(b.length-declared)} 字节。`);
      else if(declared>b.length)notes.push(`RIFF 头声明总长度 ${fmt(declared)} 字节，大于实际 ${fmt(b.length)} 字节，可能截断或长度被改写。`);
      else notes.push('RIFF 声明长度与实际文件大小一致。');
    } else if(format==='MP4'){
      let p=0,count=0,issue='';
      while(p+8<=b.length&&count<100000){let size=u32be(b,p),header=8;const type=ascii(b,p+4,4),extendsToEnd=size===0;if(size===1){if(p+16>b.length){issue='遇到不完整的扩展长度 box 头。';break;}const high=u32be(b,p+8),low=u32be(b,p+12);if(high>0x1fffff){issue=`${type} box 长度超出安全整数范围。`;break;}size=high*0x100000000+low;header=16;}else if(extendsToEnd)size=b.length-p;if(size<header){issue=`${type} box 声明长度小于头部长度。`;break;}if(size>b.length-p){issue=`${type} box 声明长度超过文件剩余数据，文件可能截断或长度被修改。`;break;}p+=size;count++;if(extendsToEnd)break;}
      if(issue)notes.push(`MP4 容器结构异常：${issue}`);
      else if(p<b.length)notes.push(`MP4 顶层 box 扫描在偏移 ${fmt(p)} 停止；剩余 ${fmt(b.length-p)} 字节不足以构成完整 box 头。`);
      else notes.push(`MP4 顶层 box 长度均落在文件边界内，共检查 ${fmt(count)} 个 box；这不能判断码流是否被改写。`);
    }
    if(!notes.length)notes.push('此格式暂未发现可由本页核对的结束标记或容器长度线索。');
    return notes;
  }
  async function estimatePngFromPixels(b){
    pngRawCache=null;
    if(typeof DecompressionStream==='undefined')return 'PNG 像素尺寸候选：浏览器缺少本地解压接口，无法读取 IDAT。';
    const depth=b[24],color=b[25],channels={0:1,2:3,3:1,4:2,6:4}[color],bits=channels*depth;
    if(!channels||!bits)return 'PNG 像素尺寸候选：颜色类型或位深不支持此推算。';
    if(b[28]!==0)return 'PNG 像素尺寸候选：隔行 PNG 暂不支持扫描行反推。';
    const chunks=[];let p=8,compressedSize=0;
    while(p+12<=b.length){const n=u32be(b,p),type=ascii(b,p+4,4),d=p+8;if(n>b.length-p-12)break;if(type==='IDAT'){compressedSize+=n;if(compressedSize>32*1024*1024)return 'PNG 像素尺寸候选：IDAT 压缩数据超过 32 MiB，跳过解压。';chunks.push(b.subarray(d,d+n));}p=d+n+4;if(type==='IEND')break;}
    if(!chunks.length)return 'PNG 像素尺寸候选：没有可读取的 IDAT 数据。';
    const compressed=new Blob(chunks).stream().pipeThrough(new DecompressionStream('deflate')),reader=compressed.getReader(),parts=[];let total=0;
    try{while(true){const x=await reader.read();if(x.done)break;total+=x.value.length;if(total>96*1024*1024){await reader.cancel();return 'PNG 像素尺寸候选：解压数据超过 96 MiB，停止推算。';}parts.push(x.value);}}catch{return 'PNG 像素尺寸候选：IDAT 解压失败，数据可能损坏或格式不受支持。';}
    const raw=new Uint8Array(total);let offset=0;for(const x of parts){raw.set(x,offset);offset+=x.length;}pngRawCache={raw,depth,color,width:u32be(b,16),height:u32be(b,20)};
    const candidates=[],root=Math.floor(Math.sqrt(total));
    for(let stride=2;stride<=root;stride++)if(total%stride===0){for(const rowStride of stride===total/stride?[stride]:[stride,total/stride]){const rowBytes=rowStride-1,height=total/rowStride,wMin=Math.floor(((rowBytes-1)*8)/bits)+1,wMax=Math.floor((rowBytes*8)/bits);if(height<1||height>100000||wMin<1||wMax>100000||wMax<wMin)continue;let valid=true;for(let y=0;y<height;y++)if(raw[y*rowStride]>4){valid=false;break;}if(valid)candidates.push({wMin,wMax,height,score:Math.abs((wMin+wMax)/2-u32be(b,16))/Math.max(1,u32be(b,16))+Math.abs(height-u32be(b,20))/Math.max(1,u32be(b,20))});}}
    if(!candidates.length)return 'PNG 像素尺寸候选：未找到符合滤波字节结构的扫描行组合。';
    candidates.sort((a,b)=>a.score-b.score);const c=candidates[0],width=c.wMin===c.wMax?String(c.wMin):`${c.wMin}–${c.wMax}`;
    return `PNG 解压像素数据推算候选：${width} × ${c.height} px；IHDR 元数据：${u32be(b,16)} × ${u32be(b,20)} px。候选由行长度和滤波字节结构推测，可能不唯一，不可视为原始尺寸证明。`;
  }
  function paeth(a,b,c){const p=a+b-c,pa=Math.abs(p-a),pb=Math.abs(p-b),pc=Math.abs(p-c);return pa<=pb&&pa<=pc?a:pb<=pc?b:c;}
  function pngLsbAnalysis(){
    if(!pngRawCache)return 'PNG 像素低位初筛：未能取得可用的 IDAT 解压数据，因此无法统计。';
    const {raw,depth,color,width,height}=pngRawCache,channels={0:1,2:3,3:1,4:2,6:4}[color];
    if(depth!==8&&depth!==16&&!(color===3&&[1,2,4].includes(depth)))return `PNG 像素低位初筛：当前颜色类型（${color}）和位深（${depth}）不在可分析范围。`;
    const rowBytes=Math.ceil(width*channels*depth/8),bpp=Math.max(1,Math.ceil(channels*depth/8));
    if(!Number.isSafeInteger(rowBytes)||height* (rowBytes+1)!==raw.length||rowBytes>32*1024*1024)return 'PNG 像素低位初筛：扫描行长度与解压数据不一致，跳过统计。';
    const prev=new Uint8Array(rowBytes),hist=new Uint32Array(depth===16?256:1<<depth);let ones=0,count=0,pos=0;
    for(let y=0;y<height;y++){
      const filter=raw[pos++],row=new Uint8Array(rowBytes);if(filter>4)return 'PNG 像素低位初筛：遇到未知扫描行滤波类型，跳过统计。';
      for(let x=0;x<rowBytes;x++){const value=raw[pos++],left=x>=bpp?row[x-bpp]:0,up=prev[x],upperLeft=x>=bpp?prev[x-bpp]:0;row[x]=(value+(filter===0?0:filter===1?left:filter===2?up:filter===3?Math.floor((left+up)/2):paeth(left,up,upperLeft)))&255;}
      if(depth===8){for(const value of row){hist[value]++;ones+=value&1;count++;}}
      else if(depth===16){for(let x=1;x<row.length;x+=2){const value=row[x];hist[value]++;ones+=value&1;count++;}}
      else {const mask=(1<<depth)-1;for(const byte of row)for(let shift=8-depth;shift>=0;shift-=depth){const value=(byte>>shift)&mask;hist[value]++;ones+=value&1;count++;}}
      prev.set(row);
    }
    let paired=0,total=0;for(let i=0;i+1<hist.length;i+=2){paired+=Math.min(hist[i],hist[i+1]);total+=hist[i]+hist[i+1];}
    const ratio=count?ones/count:0,pairMatch=total?paired/total:0;
    return `PNG 像素低位初筛：${fmt(count)} 个样本；最低位为 1 的比例 ${(ratio*100).toFixed(2)}%；相邻值对的频数接近度 ${(pairMatch*100).toFixed(2)}%。${count<10000?'样本量偏小，统计参考价值有限。':ratio>=0.48&&ratio<=0.52?'最低位接近均衡，可能来自自然图像或处理噪声，也可能与低位替换相容，不能据此确认隐写。':'未见明显的最低位均衡特征；不能排除其他嵌入方式。'}`;
  }
  function wavLsbAnalysis(b){
    let p=12,format=null,channels=0,bits=0,data=null;
    while(p+8<=b.length){const type=ascii(b,p,4),size=u32le(b,p+4),d=p+8;if(size>b.length-d)break;if(type==='fmt '&&size>=16){format=b[d]|b[d+1]<<8;channels=b[d+2]|b[d+3]<<8;bits=b[d+14]|b[d+15]<<8;}if(type==='data'){data={start:d,size};break;}p=d+size+(size&1);}
    if(!data)return 'WAV 样本低位初筛：没有找到完整的 data 数据块。';
    if(format!==1||![8,16,24,32].includes(bits))return `WAV 样本低位初筛：仅分析整数 PCM；检测到编码格式 ${format??'未知'}、${bits||'未知'} 位，未对压缩音频解码。`;
    const bytesPerSample=bits/8,sampleCount=Math.floor(data.size/bytesPerSample),limit=Math.min(sampleCount,2000000);let ones=0,prev=-1,changes=0;
    for(let i=0;i<limit;i++){const offset=data.start+i*bytesPerSample,value=b[offset+bytesPerSample-1]&1;ones+=value;if(prev>=0&&value!==prev)changes++;prev=value;}
    const ratio=limit?ones/limit:0,changeRatio=limit>1?changes/(limit-1):0;
    return `WAV PCM 样本低位初筛：${fmt(sampleCount)} 个样本（${channels||'?'} 声道、${bits} 位）；抽样 ${fmt(limit)} 个，最低位为 1 的比例 ${(ratio*100).toFixed(2)}%，相邻样本最低位变化率 ${(changeRatio*100).toFixed(2)}%。${limit<10000?'样本量偏小，统计参考价值有限。':ratio>=0.48&&ratio<=0.52?'最低位接近均衡；PCM 量化噪声本身也可能如此，不能据此确认隐写。':'未见明显的最低位均衡特征；不能排除其他嵌入方式。'}`;
  }
  function textMarkerHints(b){
    const sample=b.subarray(0,Math.min(b.length,65536)),pieces=[];for(let i=0;i<sample.length;i+=8192)pieces.push(String.fromCharCode(...sample.subarray(i,Math.min(sample.length,i+8192))));
    const text=pieces.join('').toLowerCase(),markers=['steghide','openstego','silenteye','outguess','zsteg','jsteg','f5'];
    return markers.filter(x=>text.includes(x));
  }
  function stegoAnalysis(b,format){
    const rows=[];
    if(format==='PNG')rows.push(pngLsbAnalysis());
    else if(format==='WAV')rows.push(wavLsbAnalysis(b));
    else if(format==='JPEG')rows.push('JPEG 使用有损 DCT 编码；本页不解码系数，也不执行 JSteg/F5 等专用检测。可结合文件尾随数据、元数据异常及专用 JPEG 隐写工具进一步分析。');
    else if(['MP4','AVI','WebP','GIF'].includes(format))rows.push(`${format} 内容可能包含压缩帧、动画或多个轨道；本页不解码帧/码流以统计隐写位。当前仅结合容器长度、尾随数据和内部签名提供结构线索。`);
    else rows.push('该格式没有通用、可靠的隐写位分析方法；本页仅结合已识别的结构异常和附加数据提供线索。');
    const markers=textMarkerHints(b);if(markers.length)rows.push(`文件头部 64 KiB 中出现工具/算法名称字符串：${markers.join('、')}。字符串可能只是普通文件内容，不足以证明曾使用相关工具。`);
    rows.push('以上是统计初筛，不解码隐藏载荷，也不能确认或排除隐写。自然噪声、压缩和编码器差异均会影响统计结果。');
    return rows.join('\n\n');
  }
  function commandBlock(file,size,hits){
    const starts=[{offset:0,name:'文件起始'}];
    for(const h of hits)if(h.offset>0&&!starts.some(x=>x.offset===h.offset))starts.push(h);
    starts.sort((a,b)=>a.offset-b.offset);const selected=starts.slice(0,5);
    if(selected.length<2)return '<p class="hint">当前没有足够的内部文件头来生成拆分示例。</p>';
    const q=file.replace(/'/g,"'\\''"),base=file.replace(/\.[^.]*$/,'');
    const unix=selected.map((x,i)=>{const end=selected[i+1]?.offset??size,n=end-x.offset;return `dd if='${q}' of='${base}.part${i+1}' bs=1 skip=${x.offset} count=${n} 2>/dev/null`;}).join('\n');
    const ps=selected.map((x,i)=>{const end=selected[i+1]?.offset??size;return `$s=${x.offset}; $n=${end-x.offset}; $fs=[IO.File]::OpenRead('${file.replace(/'/g,"''")}'); $fs.Position=$s; $buf=New-Object byte[] $n; [void]$fs.Read($buf,0,$n); $fs.Dispose(); [IO.File]::WriteAllBytes('${base.replace(/'/g,"''")}.part${i+1}',$buf)`;}).join('\n');
    return `<h3 style="margin:18px 0 8px">按疑似边界拆分（需人工复核）</h3><p class="hint">以下示例以偏移作为分段起点，最多展示前 5 个起点。先在源文件所在目录打开终端，再运行命令。文件名已做 shell 转义。macOS / Linux：</p><pre class="result-box">${esc(unix)}</pre><p class="hint">Windows PowerShell：</p><pre class="result-box">${esc(ps)}</pre>`;
  }
  function analyze(file){
    if(!file)return;
    const run=++analysisRun;
    $('#analysis').hidden=true;
    $('#cancel-analysis').disabled=false;
    $('#analysis-progress').hidden=false;
    $('#analysis-progress').value=0;
    $('#status').className='status';$('#status').textContent='正在本地读取并扫描文件…';
    if(file.size>512*1024*1024){$('#status').className='status error';$('#status').textContent='文件超过 512 MiB，本页为避免浏览器内存占用过高而停止分析。';$('#cancel-analysis').disabled=true;$('#analysis-progress').hidden=true;return;}
    file.arrayBuffer().then(async buf=>{
      if(run!==analysisRun)return;
      const b=new Uint8Array(buf),ext=extOf(file.name),atStart=identify(b),primary=atStart[0],format=primary?.name.split(' ')[0]||'未知';
      $('#status').textContent='正在分块扫描内部签名…';
      const scanResult=await scan(b,value=>{if(run===analysisRun){$('#analysis-progress').value=value;$('#status').textContent=`正在扫描内部签名… ${value}%`;}},()=>run!==analysisRun);
      if(run!==analysisRun||!scanResult)return;
      const {hits,hitLimitReached}=scanResult;
      $('#cancel-analysis').disabled=true;
      $('#analysis-progress').hidden=true;
      $('#status').textContent='签名扫描完成，正在整理结构与格式线索…';
      $('#analysis').hidden=false;
      let identity=`文件：${file.name}\n扩展名：${ext?'.'+ext:'（无）'}\n文件大小：${fmt(file.size)} 字节\n文件头判断：${primary?primary.name:'未识别常见文件头'}`;
      if(atStart.length>1)identity+=`\n起始处同时匹配：${atStart.map(x=>x.name).join('、')}`;
      if(primary&&!primary.ext.includes(ext))identity+=`\n结论：扩展名与文件头不匹配；该格式常见扩展名为 ${primary.ext.map(x=>'.'+x).join('、')}。`;
      else if(primary)identity+='\n结论：扩展名与识别到的文件头相符。';
      else identity+='\n结论：文件头不在内置识别范围内，无法比较扩展名。';
      $('#identity').textContent=identity;
      $('#signatures').innerHTML=hits.length?`<div class="table-wrap"><table><thead><tr><th>偏移（十进制）</th><th>偏移（十六进制）</th><th>识别签名</th><th>字节</th></tr></thead><tbody>${hits.map(h=>`<tr><td>${fmt(h.offset)}</td><td>0x${h.offset.toString(16).toUpperCase()}</td><td>${esc(h.name)}</td><td><code>${h.hex.match(/../g).join(' ')}</code></td></tr>`).join('')}</tbody></table></div>`:'<div class="status">未发现已知格式的内部签名。</div>';
      $('#commands').innerHTML=commandBlock(file.name,file.size,hits);
      const dim=dimensions(b,format),struct=inspectStructure(b,format);
      let integrity=(dim?dim+'\n':'')+struct.join('\n');
      if(format==='PNG')integrity+='\n'+await estimatePngFromPixels(b);
      if(run!==analysisRun)return;
      if(['PNG','JPEG','WebP','GIF','BMP'].includes(format))integrity+='\n\n原始图片尺寸无法仅从当前尺寸元数据证明；编码数据中的候选尺寸也不等于取证结论。';
      $('#integrity').textContent=integrity;
      $('#stego').textContent=stegoAnalysis(b,format);
      $('#status').className='status '+(hits.length||struct.some(x=>/多出|大于实际|异常|未找到/.test(x))?'warning':'success');$('#status').textContent=`分析完成。签名、偏移和结构异常均是线索，应结合上下文核实。${hitLimitReached?' 扫描达到 1000 个命中上限，可能尚未检查文件后续部分；页面最多展示 80 条。':''}`;
    }).catch(e=>{if(run===analysisRun){$('#status').className='status error';$('#status').textContent=`读取失败：${e.message||e}`;}}).finally(()=>{if(run===analysisRun){$('#cancel-analysis').disabled=true;$('#analysis-progress').hidden=true;}});
  }
  $('#cancel-analysis').addEventListener('click',()=>{analysisRun++;$('#cancel-analysis').disabled=true;$('#analysis-progress').hidden=true;$('#status').className='status warning';$('#status').textContent='分析已取消；未完成的结果不会显示。';});
  $('#file').addEventListener('change',e=>analyze(e.target.files[0]));
  $('#drop').addEventListener('dragover',e=>{e.preventDefault();$('#drop').classList.add('dragover');});
  $('#drop').addEventListener('dragleave',()=>$('#drop').classList.remove('dragover'));
  $('#drop').addEventListener('drop',e=>{e.preventDefault();$('#drop').classList.remove('dragover');analyze(e.dataTransfer.files[0]);});
})();
