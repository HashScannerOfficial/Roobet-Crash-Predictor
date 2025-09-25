(function(){'use strict';
var ERR='input is invalid type';
var HAS_W=(typeof window==='object');
var ROOT=HAS_W?window:{};
if(ROOT.NO_WIN_SHA256)HAS_W=false;
var IS_SW=!HAS_W&&typeof self==='object';
var IS_NODE=!ROOT.NO_NODE_SHA256&&typeof process==='object'&&process.versions&&process.versions.node&&process.type!='renderer';
if(IS_NODE)ROOT=global; else if(IS_SW)ROOT=self;
var IS_CJS=!ROOT.NO_COMMONJS_SHA256&&typeof module==='object'&&module.exports;
var IS_AMD=typeof define==='function'&&define.amd;
var HAS_AB=!ROOT.NO_ARRAYBUFFER_SHA256&&typeof ArrayBuffer!=='undefined';

var HEXCH=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
var PAD=[-2147483648,8388608,32768,128];
var BSH=[24,16,8,0];
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];

var OUTS=['hex','array','digest','arrayBuffer'];
var SB=[];

if(ROOT.NO_NODE_SHA256||!Array.isArray){Array.isArray=function(o){return Object.prototype.toString.call(o)==='[object Array]';};}
if(HAS_AB&&(ROOT.NO_AB_VIEW_SHA256||!ArrayBuffer.isView)){ArrayBuffer.isView=function(o){return typeof o==='object'&&o.buffer&&o.buffer.constructor===ArrayBuffer;}}

function norm(m){
  var t=typeof m;
  if(t==='string')return [m,true];
  if(t!=='object'||m===null) throw new Error(ERR);
  if(HAS_AB&&m.constructor===ArrayBuffer) return [new Uint8Array(m),false];
  if(!Array.isArray(m) && !(HAS_AB && ArrayBuffer.isView(m))) throw new Error(ERR);
  return [m,false];
}

function mkOut(type,is224){
  return function(m){ return new Has(is224,true).update(m)[type](); };
}

function mkMain(is224){
  var fn = mkOut('hex',is224);
  if(IS_NODE) fn = nodeWrap(fn,is224);
  fn.create = function(){ return new Has(is224); };
  fn.update = function(m){ return fn.create().update(m); };
  for(var i=0;i<OUTS.length;++i) fn[OUTS[i]] = mkOut(OUTS[i],is224);
  return fn;
}

function nodeWrap(fn,is224){
  var crypto = require('crypto'), BufferImpl = require('buffer').Buffer, alg = is224 ? 'sha224' : 'sha256', fromFn;
  if(BufferImpl.from && !ROOT.NO_BUFFER_FROM) fromFn = BufferImpl.from;
  else fromFn = function(m){ return new BufferImpl(m); };
  return function(m){
    if(typeof m === 'string') return crypto.createHash(alg).update(m,'utf8').digest('hex');
    if(m===null||m===undefined) throw new Error(ERR);
    if(m.constructor===ArrayBuffer) m = new Uint8Array(m);
    if(Array.isArray(m) || ArrayBuffer.isView(m) || m.constructor===BufferImpl) return crypto.createHash(alg).update(fromFn(m)).digest('hex');
    return fn(m);
  };
}

function mkHOut(type,is224){
  return function(k,m){ return new Hmac(k,is224,true).update(m)[type](); };
}
function mkHmac(is224){
  var h = mkHOut('hex',is224);
  h.create = function(k){ return new Hmac(k,is224); };
  h.update = function(k,m){ return h.create(k).update(m); };
  for(var i=0;i<OUTS.length;++i) h[OUTS[i]] = mkHOut(OUTS[i],is224);
  return h;
}

/* Hasher */
function Has(is224,shared){
  if(shared){
    SB[0]=SB[16]=SB[1]=SB[2]=SB[3]=SB[4]=SB[5]=SB[6]=SB[7]=SB[8]=SB[9]=SB[10]=SB[11]=SB[12]=SB[13]=SB[14]=SB[15]=0;
    this.blocks = SB;
  } else {
    this.blocks = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
  }
  if(is224){
    this.h0=0xc1059ed8; this.h1=0x367cd507; this.h2=0x3070dd17; this.h3=0xf70e5939;
    this.h4=0xffc00b31; this.h5=0x68581511; this.h6=0x64f98fa7; this.h7=0xbefa4fa4;
  } else {
    this.h0=0x6a09e667; this.h1=0xbb67ae85; this.h2=0x3c6ef372; this.h3=0xa54ff53a;
    this.h4=0x510e527f; this.h5=0x9b05688c; this.h6=0x1f83d9ab; this.h7=0x5be0cd19;
  }
  this.block=this.start=this.bytes=this.hBytes=0;
  this.finalized=this.hashed=false;
  this.first=true;
  this.is224=is224;
}

Has.prototype.update = function(msg){
  if(this.finalized) return this;
  var r = norm(msg); msg = r[0]; var isStr = r[1];
  var code, idx=0, i, len=msg.length, blk=this.blocks;
  while(idx<len){
    if(this.hashed){
      this.hashed=false;
      blk[0]=this.block;
      this.block = blk[16] = blk[1] = blk[2] = blk[3] = blk[4] = blk[5] = blk[6] = blk[7] = blk[8] = blk[9] = blk[10] = blk[11] = blk[12] = blk[13] = blk[14] = blk[15] = 0;
    }
    if(!isStr){
      for(i=this.start; idx<len && i<64; ++idx){
        blk[i>>>2] |= msg[idx] << BSH[i++&3];
      }
    } else {
      for(i=this.start; idx<len && i<64; ++idx){
        code = msg.charCodeAt(idx);
        if(code < 0x80){
          blk[i>>>2] |= code << BSH[i++&3];
        } else if(code < 0x800){
          blk[i>>>2] |= (0xc0 | (code>>>6)) << BSH[i++&3];
          blk[i>>>2] |= (0x80 | (code & 0x3f)) << BSH[i++&3];
        } else if(code < 0xd800 || code >= 0xe000){
          blk[i>>>2] |= (0xe0 | (code>>>12)) << BSH[i++&3];
          blk[i>>>2] |= (0x80 | ((code>>>6)&0x3f)) << BSH[i++&3];
          blk[i>>>2] |= (0x80 | (code & 0x3f)) << BSH[i++&3];
        } else {
          code = 0x10000 + (((code & 0x3ff) << 10) | (msg.charCodeAt(++idx) & 0x3ff));
          blk[i>>>2] |= (0xf0 | (code>>>18)) << BSH[i++&3];
          blk[i>>>2] |= (0x80 | ((code>>>12)&0x3f)) << BSH[i++&3];
          blk[i>>>2] |= (0x80 | ((code>>>6)&0x3f)) << BSH[i++&3];
          blk[i>>>2] |= (0x80 | (code & 0x3f)) << BSH[i++&3];
        }
      }
    }
    this.lastByteIndex = i;
    this.bytes += i - this.start;
    if(i >= 64){
      this.block = blk[16];
      this.start = i - 64;
      this._hash();
      this.hashed = true;
    } else {
      this.start = i;
    }
  }
  if(this.bytes > 4294967295){
    this.hBytes += this.bytes / 4294967296 << 0;
    this.bytes = this.bytes % 4294967296;
  }
  return this;
};

Has.prototype.finalize = function(){
  if(this.finalized) return;
  this.finalized = true;
  var blk = this.blocks, i = this.lastByteIndex;
  blk[16] = this.block;
  blk[i>>>2] |= PAD[i & 3];
  this.block = blk[16];
  if(i >= 56){
    if(!this.hashed) this._hash();
    blk[0] = this.block;
    blk[16] = blk[1] = blk[2] = blk[3] = blk[4] = blk[5] = blk[6] = blk[7] = blk[8] = blk[9] = blk[10] = blk[11] = blk[12] = blk[13] = blk[14] = blk[15] = 0;
  }
  blk[14] = this.hBytes << 3 | this.bytes >>> 29;
  blk[15] = this.bytes << 3;
  this._hash();
};

Has.prototype._hash = function(){
  var a=this.h0, b=this.h1, c=this.h2, d=this.h3, e=this.h4, f=this.h5, g=this.h6, h=this.h7, blk=this.blocks, j, s0, s1, maj, t1, t2, ch, ab, da, cd, bc;
  for(j=16;j<64;++j){
    t1 = blk[j-15];
    s0 = ((t1>>>7)|(t1<<25)) ^ ((t1>>>18)|(t1<<14)) ^ (t1>>>3);
    t1 = blk[j-2];
    s1 = ((t1>>>17)|(t1<<15)) ^ ((t1>>>19)|(t1<<13)) ^ (t1>>>10);
    blk[j] = (blk[j-16] + s0 + blk[j-7] + s1) << 0;
  }
  bc = b & c;
  for(j=0;j<64;j+=4){
    if(this.first){
      if(this.is224){
        ab = 300032;
        t1 = blk[0] - 1413257819;
        h = t1 - 150054599 << 0;
        d = t1 + 24177077 << 0;
      } else {
        ab = 704751109;
        t1 = blk[0] - 210244248;
        h = t1 - 1521486534 << 0;
        d = t1 + 143694565 << 0;
      }
      this.first = false;
    } else {
      s0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
      s1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
      ab = a & b;
      maj = ab ^ (a & c) ^ bc;
      ch = (e & f) ^ (~e & g);
      t1 = h + s1 + ch + K[j] + blk[j];
      t2 = s0 + maj;
      h = d + t1 << 0;
      d = t1 + t2 << 0;
    }
    s0 = ((d>>>2)|(d<<30)) ^ ((d>>>13)|(d<<19)) ^ ((d>>>22)|(d<<10));
    s1 = ((h>>>6)|(h<<26)) ^ ((h>>>11)|(h<<21)) ^ ((h>>>25)|(h<<7));
    da = d & a;
    maj = da ^ (d & b) ^ ab;
    ch = (h & e) ^ (~h & f);
    t1 = g + s1 + ch + K[j+1] + blk[j+1];
    t2 = s0 + maj;
    g = c + t1 << 0;
    c = t1 + t2 << 0;

    s0 = ((c>>>2)|(c<<30)) ^ ((c>>>13)|(c<<19)) ^ ((c>>>22)|(c<<10));
    s1 = ((g>>>6)|(g<<26)) ^ ((g>>>11)|(g<<21)) ^ ((g>>>25)|(g<<7));
    cd = c & d;
    maj = cd ^ (c & a) ^ da;
    ch = (g & h) ^ (~g & e);
    t1 = f + s1 + ch + K[j+2] + blk[j+2];
    t2 = s0 + maj;
    f = b + t1 << 0;
    b = t1 + t2 << 0;

    s0 = ((b>>>2)|(b<<30)) ^ ((b>>>13)|(b<<19)) ^ ((b>>>22)|(b<<10));
    s1 = ((f>>>6)|(f<<26)) ^ ((f>>>11)|(f<<21)) ^ ((f>>>25)|(f<<7));
    bc = b & c;
    maj = bc ^ (b & d) ^ cd;
    ch = (f & g) ^ (~f & h);
    t1 = e + s1 + ch + K[j+3] + blk[j+3];
    t2 = s0 + maj;
    e = a + t1 << 0;
    a = t1 + t2 << 0;
    this.chromeBugWorkAround = true;
  }
  this.h0 = this.h0 + a << 0;
  this.h1 = this.h1 + b << 0;
  this.h2 = this.h2 + c << 0;
  this.h3 = this.h3 + d << 0;
  this.h4 = this.h4 + e << 0;
  this.h5 = this.h5 + f << 0;
  this.h6 = this.h6 + g << 0;
  this.h7 = this.h7 + h << 0;
};

Has.prototype.hex = function(){
  this.finalize();
  var h0=this.h0,h1=this.h1,h2=this.h2,h3=this.h3,h4=this.h4,h5=this.h5,h6=this.h6,h7=this.h7;
  var s = HEXCH[(h0>>>28)&0x0F]+HEXCH[(h0>>>24)&0x0F]+HEXCH[(h0>>>20)&0x0F]+HEXCH[(h0>>>16)&0x0F]+HEXCH[(h0>>>12)&0x0F]+HEXCH[(h0>>>8)&0x0F]+HEXCH[(h0>>>4)&0x0F]+HEXCH[h0&0x0F]+
          HEXCH[(h1>>>28)&0x0F]+HEXCH[(h1>>>24)&0x0F]+HEXCH[(h1>>>20)&0x0F]+HEXCH[(h1>>>16)&0x0F]+HEXCH[(h1>>>12)&0x0F]+HEXCH[(h1>>>8)&0x0F]+HEXCH[(h1>>>4)&0x0F]+HEXCH[h1&0x0F]+
          HEXCH[(h2>>>28)&0x0F]+HEXCH[(h2>>>24)&0x0F]+HEXCH[(h2>>>20)&0x0F]+HEXCH[(h2>>>16)&0x0F]+HEXCH[(h2>>>12)&0x0F]+HEXCH[(h2>>>8)&0x0F]+HEXCH[(h2>>>4)&0x0F]+HEXCH[h2&0x0F]+
          HEXCH[(h3>>>28)&0x0F]+HEXCH[(h3>>>24)&0x0F]+HEXCH[(h3>>>20)&0x0F]+HEXCH[(h3>>>16)&0x0F]+HEXCH[(h3>>>12)&0x0F]+HEXCH[(h3>>>8)&0x0F]+HEXCH[(h3>>>4)&0x0F]+HEXCH[h3&0x0F]+
          HEXCH[(h4>>>28)&0x0F]+HEXCH[(h4>>>24)&0x0F]+HEXCH[(h4>>>20)&0x0F]+HEXCH[(h4>>>16)&0x0F]+HEXCH[(h4>>>12)&0x0F]+HEXCH[(h4>>>8)&0x0F]+HEXCH[(h4>>>4)&0x0F]+HEXCH[h4&0x0F]+
          HEXCH[(h5>>>28)&0x0F]+HEXCH[(h5>>>24)&0x0F]+HEXCH[(h5>>>20)&0x0F]+HEXCH[(h5>>>16)&0x0F]+HEXCH[(h5>>>12)&0x0F]+HEXCH[(h5>>>8)&0x0F]+HEXCH[(h5>>>4)&0x0F]+HEXCH[h5&0x0F]+
          HEXCH[(h6>>>28)&0x0F]+HEXCH[(h6>>>24)&0x0F]+HEXCH[(h6>>>20)&0x0F]+HEXCH[(h6>>>16)&0x0F]+HEXCH[(h6>>>12)&0x0F]+HEXCH[(h6>>>8)&0x0F]+HEXCH[(h6>>>4)&0x0F]+HEXCH[h6&0x0F];
  if(!this.is224){
    s += HEXCH[(h7>>>28)&0x0F]+HEXCH[(h7>>>24)&0x0F]+HEXCH[(h7>>>20)&0x0F]+HEXCH[(h7>>>16)&0x0F]+HEXCH[(h7>>>12)&0x0F]+HEXCH[(h7>>>8)&0x0F]+HEXCH[(h7>>>4)&0x0F]+HEXCH[h7&0x0F];
  }
  return s;
};

Has.prototype.toString = Has.prototype.hex;

Has.prototype.digest = function(){
  this.finalize();
  var h0=this.h0,h1=this.h1,h2=this.h2,h3=this.h3,h4=this.h4,h5=this.h5,h6=this.h6,h7=this.h7;
  var arr = [
    (h0>>>24)&0xFF,(h0>>>16)&0xFF,(h0>>>8)&0xFF,h0&0xFF,
    (h1>>>24)&0xFF,(h1>>>16)&0xFF,(h1>>>8)&0xFF,h1&0xFF,
    (h2>>>24)&0xFF,(h2>>>16)&0xFF,(h2>>>8)&0xFF,h2&0xFF,
    (h3>>>24)&0xFF,(h3>>>16)&0xFF,(h3>>>8)&0xFF,h3&0xFF
  ];
  if(!this.is224) arr.push((h4>>>24)&0xFF,(h4>>>16)&0xFF,(h4>>>8)&0xFF,h4&0xFF,(h5>>>24)&0xFF,(h5>>>16)&0xFF,(h5>>>8)&0xFF,h5&0xFF,(h6>>>24)&0xFF,(h6>>>16)&0xFF,(h6>>>8)&0xFF,h6&0xFF,(h7>>>24)&0xFF,(h7>>>16)&0xFF,(h7>>>8)&0xFF,h7&0xFF);
  return arr;
};

Has.prototype.array = Has.prototype.digest;

Has.prototype.arrayBuffer = function(){
  this.finalize();
  var buf = new ArrayBuffer(this.is224?28:32);
  var dv = new DataView(buf);
  dv.setUint32(0,this.h0); dv.setUint32(4,this.h1); dv.setUint32(8,this.h2); dv.setUint32(12,this.h3); dv.setUint32(16,this.h4); dv.setUint32(20,this.h5); dv.setUint32(24,this.h6);
  if(!this.is224) dv.setUint32(28,this.h7);
  return buf;
};

/* HMAC */
function Hmac(key,is224,shared){
  var r = norm(key); key = r[0];
  if(r[1]){
    var out=[], L=key.length, p=0, cc;
    for(var i=0;i<L;++i){
      cc = key.charCodeAt(i);
      if(cc < 0x80) out[p++]=cc;
      else if(cc < 0x800){ out[p++]=(0xc0|(cc>>>6)); out[p++]=(0x80|(cc&0x3f)); }
      else if(cc < 0xd800 || cc >= 0xe000){ out[p++]=(0xe0|(cc>>>12)); out[p++]=(0x80|((cc>>>6)&0x3f)); out[p++]=(0x80|(cc&0x3f)); }
      else { cc = 0x10000 + (((cc&0x3ff)<<10)|(key.charCodeAt(++i)&0x3ff)); out[p++]=(0xf0|(cc>>>18)); out[p++]=(0x80|((cc>>>12)&0x3f)); out[p++]=(0x80|((cc>>>6)&0x3f)); out[p++]=(0x80|(cc&0x3f)); }
    }
    key = out;
  }
  if(key.length > 64) key = (new Has(is224,true)).update(key).array();
  var oKey=[], iKey=[];
  for(i=0;i<64;++i){ var bb = key[i]||0; oKey[i] = 0x5c ^ bb; iKey[i] = 0x36 ^ bb; }
  Has.call(this,is224,shared);
  this.update(iKey);
  this.oKey = oKey;
  this.inner = true;
  this.shared = shared;
}
Hmac.prototype = new Has();

Hmac.prototype.finalize = function(){
  Has.prototype.finalize.call(this);
  if(this.inner){
    this.inner = false;
    var ih = this.array();
    Has.call(this,this.is224,this.shared);
    this.update(this.oKey);
    this.update(ih);
    Has.prototype.finalize.call(this);
  }
};

/* Exports */
var api = mkMain();
api.sha256 = api;
api.sha224 = mkMain(true);
api.sha256.hmac = mkHmac();
api.sha224.hmac = mkHmac(true);

if(IS_CJS) module.exports = api;
else {
  ROOT.sha256 = api.sha256;
  ROOT.sha224 = api.sha224;
  if(IS_AMD) define(function(){ return api; });
}
})();
