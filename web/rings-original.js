// ---- 3D rings (canvas) ----
const reduce=matchMedia("(prefers-reduced-motion: reduce)").matches;
function proj(p,spin,tilt,cx,cy,f){
  const cs=Math.cos(spin),sn=Math.sin(spin);
  const x=p.x*cs+p.z*sn, z=-p.x*sn+p.z*cs, y=p.y;
  const ct=Math.cos(tilt),st=Math.sin(tilt);
  const y2=y*ct+z*st, z2=-y*st+z*ct, k=f/(f+z2);
  return {x:cx+x*k,y:cy-y2*k,z:z2};
}
function seg(faces,o){
  const N=8,A=[];for(let i=0;i<=N;i++)A.push(o.a0+(o.a1-o.a0)*i/N);
  const P=(r,a,y)=>({x:r*Math.cos(a),y,z:r*Math.sin(a)});
  const rv=A.slice().reverse();
  const top=[...A.map(a=>P(o.r2,a,o.t)),...rv.map(a=>P(o.r1,a,o.t))];
  const outer=[...A.map(a=>P(o.r2,a,o.t)),...rv.map(a=>P(o.r2,a,-o.t))];
  const inner=[...A.map(a=>P(o.r1,a,o.t)),...rv.map(a=>P(o.r1,a,-o.t))];
  const c0=[P(o.r1,o.a0,o.t),P(o.r2,o.a0,o.t),P(o.r2,o.a0,-o.t),P(o.r1,o.a0,-o.t)];
  const c1=[P(o.r1,o.a1,o.t),P(o.r2,o.a1,o.t),P(o.r2,o.a1,-o.t),P(o.r1,o.a1,-o.t)];
  [[top,1],[outer,.7],[inner,.5],[c0,.6],[c1,.6]].forEach(([pts,b])=>faces.push({pts,b,rgb:o.rgb,glow:b===1?o.glow:0,edge:o.edge}));
}
function renderFaces(ctx,faces,spin,tilt,cx,cy,f){
  const pf=faces.map(F=>{const q=F.pts.map(p=>proj(p,spin,tilt,cx,cy,f));return {...F,q,z:q.reduce((s,p)=>s+p.z,0)/q.length}});
  pf.sort((a,b)=>b.z-a.z);
  pf.forEach(F=>{
    ctx.beginPath();F.q.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.closePath();
    ctx.shadowColor=F.glow>0?`rgba(255,106,43,${.75*F.glow})`:"transparent";ctx.shadowBlur=F.glow>0?20*F.glow:0;
    ctx.fillStyle=`rgb(${F.rgb.map(c=>Math.round(c*F.b)).join(",")})`;ctx.fill();
    ctx.shadowBlur=0;ctx.lineWidth=1;ctx.strokeStyle=F.edge||"rgba(255,255,255,.10)";ctx.stroke();
  });
}
function fit(c){const r=c.getBoundingClientRect(),d=Math.min(devicePixelRatio||1,2);c.width=Math.max(1,r.width*d);c.height=Math.max(1,r.height*d);const x=c.getContext("2d");x.setTransform(d,0,0,d,0,0);return {x,w:r.width,h:r.height};}
const mix=(a,b,t)=>a.map((v,i)=>v+(b[i]-v)*t);
const lerpState={atk:FAMS.map(()=>0),def:LAYERS.map(()=>Array(8).fill(0))};

function drawAtk(time){
  const c=$("#atkCanvas"),{x,w,h}=fit(c);x.clearRect(0,0,w,h);
  const u=Math.min(w/460,h/380),cx=w/2,cy=h/2+4*u,spin=reduce?.5:time*0.00022,tilt=0.95,f=620*u;
  const faces=[],N=FAMS.length,gap=0.07,on=R[cur].on;
  FAMS.forEach((fm,i)=>{
    const tgt=on.includes(fm.k)?1:0;lerpState.atk[i]+=(tgt-lerpState.atk[i])*(reduce?1:.1);
    const lit=lerpState.atk[i],pulse=reduce?1:.75+.25*Math.sin(time*.004+i);
    const rgb=mix([52,58,82],[255,106,43],lit);
    const a0=i/N*Math.PI*2+gap,a1=(i+1)/N*Math.PI*2-gap;
    seg(faces,{r1:84*u,r2:136*u,t:(11+10*lit)*u,a0,a1,rgb,glow:lit*pulse,edge:lit>.5?"rgba(255,200,170,.35)":null});
  });
  renderFaces(x,faces,spin,tilt,cx,cy,f);
  x.font=`700 ${Math.max(10,11.5*u)}px "Plus Jakarta Sans",sans-serif`;x.textBaseline="middle";
  FAMS.forEach((fm,i)=>{
    const am=(i+.5)/N*Math.PI*2,p=proj({x:166*u*Math.cos(am),y:0,z:166*u*Math.sin(am)},spin,tilt,cx,cy,f);
    const lit=lerpState.atk[i];x.fillStyle=lit>.5?"#ffffff":"#7d8399";
    x.textAlign=p.x>cx+8?"left":p.x<cx-8?"right":"center";x.fillText(fm.s,p.x,p.y);
  });
}
function drawDef(time){
  const c=$("#defCanvas"),{x,w,h}=fit(c);x.clearRect(0,0,w,h);
  const u=Math.min(w/460,h/380),cx=w/2,cy=h/2+4*u,spin=reduce?-.4:-time*0.00016,tilt=0.95,f=620*u;
  const faces=[],gap=0.06,rings=[[112,136],[88,106],[64,82],[40,58]];
  LAYERS.forEach((L,li)=>{
    const col=hexRgb(L.c);
    for(let s=0;s<8;s++){
      const filled=s<L.rules[cur],isNew=filled&&s>=(cur?L.rules[cur-1]:0);
      const tgt=filled?1:0;lerpState.def[li][s]+=(tgt-lerpState.def[li][s])*(reduce?1:.1);
      const lit=lerpState.def[li][s],pulse=isNew&&!reduce?.6+.4*Math.sin(time*.006+s):0;
      const rgb=mix([40,44,62],col,lit*(isNew?1:.82));
      seg(faces,{r1:rings[li][0]*u,r2:rings[li][1]*u,t:(5+4*lit)*u,a0:s/8*Math.PI*2+gap,a1:(s+1)/8*Math.PI*2-gap,rgb,glow:0,edge:isNew?"rgba(255,255,255,.7)":null});
    }
  });
  // core disc
  const disc=[];for(let i=0;i<=40;i++){const a=i/40*Math.PI*2;disc.push({x:30*u*Math.cos(a),y:0,z:30*u*Math.sin(a)});}
  faces.push({pts:disc,b:1,rgb:[255,106,43],glow:0,edge:"rgba(255,255,255,.25)"});
  renderFaces(x,faces,spin,tilt,cx,cy,f);
}
function hexRgb(h){return [1,3,5].map(i=>parseInt(h.slice(i,i+2),16));}
function loop(t){drawAtk(t);drawDef(t);if(!reduce)requestAnimationFrame(loop);}


requestAnimationFrame(loop);
