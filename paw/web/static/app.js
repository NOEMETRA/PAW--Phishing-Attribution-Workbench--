'use strict';
const $ = id => document.getElementById(id);
const state = {file:null, job:null, case:null, offset:0, poll:0, busy:false, jobsBusy:false};
const labels = {queued:'In coda',running:'In corso',completed:'Completata',failed:'Fallita',timed_out:'Tempo esaurito',cancelled:'Annullata',resource_limited:'Limite risorse',interrupted:'Interrotta',incomplete:'Incompleta',partial:'Parziale',skipped:'Escluso',not_evaluated:'Non valutato',parsed_unverified:'Letto, non verificato',reported_only:'Dichiarato negli header',unavailable:'Non disponibile',verified:'Verificata',available:'Disponibile'};
const stages = {imports:'Preparazione del motore',mime_parsing:'Struttura MIME',ingest:'Conservazione originale',deobfuscation:'Contenuto e link',detonation:'Detonazione',attachment_metadata:'Metadati allegati',headers_authentication:'Header e autenticazione',ip_enrichment:'Arricchimento IP',domain_enrichment:'Arricchimento domini',scoring:'Valutazione',reports:'Report',exports:'Pacchetto evidenze',evidence_seal:'Sigillatura evidenze',completed:'Esecuzione terminata'};
const active = job => job && ['queued','running'].includes(job.status);
function el(tag, className, text){ const n=document.createElement(tag); if(className)n.className=className; if(text!==undefined)n.textContent=String(text); return n; }
function badge(status){return el('span','badge '+(Object.hasOwn(labels,status)?status:''),labels[status]||status||'Non disponibile');}
function notice(message){$('notice').textContent=message||'';$('notice').hidden=!message;}
function duration(seconds){if(!Number.isFinite(seconds))return '—';seconds=Math.max(0,Math.floor(seconds));return `${Math.floor(seconds/60)}m ${String(seconds%60).padStart(2,'0')}s`;}
async function api(path, options={}){
  const response=await fetch(path,{...options,cache:'no-store'});
  if(!response.ok){let detail;try{detail=(await response.json()).detail;}catch{detail=response.statusText;}throw new Error(typeof detail==='string'?detail:JSON.stringify(detail));}
  return response.json();
}
const post=(path,value={})=>api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});
function selectFile(file){
  if(state.busy)return;
  if(!file)return;
  if(!file.name.toLowerCase().endsWith('.eml')){notice('Scegli un EML originale. La conversione MSG non è attualmente disponibile.');state.file=null;}
  else if(file.size===0||file.size>25*1024**2){notice('Il file deve contenere dati e non superare 25 MiB.');state.file=null;}
  else{state.file=file;notice('');}
  $('file-title').textContent=state.file?state.file.name:'Scegli un file o trascinalo qui';
  $('file-description').textContent=state.file?`${(state.file.size/1024).toFixed(1)} KiB · originale da conservare`:'EML originale · massimo 25 MiB';
  $('start-analysis').disabled=!state.file;
}
$('email-file').addEventListener('change',event=>selectFile(event.target.files[0]));
for(const name of ['dragenter','dragover'])$('dropzone').addEventListener(name,event=>{event.preventDefault();$('dropzone').classList.add('drag');});
for(const name of ['dragleave','drop'])$('dropzone').addEventListener(name,event=>{event.preventDefault();$('dropzone').classList.remove('drag');if(name==='drop')selectFile(event.dataTransfer.files[0]);});
$('analysis-form').addEventListener('submit',async event=>{
  event.preventDefault();if(!state.file||state.busy)return;
  state.busy=true;$('start-analysis').disabled=true;$('start-analysis').textContent='Importazione…';$('email-file').disabled=true;notice('');
  const selectedFile=state.file;
  try{
    const form=new FormData();form.append('file',selectedFile);
    const upload=await api('/api/upload',{method:'POST',body:form});
    const created=await post('/api/analyze',{file_path:upload.path,profile:$('profile').value,
      options:{no_egress:true,stix:true,abuse:true,anchor:false,lang:'it'},
      limits:{wall_seconds:Number($('deadline').value),stage_seconds:Number($('stage-timeout').value),memory_bytes:Number($('memory').value)*1024**2}});
    await openJob(created.analysis_id);await refreshJobs();
  }catch(error){notice('Analisi non avviata: '+error.message);}
  finally{state.busy=false;$('email-file').disabled=false;$('start-analysis').disabled=!state.file;$('start-analysis').replaceChildren(document.createTextNode('Avvia analisi '),el('span','', '→'));}
});
$('new-analysis').addEventListener('click',()=>{state.poll++;state.job=null;state.case=null;$('intake-view').hidden=false;$('job-view').hidden=true;$('case-view').hidden=true;notice('');refreshCases().catch(error=>notice(error.message));$('email-file').focus();});
$('mobile-cases').addEventListener('click',()=>{const expanded=document.querySelector('.sidebar').classList.toggle('mobile-open');$('mobile-cases').setAttribute('aria-expanded',String(expanded));});
async function refreshCases(){
  const offset=state.offset;const result=await api(`/api/cases?limit=20&offset=${offset}`);if(offset!==state.offset)return;
  const list=$('case-list');list.replaceChildren();
  for(const item of result.cases){
    const row=el('button','case-row'+(state.case?.case_id===item.case_id?' selected':''));
    row.append(el('strong','',item.subject||item.case_id.replace(/^case-/,'')),el('small','',item.created_at?new Date(item.created_at).toLocaleString('it-IT'):'Data non disponibile'),badge(item.status));
    row.addEventListener('click',()=>openCase(item.case_id).catch(error=>notice(error.message)));list.append(row);
  }
  if(!result.cases.length)list.append(el('p','muted','Nessun caso in questa pagina.'));
  $('case-page').textContent=result.total?`${state.offset+1}–${Math.min(state.offset+20,result.total)} / ${result.total}`:'0 casi';
  $('previous-cases').disabled=state.offset===0;$('next-cases').disabled=state.offset+20>=result.total;
}
$('refresh-cases').addEventListener('click',()=>refreshCases().catch(error=>notice(error.message)));
for(const [id,step] of [['previous-cases',-20],['next-cases',20]])$(id).addEventListener('click',()=>{state.offset=Math.max(0,state.offset+step);refreshCases().catch(error=>notice(error.message));});
async function refreshJobs(){
  if(state.jobsBusy)return;state.jobsBusy=true;
  try{
    const result=await api('/api/analyses');const list=$('job-list');list.replaceChildren();
    for(const item of result.jobs){const row=el('button','job-row');const text=el('span');text.append(el('strong','',item.filename||item.analysis_id),el('small','',`${item.queued_at?new Date(item.queued_at).toLocaleString('it-IT'):''} · ${item.analysis_id.slice(-8)}`));row.append(text,badge(item.status));row.addEventListener('click',()=>openJob(item.analysis_id).catch(error=>notice(error.message)));list.append(row);}
    if(!result.jobs.length)list.append(el('p','muted','Le esecuzioni reali compariranno qui.'));
  }finally{state.jobsBusy=false;}
}
$('refresh-jobs').addEventListener('click',()=>refreshJobs().catch(error=>notice(error.message)));
async function openJob(id){
  const token=++state.poll;state.case=null;state.job={analysis_id:id,status:'loading'};$('case-view').hidden=true;$('intake-view').hidden=true;$('job-view').hidden=false;$('job-log').hidden=true;notice('');
  const poll=async()=>{
    try{
      const job=await api('/api/analysis/'+encodeURIComponent(id));if(token!==state.poll)return;
      state.job={...job,analysis_id:id};renderJob();
      if(active(job)){setTimeout(poll,700);}
      else{await refreshCases();await refreshJobs();if(token!==state.poll)return;if(job.case_id)await openCase(job.case_id,true);}
    }catch(error){if(token!==state.poll)return;notice('Stato del job non disponibile: '+error.message);setTimeout(poll,2500);}
  };
  await poll();
}
function renderJob(){
  const job=state.job, progress=job.observed_progress||{};
  $('job-filename').textContent=job.filename||job.analysis_id;
  $('job-status').replaceChildren(badge(job.status));
  $('job-stage').textContent=job.status==='queued'?'In attesa del worker':(stages[progress.stage]||progress.stage||labels[job.status]||'Preparazione');
  const elapsed=(Date.parse(job.completed_at||new Date().toISOString())-Date.parse(job.queued_at))/1000;
  $('job-elapsed').textContent=duration(elapsed);$('job-limit').textContent=duration(job.limits?.wall_seconds);
  $('cancel-job').disabled=!active(job)||Boolean(job.cancel_requested_at);
  $('cancel-job').textContent=job.cancel_requested_at&&active(job)?'Annullamento richiesto…':'Annulla job';
  $('job-description').textContent=job.error||((job.status==='completed')?'Worker terminato; la copertura dell’analisi è indicata nel caso.':'Fasi osservate dal worker. Nessuna percentuale di avanzamento stimata.');
  const timeline=$('job-timeline');timeline.replaceChildren();
  for(const timing of progress.stage_timings||[]){const skipped=job.no_egress&&['detonation','ip_enrichment','domain_enrichment'].includes(timing.stage);timeline.append(el('li','',`${stages[timing.stage]||timing.stage}${skipped?' · escluso offline':''} · ${Number(timing.elapsed_seconds).toFixed(2)} s`));}
  if(active(job)&&progress.stage)timeline.append(el('li','current',stages[progress.stage]||progress.stage));
  const partial=(job.partial_cases||[])[0];$('open-partial').hidden=!partial;
}
function renderAuthentication(authentication){
  const auth=$('authentication-list');auth.replaceChildren();
  for(const method of ['spf','dkim','dmarc','arc']){
    const row=el('div','coverage-row'),check=el('span');const verification=authentication?.[method]?.verification;
    check.append(badge(verification?.status||'not_evaluated'));
    if(verification?.result)check.append(el('span','badge '+(verification.result==='pass'?'verified':verification.result==='fail'?'failed':'not_evaluated'),'Esito: '+verification.result));
    row.append(el('span','',method.toUpperCase()),check);auth.append(row);
  }
}
$('cancel-job').addEventListener('click',async()=>{if(!state.job)return;const id=state.job.analysis_id;$('cancel-job').disabled=true;try{const job=await post('/api/analysis/'+encodeURIComponent(id)+'/cancel');if(state.job?.analysis_id===id){state.job={...job,analysis_id:id};renderJob();}}catch(error){notice(error.message);if(state.job?.analysis_id===id)$('cancel-job').disabled=false;}});
$('open-partial').addEventListener('click',()=>{const item=state.job?.partial_cases?.[0];if(item)openCase(item.case_id,true).catch(error=>notice(error.message));});
$('show-log').addEventListener('click',async()=>{if(!state.job)return;const id=state.job.analysis_id;try{const log=await api('/api/analysis/'+encodeURIComponent(id)+'/log');if(state.job?.analysis_id!==id)return;$('job-log').textContent=(log.truncated?'Ultimi 64 KiB del log.\n\n':'')+log.text;$('job-log').hidden=false;}catch(error){notice(error.message);}});
async function openCase(id,keepJob=false){
  const token=keepJob?state.poll:++state.poll;
  state.case={case_id:id};$('case-view').hidden=true;$('verify-case').disabled=true;notice('');
  const data=await api('/api/cases/'+encodeURIComponent(id));if(token!==state.poll||state.case?.case_id!==id)return;
  state.case=data;$('verify-case').disabled=false;$('intake-view').hidden=true;$('case-view').hidden=false;if(!keepJob)$('job-view').hidden=true;
  $('case-id').textContent=id;$('case-title').textContent=data.email?.subject||'Evidenze del caso';$('case-status').textContent=labels[data.status]||data.status;
  $('case-scope').textContent=data.execution?.no_egress?'Analisi locale offline':(data.execution?.scope||'Ambito non disponibile');
  $('case-decision').textContent=({Inconclusive:'Inconclusiva',Benign:'Basso rischio',Suspicious:'Sospetta',Malicious:'Elevato rischio'})[data.score?.decision]||data.score?.decision||'Non disponibile';
  $('case-score').textContent=Number.isFinite(data.score?.score)?`Indice euristico ${data.score.score.toFixed(2)} · non una probabilità`:'Indice non disponibile';
  $('case-coverage').textContent=labels[data.execution?.assessment_status||data.score?.assessment_status]||'Non disponibile';
  $('case-integrity').textContent='Da verificare';$('integrity-description').textContent='Coerenza dei file, distinta dall’origine.';
  $('case-caution').textContent=data.status==='completed'?'Esecuzione terminata. Verifiche mancanti e metadati degli allegati non dimostrano l’assenza di phishing o malware.':'Caso incompleto: le evidenze conservate non costituiscono un’analisi conclusa.';
  if(Object.keys(data.artifact_errors||{}).length)$('case-caution').textContent+=' Alcuni artefatti non sono leggibili; dettagli nei dati strutturati.';
  const writing=['queued','running'].includes(data.status);$('verify-case').disabled=writing;
  $('export-case').setAttribute('aria-disabled',String(writing));$('export-case').href=writing?'#':'/api/export/'+encodeURIComponent(id);
  const coverage=$('coverage-list');coverage.replaceChildren();
  for(const [name,value] of Object.entries(data.coverage?.stages||{})){const row=el('div','coverage-row');const label=el('span','',stages[name]||({header_parsing:'Parsing header',received_path:'Catena Received',network_enrichment:'Arricchimento di rete'})[name]||name);if(value.reason)label.append(el('small','',value.reason));row.append(label,badge(value.status));coverage.append(row);}
  if(!coverage.childNodes.length)coverage.append(el('p','muted','Copertura non disponibile.'));
  const facts=$('origin-details');facts.replaceChildren();
  for(const [name,value] of [['From dichiarato',data.email?.from],['IP candidato',data.origin?.ip],['Dominio From',data.authentication?.from_domain],['Fonte',data.origin?.source],['Origine verificata',data.origin?.verified===true?'Sì':'Non verificata']])facts.append(el('dt','',name),el('dd','mono',value||'Non disponibile'));
  renderAuthentication(data.authentication);
  const attachments=$('attachment-list');attachments.replaceChildren();
  for(const item of Array.isArray(data.attachments)?data.attachments:[]){const article=el('article','attachment');article.append(el('h3','',item.filename),el('p','muted',`${item.size} byte · ${item.declared_mime||item.mime||'Tipo dichiarato sconosciuto'}`),el('code','mono','SHA-256 '+(item.sha256||'Non disponibile')),el('p','muted','Malware / macro: non valutati'),el('code','mono',item.evidence_path||'Percorso evidenza non disponibile'));attachments.append(article);}
  if(!attachments.childNodes.length)attachments.append(el('p','muted',Array.isArray(data.attachments)?'Nessun allegato rilevato.':'Inventario allegati non disponibile.'));
  $('case-data').textContent=JSON.stringify(data,null,2);renderReport();activateTab('overview');await refreshCases();
}
function renderReport(){const value=state.case?.[$('report-kind').value];$('report-content').textContent=value||'Report non disponibile per questo caso.';}
$('export-case').addEventListener('click',event=>{if($('export-case').getAttribute('aria-disabled')==='true')event.preventDefault();});
$('report-kind').addEventListener('change',renderReport);
function activateTab(tab){for(const button of document.querySelectorAll('[data-tab]')){const selected=button.dataset.tab===tab;button.setAttribute('aria-selected',String(selected));button.tabIndex=selected?0:-1;$(button.dataset.tab+'-tab').hidden=!selected;}}
const tabButtons=[...document.querySelectorAll('[data-tab]')];
for(const button of tabButtons){button.addEventListener('click',()=>activateTab(button.dataset.tab));button.addEventListener('keydown',event=>{let index=tabButtons.indexOf(button);if(event.key==='ArrowRight')index=(index+1)%tabButtons.length;else if(event.key==='ArrowLeft')index=(index+tabButtons.length-1)%tabButtons.length;else if(event.key==='Home')index=0;else if(event.key==='End')index=tabButtons.length-1;else return;event.preventDefault();activateTab(tabButtons[index].dataset.tab);tabButtons[index].focus();});}
$('verify-case').addEventListener('click',async()=>{if(!state.case)return;const id=state.case.case_id,token=state.poll;$('verify-case').disabled=true;$('case-integrity').textContent='Verifica in corso…';try{const result=await post('/api/cases/'+encodeURIComponent(id)+'/verify');if(state.case?.case_id!==id||state.poll!==token)return;$('case-integrity').textContent=result.integrity==='verified'?'Verificata':'Non verificata';$('integrity-description').textContent='File locali · '+new Date(result.checked_at).toLocaleTimeString('it-IT');}catch(error){if(state.case?.case_id===id&&state.poll===token){notice(error.message);$('case-integrity').textContent='Non disponibile';}}finally{if(state.case?.case_id===id&&state.poll===token)$('verify-case').disabled=false;}});
async function connect(){try{await api('/health');$('connection-dot').classList.add('green');$('connection').textContent='Servizio locale connesso';}catch{$('connection-dot').classList.remove('green');$('connection').textContent='Servizio non raggiungibile';}}
Promise.all([connect(),refreshCases(),refreshJobs()]).catch(error=>notice('Dati non disponibili: '+error.message));
setInterval(()=>{connect();refreshJobs().catch(()=>{});},5000);
