document.addEventListener('DOMContentLoaded',()=>{
  // password show/hide
  document.querySelectorAll('.eye').forEach(b=>b.addEventListener('click',()=>{
    const i=b.parentElement.querySelector('input');
    i.type=i.type==='password'?'text':'password';
  }));
  // flash dismiss
  document.querySelectorAll('.flash button').forEach(b=>b.addEventListener('click',()=>b.parentElement.remove()));
  // sidebar toggle
  const sb=document.getElementById('sidebar');
  document.querySelectorAll('[data-toggle-sidebar]').forEach(b=>b.addEventListener('click',()=>sb&&sb.classList.toggle('open')));
  // profile menu
  const av=document.getElementById('avatar'),pop=document.getElementById('menuPop');
  if(av&&pop){av.addEventListener('click',e=>{e.stopPropagation();pop.classList.toggle('open')});
    document.addEventListener('click',()=>pop.classList.remove('open'));}
  // register: live validation
  const pw=document.getElementById('password'),cf=document.getElementById('confirm'),msg=document.getElementById('matchMsg');
  if(pw&&cf&&msg){
    const check=()=>{
      if(!cf.value){msg.textContent='';msg.className='';return;}
      if(pw.value===cf.value){msg.textContent='✓ Passwords match.';msg.className='ok';}
      else{msg.textContent='Passwords do not match.';msg.className='err';}
    };
    pw.addEventListener('input',check);cf.addEventListener('input',check);
  }
  // confirm delete
  document.querySelectorAll('form[data-confirm]').forEach(f=>f.addEventListener('submit',e=>{
    if(!confirm(f.dataset.confirm))e.preventDefault();
  }));
});
