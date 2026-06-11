/-
  CertiorPlan.Debugger.Widget.UI - ProofWidgets Verification Explorer

  The flagship UI component that renders inside the Lean4 infoview via
  ProofWidgets. Extends ImpLab's trace console with three Certior-specific
  panels: Flow Graph, Proof Certificates, and Compliance Status.

  Architecture:
    - React component rendered via `@[widget_module]`
    - Communicates with Lean4 via `useRpcSession()` hook
    - 11 RPC methods for session control + verification inspection
    - Color-coded security levels (green/blue/amber/red)
    - Time-travel debugging with full verification state

  Panels:
    [Left Column]     Program listing with syntax highlighting
    [Right Column]    Call Stack
                      Locals / Resources (side by side)
                      Flow Labels - security level per data binding
                      Proof Certificates - issued verification proofs
                      Flow Graph - information flow edges
                      Compliance Status - policy dashboard

  Usage in Lean4:
    ```
    #widget CertiorPlan.verificationExplorerWidget
      CertiorPlan.WidgetInitProps.mk hipaaDemo
    ```

  Copyright (c) 2026 Certior. All rights reserved.
  Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
-/

import Lean
import CertiorPlan.Debugger.Widget.Types

open Lean Widget

namespace CertiorPlan

@[widget_module]
def verificationExplorerWidget : Widget.Module where
  javascript := "
import * as React from 'react';
import { useRpcSession } from '@leanprover/infoview';
const e = React.createElement;
const { useState, useEffect, useRef } = React;

/* ─── Utilities ──────────────────────────────────────────────────── */

function groupBySkill(program) {
  const groups = [];
  for (const line of program) {
    const last = groups.length > 0 ? groups[groups.length - 1] : null;
    if (!last || last.skillName !== line.skillName) {
      groups.push({ skillName: line.skillName, lines: [line] });
    } else {
      last.lines.push(line);
    }
  }
  return groups;
}

function stopReasonStyle(stopReason, terminated) {
  if (terminated) return { label:'terminated', fg:'#7f1d1d', bg:'#fff1f2', border:'#fecdd3' };
  const map = {
    entry:      { label:'entry',      fg:'#1d4ed8', bg:'#eef2ff', border:'#c7d2fe' },
    step:       { label:'step',       fg:'#0e7490', bg:'#ecfeff', border:'#a5f3fc' },
    breakpoint: { label:'breakpoint', fg:'#0f4c81', bg:'#ecfeff', border:'#67e8f9' },
    exception:  { label:'exception',  fg:'#9a3412', bg:'#fff7ed', border:'#fed7aa' },
    flow_violation:    { label:'flow violation',    fg:'#b91c1c', bg:'#fef2f2', border:'#fecaca' },
    budget_exceeded:   { label:'budget exceeded',   fg:'#a16207', bg:'#fffbeb', border:'#fde68a' },
    capability_watch:  { label:'capability watch',  fg:'#7e22ce', bg:'#faf5ff', border:'#d8b4fe' },
    approval_required: { label:'approval required', fg:'#b45309', bg:'#fffbeb', border:'#fcd34d' },
    approval_rejected: { label:'rejected',          fg:'#991b1b', bg:'#fef2f2', border:'#fca5a5' },
  };
  return map[stopReason] || { label:String(stopReason), fg:'#334155', bg:'#f8fafc', border:'#cbd5e1' };
}

/* ─── Style helpers ──────────────────────────────────────────────── */

function btnStyle(variant, disabled) {
  if (disabled) return {
    border:'1px solid #dbe4ee', background:'linear-gradient(180deg,#f8fafc 0%,#eef2ff 100%)',
    color:'#94a3b8', borderRadius:'9px', padding:'5px 9px', fontSize:'11px',
    fontWeight:700, letterSpacing:'0.03em', cursor:'default'
  };
  if (variant === 'continue') return {
    border:'1px solid #0e7490', background:'linear-gradient(180deg,#0891b2 0%,#0e7490 100%)',
    color:'#fff', borderRadius:'9px', padding:'5px 9px', fontSize:'11px',
    fontWeight:700, letterSpacing:'0.03em', cursor:'pointer',
    boxShadow:'0 0 0 1px rgba(255,255,255,0.2) inset,0 6px 14px -9px rgba(14,116,144,0.8)'
  };
  if (variant === 'approve') return {
    border:'1px solid #16a34a', background:'linear-gradient(180deg,#22c55e 0%,#16a34a 100%)',
    color:'#fff', borderRadius:'9px', padding:'5px 9px', fontSize:'11px',
    fontWeight:700, cursor:'pointer'
  };
  if (variant === 'reject') return {
    border:'1px solid #dc2626', background:'linear-gradient(180deg,#ef4444 0%,#dc2626 100%)',
    color:'#fff', borderRadius:'9px', padding:'5px 9px', fontSize:'11px',
    fontWeight:700, cursor:'pointer'
  };
  return {
    border:'1px solid #bae6fd', background:'linear-gradient(180deg,#fff 0%,#f0f9ff 100%)',
    color:'#0f172a', borderRadius:'9px', padding:'5px 9px', fontSize:'11px',
    fontWeight:700, letterSpacing:'0.03em', cursor:'pointer',
    boxShadow:'0 1px 0 #fff inset'
  };
}

function panel(title, content, key, opts) {
  const accent = (opts && opts.accent) || '#0e7490';
  const badge = opts && opts.badge;
  return e('section', { key, style:{
    border:'1px solid #dbeafe', borderRadius:'10px', padding:'8px 9px',
    background:'linear-gradient(170deg,rgba(255,255,255,0.96) 0%,rgba(240,249,255,0.95) 100%)',
    boxShadow:'0 10px 25px -22px rgba(14,116,144,0.55)'
  }}, [
    e('div', { key:'hdr', style:{
      display:'flex', justifyContent:'space-between', alignItems:'center',
      marginBottom:'6px', borderBottom:'1px solid #e2e8f0', paddingBottom:'4px'
    }}, [
      e('span', { key:'t', style:{
        fontWeight:700, fontSize:'10px', color:accent,
        textTransform:'uppercase', letterSpacing:'0.08em'
      }}, title),
      badge ? e('span', { key:'b', style:{
        fontSize:'9px', fontWeight:700, color:badge.fg,
        background:badge.bg, border:'1px solid '+(badge.border||badge.bg),
        borderRadius:'999px', padding:'1px 6px'
      }}, badge.text) : null
    ]),
    content
  ]);
}

/* ─── Code tokens ────────────────────────────────────────────────── */

function renderTokens(text, prefix) {
  const toks = text.match(/:=|[(),]|-?\\d+|[A-Za-z_][A-Za-z0-9_]*|@\\w+|\\s+|./g) || [];
  let prev = '';
  return toks.map((tok, i) => {
    if (/^\\s+$/.test(tok)) return tok;
    const s = {};
    if (/^(let|set|get|return|emit|invoke|checkFlow|def|skill|main|require|resource)$/.test(tok)) {
      s.color = '#0e7490'; s.fontWeight = 700;
    } else if (/^@(Public|Internal|Sensitive|Restricted)$/.test(tok)) {
      const lvlMap = {'@Public':'#22c55e','@Internal':'#3b82f6','@Sensitive':'#f59e0b','@Restricted':'#ef4444'};
      s.color = lvlMap[tok] || '#64748b'; s.fontWeight = 700;
    } else if (/^-?\\d+$/.test(tok)) {
      s.color = '#166534'; s.fontWeight = 650;
    } else if (/^[:=(),]$/.test(tok)) {
      s.color = '#64748b';
    } else if (prev === 'invoke' || prev === 'skill') {
      s.color = '#0f766e'; s.fontWeight = 700;
    }
    if (/^[A-Za-z_]/.test(tok)) prev = tok;
    return e('span', { key: prefix+'-t-'+i, style: s }, tok);
  });
}

/* ─── Flow Labels Panel (NEW) ────────────────────────────────────── */

function FlowLabelsPanel({ flowLabels }) {
  if (!flowLabels || flowLabels.length === 0) {
    return panel('Flow Labels', e('p', { style:{ margin:0, color:'#64748b', fontSize:'11px' }}, '(no labels assigned)'), 'flow-labels');
  }
  const rows = flowLabels.map((fl, i) =>
    e('div', { key:i, style:{
      display:'flex', alignItems:'center', gap:'6px', marginBottom:'3px'
    }}, [
      e('span', { key:'id', style:{ fontWeight:600, minWidth:'80px' }}, fl.dataId),
      e('span', { key:'lvl', style:{
        fontSize:'10px', fontWeight:700, padding:'1px 7px', borderRadius:'999px',
        color: fl.levelColor, background: fl.levelBgColor,
        border: '1px solid ' + fl.levelBorderColor
      }}, fl.level),
      ...(fl.tags || []).map((tag, ti) =>
        e('span', { key:'tag-'+ti, style:{
          fontSize:'9px', color:'#64748b', background:'#f1f5f9',
          borderRadius:'4px', padding:'0 4px'
        }}, tag)
      )
    ])
  );
  return panel('Flow Labels', e('div', { key:'list' }, rows), 'flow-labels', {
    accent: '#3b82f6',
    badge: { text: flowLabels.length + ' bindings', fg:'#1d4ed8', bg:'#dbeafe' }
  });
}

/* ─── Certificates Panel (NEW) ───────────────────────────────────── */

function CertificatesPanel({ certificates }) {
  if (!certificates || certificates.length === 0) {
    return panel('Certificates', e('p', { style:{ margin:0, color:'#64748b', fontSize:'11px' }}, '(none issued)'), 'certs');
  }
  const rows = certificates.map((cert, i) => {
    const verified = cert.property !== 'flow_violation';
    return e('div', { key:i, style:{
      marginBottom:'6px', padding:'4px 6px', borderRadius:'6px',
      border: '1px solid ' + (verified ? '#bbf7d0' : '#fecaca'),
      background: verified ? '#f0fdf4' : '#fef2f2'
    }}, [
      e('div', { key:'hdr', style:{
        display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'2px'
      }}, [
        e('span', { key:'idx', style:{ fontWeight:700, fontSize:'11px' }},
          (verified ? '✓ ' : '✗ ') + '①②③④⑤⑥⑦⑧⑨⑩'[cert.index] + ' '),
        e('span', { key:'prop', style:{
          fontWeight:600, fontSize:'11px',
          color: verified ? '#166534' : '#b91c1c'
        }}, cert.property)
      ]),
      e('div', { key:'flow', style:{ fontSize:'10px', color:'#475569' }},
        (cert.inputLabels || []).join(', ') + ' → ' + cert.outputLabel),
      cert.detail ? e('div', { key:'det', style:{ fontSize:'10px', color:'#64748b', fontStyle:'italic' }}, cert.detail) : null
    ]);
  });
  const allOk = certificates.every(c => c.property !== 'flow_violation');
  return panel('Certificates', e('div', { key:'list' }, rows), 'certs', {
    accent: allOk ? '#16a34a' : '#dc2626',
    badge: { text: certificates.length + ' issued', fg: allOk ? '#166534' : '#b91c1c', bg: allOk ? '#dcfce7' : '#fee2e2' }
  });
}

/* ─── Flow Graph Panel (NEW) ─────────────────────────────────────── */

function FlowGraphPanel({ flowEdges }) {
  if (!flowEdges || flowEdges.length === 0) {
    return panel('Flow Graph', e('p', { style:{ margin:0, color:'#64748b', fontSize:'11px' }}, '(no edges)'), 'flow-graph');
  }
  const rows = flowEdges.map((edge, i) => {
    const ok = edge.allowed;
    return e('div', { key:i, style:{
      display:'flex', flexWrap:'wrap', alignItems:'center', gap:'4px', marginBottom:'3px',
      padding:'4px 6px', borderRadius:'4px',
      background: ok ? '#f8fafc' : '#fef2f2',
      border: ok ? '1px solid #e2e8f0' : '1px solid #fecaca'
    }}, [
      e('span', { key:'src', style:{ fontWeight:600, fontSize:'10px', background: ok ? '#e0f2fe' : '#fee2e2', padding: '2px 4px', borderRadius: '4px', border: ok ? '1px solid #bae6fd' : '1px solid #fecaca', whiteSpace: 'nowrap' }}, edge.source),
      e('span', { key:'arrow', style:{ color: ok ? '#0ea5e9' : '#dc2626', fontWeight:700, fontSize:'12px' }}, ' → '),
      e('span', { key:'tgt', style:{ fontWeight:600, fontSize:'10px', background: '#f1f5f9', padding: '2px 4px', borderRadius: '4px', border: '1px solid #e2e8f0', whiteSpace: 'nowrap' }}, edge.target),
      e('span', { key:'status', style:{
        marginLeft:'auto', fontWeight:700, fontSize:'11px',
        color: ok ? '#16a34a' : '#dc2626'
      }}, ok ? '✓' : '✗')
    ]);
  });
  const violations = flowEdges.filter(e => !e.allowed).length;
  return panel('Flow Graph', e('div', null, [
    ...rows,
    e('div', { key:'legend', style:{
      marginTop:'4px', paddingTop:'4px', borderTop:'1px solid #e2e8f0',
      fontSize:'10px', color:'#64748b'
    }}, '✓ = flow allowed   ✗ = flow blocked')
  ]), 'flow-graph', {
    accent: violations > 0 ? '#dc2626' : '#0e7490',
    badge: violations > 0 ? { text: violations + ' violation' + (violations > 1 ? 's' : ''), fg:'#b91c1c', bg:'#fee2e2' } : null
  });
}

/* ─── Compliance Panel (NEW) ─────────────────────────────────────── */

function CompliancePanel({ compliance, stopReason }) {
  if (!compliance) return null;
  const c = compliance;
  const budgetPct = c.budgetTotal > 0 ? Math.round((c.budgetUsed * 100) / c.budgetTotal) : 0;
  const budgetColor = budgetPct > 90 ? '#dc2626' : budgetPct > 70 ? '#f59e0b' : '#16a34a';
  const needsApproval = stopReason === 'approval_required';
  const rows = [
    { label:'Policy', value:c.policy || 'Default', color:'#0f172a', bold:true },
    { label:'Steps executed', value:String(c.totalSteps), color:'#475569' },
    { label:'Certificates', value:String(c.certificateCount), color:'#16a34a' },
    { label:'Flow violations', value:String(c.flowViolations), color: c.flowViolations > 0 ? '#dc2626' : '#16a34a' },
    { label:'Budget', value: c.budgetUsed+'/'+c.budgetTotal+' ('+budgetPct+'%)', color:budgetColor },
    { label:'Approvals pending', value:String(c.approvalsPending), color: c.approvalsPending > 0 ? '#f59e0b' : '#16a34a' },
  ];
  return panel('Compliance', e('div', null, [
    ...rows.map((r, i) => e('div', { key:i, style:{
      display:'flex', justifyContent:'space-between', fontSize:'11px', marginBottom:'2px'
    }}, [
      e('span', { key:'l', style:{ color:'#64748b' }}, r.label),
      e('span', { key:'v', style:{ fontWeight: r.bold ? 700 : 600, color:r.color }}, r.value)
    ])),
    // Budget bar
    e('div', { key:'bar-outer', style:{
      marginTop:'4px', height:'4px', borderRadius:'2px', background:'#e2e8f0'
    }}, e('div', { key:'bar-inner', style:{
      height:'100%', borderRadius:'2px', background:budgetColor,
      width: Math.min(budgetPct, 100)+'%', transition:'width 0.3s ease'
    }})),
    c.allClear ? e('div', { key:'clear', style:{
      marginTop:'6px', textAlign:'center', fontWeight:700, fontSize:'11px',
      color:'#16a34a', background:'#f0fdf4', border:'1px solid #bbf7d0',
      borderRadius:'6px', padding:'3px'
    }}, '✓ ALL CLEAR') : null
  ]), 'compliance', {
    accent: c.allClear ? '#16a34a' : '#f59e0b',
    badge: c.allClear
      ? { text:'COMPLIANT', fg:'#166534', bg:'#dcfce7', border:'#bbf7d0' }
      : { text:'REVIEW', fg:'#92400e', bg:'#fef3c7', border:'#fde68a' }
  });
}

/* ─── Main Widget ────────────────────────────────────────────────── */

export default function(props) {
  const rs = useRpcSession();
  const [session, setSession] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [narrow, setNarrow] = useState(false);
  const [activeTab, setActiveTab] = useState('flow-labels');
  const sidRef = useRef(null);
  const launchParams = {
    planInfo: props.planInfo,
    stopOnEntry: props.stopOnEntry ?? true,
    breakpoints: props.breakpoints ?? []
  };
  const launchSig = JSON.stringify(launchParams);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const check = () => setNarrow(window.innerWidth < 960);
    check();
    window.addEventListener('resize', check);
    return () => window.removeEventListener('resize', check);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setBusy(true); setError(null);
      try {
        const s = await rs.call('CertiorPlan.Debugger.Widget.Server.widgetLaunch', launchParams);
        if (!cancelled) { sidRef.current = s.sessionId; setSession(s); }
      } catch(e) { if (!cancelled) setError(String(e)); }
      finally { if (!cancelled) setBusy(false); }
    })();
    return () => {
      cancelled = true;
      if (sidRef.current !== null) {
        rs.call('CertiorPlan.Debugger.Widget.Server.widgetDisconnect',
          { sessionId: sidRef.current }).catch(()=>{});
        sidRef.current = null;
      }
    };
  }, [rs, launchSig]);

  async function ctrl(method) {
    if (!session) return;
    setBusy(true); setError(null);
    try {
      const updated = await rs.call(method, { sessionId: session.sessionId });
      sidRef.current = updated.sessionId;
      setSession(updated);
    } catch(e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function approve(approved) {
    if (!session) return;
    setBusy(true); setError(null);
    try {
      const updated = await rs.call('CertiorPlan.Debugger.Widget.Server.widgetApprove', {
        sessionId: session.sessionId,
        stepId: 'step_' + session.state.pc,
        approved,
        reason: approved ? 'Manual approval via widget' : 'Rejected via widget'
      });
      sidRef.current = updated.sessionId;
      setSession(updated);
    } catch(e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  /* Error / loading states */
  if (error) return e('pre', { style:{
    color:'#b42318', margin:0, border:'1px solid #fecaca',
    background:'#fef2f2', borderRadius:'8px', padding:'10px'
  }}, String(error));
  if (!session) return e('div', { style:{
    border:'1px solid #e2e8f0', borderRadius:'8px', padding:'10px', color:'#475569'
  }}, busy ? 'Launching verification session...' : 'No session');

  const st = session.state;
  const prog = session.program;
  const groups = groupBySkill(prog);
  const tone = stopReasonStyle(session.stopReason, session.terminated);
  const needsApproval = session.stopReason === 'approval_required';
  const ns = 'CertiorPlan.Debugger.Widget.Server.';

  /* ─── Program listing ─── */
  const programSections = groups.map((g, gi) =>
    e('div', { key:'g-'+gi, style:{ marginBottom:'10px' }}, [
      e('div', { key:'hdr', style:{
        fontWeight:700, borderBottom:'1px solid #e2e8f0', marginBottom:'4px', paddingBottom:'3px'
      }}, [
        e('span', { key:'kw', style:{ color:'#0f4c81', fontWeight:700 }}, 'skill '),
        e('span', { key:'nm', style:{ color:'#0f172a', fontWeight:700 }}, g.skillName),
        e('span', { key:'p', style:{ color:'#64748b' }}, '(...)')
      ]),
      e('ol', { key:'lines', style:{ margin:0, paddingLeft:'20px' }},
        g.lines.map((line, li) => {
          const active = st.skillName === line.skillName && st.stepLine === line.stepLine;
          return e('li', { key:'l-'+li+'-'+line.stepLine, style:{
            background: active ? '#cffafe' : 'transparent',
            border: active ? '1px solid #0ea5a4' : '1px solid transparent',
            borderRadius:'6px', padding:'1px 6px 1px 10px',
            boxShadow: active ? 'inset 4px 0 0 #0f766e' : 'none',
            marginBottom:'1px', whiteSpace:'pre', fontSize:'11px'
          }}, [
            e('span', { key:'pfx', style:{ color:'#64748b' }},
              '[L'+line.sourceLine+'] '+line.stepLine+'  '),
            ...renderTokens(line.text, 'l-'+li)
          ]);
        })
      )
    ])
  );

  /* ─── Pill metadata ─── */
  const pill = (k, v) => e('span', { key:k, style:{
    border:'1px solid #bae6fd', borderRadius:'999px',
    background:'linear-gradient(180deg,#fff 0%,#f0f9ff 100%)',
    padding:'1px 6px', color:'#0f4c81', fontSize:'9px'
  }}, k+':'+v);

  /* ─── Tabbed Certior panels ─── */
  const tabs = [
    { id:'flow-labels', label:'Flow Labels' },
    { id:'certificates', label:'Certificates' },
    { id:'flow-graph', label:'Flow Graph' },
    { id:'compliance', label:'Compliance' },
  ];
  const tabBar = e('div', { key:'tabs', style:{
    display:'flex', gap:'2px', marginBottom:'8px', borderBottom:'1px solid #e2e8f0', paddingBottom:'2px'
  }}, tabs.map(t => e('button', { key:t.id, onClick:()=>setActiveTab(t.id), style:{
    border:'none', background: activeTab === t.id ? '#0e7490' : 'transparent',
    color: activeTab === t.id ? '#fff' : '#64748b',
    borderRadius:'6px 6px 0 0', padding:'3px 8px', fontSize:'10px',
    fontWeight:700, cursor:'pointer', letterSpacing:'0.03em'
  }}, t.label)));

  const certiorPanel = activeTab === 'flow-labels' ? FlowLabelsPanel({ flowLabels: st.flowLabels })
    : activeTab === 'certificates' ? CertificatesPanel({ certificates: st.certificates })
    : activeTab === 'flow-graph' ? FlowGraphPanel({ flowEdges: st.flowEdges })
    : CompliancePanel({ compliance: st.compliance, stopReason: session.stopReason });

  /* ─── Call stack ─── */
  const stackRows = st.callStack.map((f, i) =>
    e('li', { key:i, style:{ fontWeight: i===0?700:500, opacity: i===0?1:0.78, marginBottom:'2px', fontSize:'11px' }},
      (i===0?'→ ':'  ') + f.skillName + ':' + f.stepLine + ' [L'+f.sourceLine+']')
  );

  /* ─── Locals / resources ─── */
  const mkBindings = (bindings) => bindings.map((b, i) =>
    e('li', { key:i, style:{ marginBottom:'2px', fontSize:'11px' }}, b.name + ' = ' + b.value)
  );

  /* ─── Main layout ─── */
  return e('div', { style:{
    border:'1px solid #cfe7ff', borderRadius:'12px', padding:'12px',
    background:
      'radial-gradient(120% 120% at 10% 0%,rgba(186,230,253,0.38) 0%,rgba(255,255,255,0) 45%),' +
      'radial-gradient(120% 120% at 100% 100%,rgba(199,210,254,0.26) 0%,rgba(255,255,255,0) 40%),' +
      'linear-gradient(180deg,#f8fbff 0%,#ffffff 100%)',
    fontFamily:'IBM Plex Mono,ui-monospace,SFMono-Regular,Menlo,monospace',
    fontSize:'12px', lineHeight:1.42,
    boxShadow:'0 20px 45px -36px rgba(14,116,144,0.75)'
  }}, [
    /* Header */
    e('div', { key:'hud', style:{
      display:'flex', justifyContent:'space-between', alignItems:'center',
      marginBottom:'8px', paddingBottom:'5px', borderBottom:'1px solid #dbeafe',
      color:'#0f4c81', fontSize:'10px', letterSpacing:'0.08em', textTransform:'uppercase'
    }}, [
      e('span', { key:'l' }, [
        e('span', { key:'shield', style:{ marginRight:'4px' }}, '🛡'),
        'Certior Verification Explorer'
      ]),
      e('span', { key:'r', style:{ opacity:0.72 }}, 'Verified Session')
    ]),

    /* Controls */
    e('div', { key:'ctrl', style:{
      display:'flex', gap:'6px', alignItems:'center', marginBottom:'8px', flexWrap:'wrap'
    }}, [
      e('button', { key:'back', onClick:()=>ctrl(ns+'widgetStepBack'), disabled:busy, style:btnStyle('default',busy) }, '⟵ Back'),
      e('button', { key:'step', onClick:()=>ctrl(ns+'widgetStepIn'), disabled:busy, style:btnStyle('default',busy) }, 'Step In'),
      e('button', { key:'next', onClick:()=>ctrl(ns+'widgetNext'), disabled:busy, style:btnStyle('default',busy) }, 'Next'),
      e('button', { key:'out', onClick:()=>ctrl(ns+'widgetStepOut'), disabled:busy, style:btnStyle('default',busy) }, 'Step Out'),
      e('button', { key:'cont', onClick:()=>ctrl(ns+'widgetContinue'), disabled:busy, style:btnStyle('continue',busy) }, '▶ Continue'),
      needsApproval ? e('button', { key:'approve', onClick:()=>approve(true), disabled:busy, style:btnStyle('approve',busy) }, '✓ Approve') : null,
      needsApproval ? e('button', { key:'reject', onClick:()=>approve(false), disabled:busy, style:btnStyle('reject',busy) }, '✗ Reject') : null,
      e('span', { key:'status', style:{
        marginLeft:'4px', border:'1px solid '+tone.border, borderRadius:'999px',
        background:tone.bg, color:tone.fg, padding:'3px 9px', fontWeight:700,
        textTransform:'uppercase', letterSpacing:'0.08em', fontSize:'9px',
        boxShadow:'0 0 0 1px rgba(255,255,255,0.8) inset'
      }}, tone.label)
    ]),

    /* Metadata pills */
    e('div', { key:'meta', style:{ display:'flex', gap:'4px', flexWrap:'wrap', marginBottom:'8px' }}, [
      pill('skill', st.skillName), pill('pc', st.pc), pill('line', st.stepLine),
      pill('src', 'L'+st.sourceLine), pill('depth', st.callDepth),
      pill('budget', st.budgetRemaining)
    ]),

    /* Body: two-column layout */
    e('div', { key:'body', style:{
      display:'grid', gridTemplateColumns: narrow ? '1fr' : 'minmax(0,1.6fr) minmax(260px,1fr)',
      gap:'10px'
    }}, [
      /* Left: Program listing */
      panel('Program', e('div', { key:'list' }, programSections), 'program'),

      /* Right: Inspector panels */
      e('div', { key:'side', style:{ display:'grid', gap:'8px', alignContent:'start' }}, [
        panel('Call Stack',
          stackRows.length === 0
            ? e('p', { style:{ margin:0, color:'#64748b', fontSize:'11px' }}, '(empty)')
            : e('ul', { style:{ margin:0, paddingLeft:'16px' }}, stackRows),
          'stack'),

        e('div', { key:'locals-res', style:{
          display:'grid', gap:'8px', gridTemplateColumns:'repeat(auto-fit,minmax(160px,1fr))'
        }}, [
          panel('Locals',
            st.bindings.length === 0
              ? e('p', { style:{ margin:0, color:'#64748b', fontSize:'11px' }}, '(empty)')
              : e('ul', { style:{ margin:0, paddingLeft:'16px' }}, mkBindings(st.bindings)),
            'locals'),
          panel('Resources',
            st.resourceBindings.length === 0
              ? e('p', { style:{ margin:0, color:'#64748b', fontSize:'11px' }}, '(empty)')
              : e('ul', { style:{ margin:0, paddingLeft:'16px' }}, mkBindings(st.resourceBindings)),
            'resources')
        ]),

        /* Tabbed Certior panels */
        e('div', { key:'certior-tabs' }, [ tabBar, certiorPanel ])
      ])
    ])
  ]);
}
"

end CertiorPlan
