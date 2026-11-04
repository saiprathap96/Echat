import { useEffect, useRef, useState } from 'react';
import axios from 'axios'; import { io } from 'socket.io-client';
import { Search, Send, Lock, ShieldCheck, ArrowLeft, LogOut } from 'lucide-react';
import { createIdentity, hasIdentity, encrypt, decrypt, safetyNumber } from './crypto/e2ee.js';

const API = import.meta.env.VITE_API_URL || (typeof window !== 'undefined' && !window.location.origin.includes('localhost') ? window.location.origin : 'http://localhost:4000');
const http = axios.create({ baseURL: API + '/api' });
const load = () => JSON.parse(localStorage.getItem('sc') || 'null');

export default function App() {
  const [session, setSession] = useState(load());
  const out = () => { localStorage.removeItem('sc'); setSession(null); };
  return session ? <Chat session={session} onLogout={out} /> : <AuthScreen onAuth={(s) => { localStorage.setItem('sc', JSON.stringify(s)); setSession(s); }} />;
}

function AuthScreen({ onAuth }) {
  const [mode, setMode] = useState('login'), [f, setF] = useState({}), [err, setErr] = useState('');
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const submit = async (e) => {
    e.preventDefault(); setErr('');
    try {
      if (mode === 'register') {
        if (f.password !== f.confirm) return setErr('Passwords do not match');
        const identityPublicKey = await createIdentity(f.username.toLowerCase());
        const { data } = await http.post('/auth/register', { name: f.name, username: f.username, email: f.email, password: f.password, identityPublicKey });
        onAuth(data);
      } else {
        const { data } = await http.post('/auth/login', { login: f.login, password: f.password });
        if (!(await hasIdentity(data.user.username))) return setErr('No encryption key on this device. Multi-device is not supported yet.');
        onAuth(data);
      }
    } catch (e) { setErr(e.response?.data?.error || 'Something went wrong'); }
  };
  const inp = 'w-full rounded-xl bg-zinc-900 px-4 py-3 outline-none focus:ring-2 ring-blue-500';
  return (
    <div className="min-h-screen grid place-items-center p-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-3">
        <h1 className="text-3xl font-bold flex items-center gap-2"><Lock className="text-blue-500" /> SecureChat</h1>
        {mode === 'register' ? <>
          <input className={inp} placeholder="Full name" onChange={set('name')} />
          <input className={inp} placeholder="Username" onChange={set('username')} />
          <input className={inp} placeholder="Email" type="email" onChange={set('email')} />
        </> : <input className={inp} placeholder="Email or username" onChange={set('login')} />}
        <input className={inp} placeholder="Password" type="password" onChange={set('password')} />
        {mode === 'register' && <input className={inp} placeholder="Confirm password" type="password" onChange={set('confirm')} />}
        {err && <p className="text-red-400 text-sm">{err}</p>}
        <button className="w-full rounded-xl bg-blue-500 py-3 font-semibold">{mode === 'login' ? 'Log in' : 'Create account'}</button>
        <button type="button" className="text-sm text-zinc-400" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>
          {mode === 'login' ? 'New here? Register' : 'Have an account? Log in'}</button>
      </form>
    </div>);
}

function Chat({ session, onLogout }) {
  const { token, user } = session, me = user.username;
  const [q, setQ] = useState(''), [results, setResults] = useState([]), [peer, setPeer] = useState(null);
  const [msgs, setMsgs] = useState([]), [text, setText] = useState(''), [onlineSet, setOnline] = useState(new Set());
  const [typing, setTyping] = useState(false), [safety, setSafety] = useState('');
  const sock = useRef(), peerRef = useRef(), bottom = useRef();
  const auth = { headers: { Authorization: 'Bearer ' + token } };
  peerRef.current = peer;

  const toView = async (m, p) => ({ id: m._id, mine: m.senderId === user.id, status: m.deliveryStatus, at: m.createdAt, text: await decrypt(me, p.identityPublicKey, m) });

  const loadUsers = () => {
    http.get('/users/search', { ...auth, params: { q } }).then((r) => setResults(r.data)).catch(() => {});
  };

  useEffect(() => {
    const s = io(API, { auth: { token } }); sock.current = s;
    s.on('online_list', (l) => setOnline(new Set(l)));
    s.on('user_status_changed', ({ userId, online }) => {
      setOnline((o) => { const n = new Set(o); online ? n.add(userId) : n.delete(userId); return n; });
      loadUsers();
    });
    s.on('receive_message', async (m) => {
      const p = peerRef.current; if (!p || m.senderId !== p.id) return;
      const view = await toView(m, p);
      setMsgs((x) => [...x, view]); s.emit('mark_delivered', { id: m._id }); s.emit('mark_read', { peerId: p.id });
    });
    s.on('message_read', ({ by }) => peerRef.current?.id === by && setMsgs((x) => x.map((m) => (m.mine ? { ...m, status: 'read' } : m))));
    s.on('user_typing', ({ userId }) => peerRef.current?.id === userId && setTyping(true));
    s.on('user_stopped_typing', () => setTyping(false));
    return () => s.disconnect();
  }, []);
  useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth' }); }, [msgs]);
  useEffect(() => {
    const t = setTimeout(() => {
      http.get('/users/search', { ...auth, params: { q } }).then((r) => setResults(r.data)).catch(() => {});
    }, 200);
    return () => clearTimeout(t);
  }, [q]);

  const open = async (p) => {
    setPeer(p); setMsgs([]);
    const { data } = await http.get('/messages/' + p.id, auth);
    setMsgs(await Promise.all(data.map((m) => toView(m, p))));
    sock.current.emit('mark_read', { peerId: p.id });
    const mine = (await http.get('/users/me', auth)).data.identityPublicKey;
    setSafety(await safetyNumber(mine, p.identityPublicKey));
  };
  const send = async (e) => {
    e.preventDefault(); const t = text.trim(); if (!t) return; setText('');
    const clientId = crypto.randomUUID();
    const payload = await encrypt(me, peer.identityPublicKey, t); // encrypted before leaving the device
    sock.current.emit('send_message', { to: peer.id, clientId, ...payload }, (r) => {
      if (r.ok) setMsgs((x) => [...x, { id: r.message._id, mine: true, status: 'sent', at: r.message.createdAt, text: t }]);
    });
    sock.current.emit('stop_typing', { to: peer.id });
  };
  const tick = { sent: '✓', delivered: '✓✓', read: '✓✓' };

  return (
    <div className="h-screen flex bg-black">
      <aside className={`${peer ? 'hidden md:flex' : 'flex'} w-full md:w-80 flex-col bg-zinc-950 border-r border-zinc-900`}>
        <div className="p-4 flex items-center justify-between"><h2 className="text-xl font-bold">Messages</h2>
          <button onClick={onLogout} title="Log out"><LogOut size={18} className="text-zinc-400" /></button></div>
        <div className="px-4 pb-3 relative"><Search size={16} className="absolute left-7 top-3 text-zinc-500" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find users by username" className="w-full rounded-xl bg-zinc-900 pl-9 pr-3 py-2 outline-none" /></div>
        <div className="flex-1 overflow-y-auto">
          {results.map((u) => (
            <button key={u.id} onClick={() => open(u)} className={`w-full px-4 py-3 flex items-center gap-3 hover:bg-zinc-900 text-left transition ${peer?.id === u.id ? 'bg-zinc-900 border-l-2 border-blue-500' : ''}`}>
              <div className="size-10 rounded-full bg-blue-500 grid place-items-center font-bold text-white shrink-0">{u.name[0]?.toUpperCase()}</div>
              <div className="flex-1 min-w-0">
                <div className="font-medium truncate">{u.name}</div>
                <div className="text-xs text-zinc-500 truncate">@{u.username}</div>
              </div>
              {onlineSet.has(u.id) && <span className="size-2.5 rounded-full bg-green-500 shrink-0" title="Online" />}
            </button>
          ))}
          {!results.length && (
            <div className="p-5 text-sm text-zinc-500 space-y-3">
              <p>No other users found.</p>
              <div className="rounded-xl bg-zinc-900/80 p-3 text-xs text-zinc-400 border border-zinc-800">
                <div className="font-semibold text-zinc-200 mb-1">🚀 How to test chatting:</div>
                <ol className="list-decimal list-inside space-y-1 text-zinc-400">
                  <li>Open an <strong>Incognito window</strong> (Ctrl+Shift+N)</li>
                  <li>Go to <span className="text-blue-400">localhost:5173</span></li>
                  <li>Click <strong>Register</strong> and create a second account</li>
                  <li>They will instantly appear here!</li>
                </ol>
              </div>
            </div>
          )}
        </div>
      </aside>
      <main className={`${peer ? 'flex' : 'hidden md:flex'} flex-1 flex-col min-w-0`}>
        {!peer ? <div className="m-auto text-zinc-500 flex flex-col items-center gap-2"><ShieldCheck size={40} />End-to-end encrypted</div> : <>
          <header className="p-4 flex items-center gap-3 border-b border-zinc-900">
            <button className="md:hidden" onClick={() => setPeer(null)}><ArrowLeft /></button>
            <div className="size-10 rounded-full bg-blue-500 grid place-items-center font-bold">{peer.name[0]}</div>
            <div className="flex-1"><div className="font-semibold">{peer.name}</div>
              <div className="text-xs text-zinc-400">{typing ? 'typing…' : onlineSet.has(peer.id) ? 'online' : 'offline'}</div></div>
            <div className="text-xs text-green-400 flex items-center gap-1"><Lock size={12} /> Encrypted</div>
          </header>
          <div className="px-4 py-1 text-[10px] text-zinc-600 truncate">Safety number (compare out-of-band): {safety}</div>
          <div className="flex-1 overflow-y-auto p-4 space-y-2">
            {msgs.map((m) => (
              <div key={m.id} className={`flex ${m.mine ? 'justify-end' : ''}`}>
                <div className={`max-w-[75%] rounded-2xl px-4 py-2 ${m.mine ? 'bg-blue-500' : 'bg-zinc-800'}`}>
                  <div className="break-words">{m.text}</div>
                  <div className="text-[10px] opacity-70 text-right">{new Date(m.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    {m.mine && <span className={m.status === 'read' ? ' text-cyan-300' : ''}> {tick[m.status]}</span>}</div>
                </div></div>))}
            <div ref={bottom} /></div>
          <form onSubmit={send} className="p-3 flex gap-2 border-t border-zinc-900">
            <input value={text} onChange={(e) => { setText(e.target.value); sock.current.emit('typing', { to: peer.id }); }}
              onBlur={() => sock.current.emit('stop_typing', { to: peer.id })} placeholder="Type your message"
              className="flex-1 rounded-full bg-zinc-900 px-5 py-3 outline-none" />
            <button className="size-12 rounded-full bg-blue-500 grid place-items-center"><Send size={18} /></button></form>
        </>}
      </main>
    </div>);
}
