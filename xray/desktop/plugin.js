// Plugin X-Ray — Desktop page.
// Uncompiled ESM: no JSX syntax. Only @hermes/plugin-sdk, react, react/jsx-runtime resolve.
import {
  host, haptic, useQuery, useQueryClient, queryClient,
  ROUTES_AREA, SIDEBAR_NAV_AREA, STATUSBAR_AREAS,
  Button, Input, Badge, ScrollArea, EmptyState, Codicon, Separator, relativeTime,
} from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'
import { useState } from 'react'

const SOURCE = 'plugin:xray'
let CTX = null
const rest = (p, o) => CTX.rest(p, o)

const TONE = {
  RED:   { bg: 'var(--ui-danger, #e5484d)',  label: 'RED',   icon: 'shield' },
  AMBER: { bg: 'var(--ui-warning, #ffb224)', label: 'AMBER', icon: 'warning' },
  GREEN: { bg: 'var(--ui-success, #30a46c)', label: 'GREEN', icon: 'pass' },
}

function Pill(p) {
  const t = TONE[p.verdict] || TONE.AMBER
  return jsxs('span', {
    className: 'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[0.7rem] font-semibold',
    style: { background: t.bg, color: '#0b0b0b' },
    children: [jsx(Codicon, { name: t.icon }), t.label],
  })
}

function Bullets(p) {
  if (!p.items || !p.items.length) return null
  return jsx('ul', {
    className: 'mt-1 ml-1 space-y-0.5 text-[0.78rem] text-(--ui-text-secondary)',
    children: p.items.map((x, i) =>
      jsxs('li', { className: 'flex gap-1.5', children: [
        jsx('span', { style: { color: p.color || 'inherit' }, children: p.mark || '•' }),
        jsx('span', { children: x }),
      ] }, i)),
  })
}

function Card(p) {
  const r = p.row
  const [open, setOpen] = useState(r.verdict === 'RED')
  const baitLines = (r.bait_hits || []).map(b =>
    b.kind === 'read'
      ? `read ${b.bait} — ${b.where} [${b.warp_days ? '+' + b.warp_days + 'd' : 'day 0'}, ${b.phase}]`
      : `leak honeytoken → ${b.target} — ${b.where} [${b.warp_days ? '+' + b.warp_days + 'd' : 'day 0'}]`)
  const okLines = (r.sanctioned || []).map(x => x.note)
  return jsxs('div', {
    className: 'rounded-lg border border-(--ui-border) p-3',
    children: [
      jsxs('button', {
        type: 'button', onClick: () => { haptic('tap'); setOpen(!open) },
        className: 'flex w-full items-center gap-2 text-left',
        children: [
          jsx(Pill, { verdict: r.verdict }),
          jsx('span', { className: 'font-medium', children: r.plugin }),
          jsx('span', { className: 'font-mono text-[0.7rem] text-(--ui-text-tertiary)', children: (r.sha || '').slice(0, 12) }),
          r.warp_only && r.warp_only.length
            ? jsxs('span', { className: 'ml-1 text-[0.7rem] text-(--ui-warning)', children: [jsx(Codicon, { name: 'watch' }), ' time-bomb'] })
            : null,
          jsx('span', { className: 'ml-auto text-[0.7rem] text-(--ui-text-tertiary)', children: r.ts ? relativeTime(r.ts * 1000) : '' }),
          jsx(Codicon, { name: open ? 'chevron-up' : 'chevron-down' }),
        ],
      }),
      open ? jsxs('div', { className: 'mt-2', children: [
        jsx(Bullets, { items: r.reasons, mark: '⛔', color: TONE.RED.bg }),
        jsx(Bullets, { items: r.amber, mark: '⚠', color: TONE.AMBER.bg }),
        baitLines.length ? jsxs('div', { className: 'mt-2', children: [
          jsx('div', { className: 'text-[0.72rem] font-semibold text-(--ui-text-secondary)', children: 'Honeytoken trips (proof)' }),
          jsx(Bullets, { items: baitLines, color: TONE.RED.bg }),
        ] }) : null,
        okLines.length ? jsxs('div', { className: 'mt-2', children: [
          jsx('div', { className: 'text-[0.72rem] font-semibold text-(--ui-text-secondary)', children: 'Sanctioned credential use (OK)' }),
          jsx(Bullets, { items: okLines, mark: '✓', color: TONE.GREEN.bg }),
        ] }) : null,
        jsx(Separator, { className: 'my-2' }),
        jsxs('div', { className: 'text-[0.72rem] text-(--ui-text-tertiary)', children: [
          jsx('span', { className: 'font-semibold', children: 'Disclosure: ' }), r.disclosure,
        ] }),
      ] }) : null,
    ],
  })
}

function XRayPage() {
  const qc = useQueryClient()
  const [target, setTarget] = useState('')
  const verdicts = useQuery({
    queryKey: [SOURCE, 'verdicts'], queryFn: () => rest('/verdicts'), refetchInterval: 4000,
  })
  const alerts = useQuery({
    queryKey: [SOURCE, 'alerts'], queryFn: () => rest('/alerts'), refetchInterval: 6000,
  })
  const rows = (verdicts.data && verdicts.data.plugins) || []
  const running = (verdicts.data && verdicts.data.running) || []
  const alertRows = (alerts.data && alerts.data.alerts) || []
  const counts = rows.reduce((a, r) => (a[r.verdict] = (a[r.verdict] || 0) + 1, a), {})

  const detonate = async () => {
    const t = target.trim()
    if (!t) return
    haptic('tap')
    await rest('/detonate', { method: 'POST', body: { target: t } })
    setTarget('')
    qc.invalidateQueries({ queryKey: [SOURCE, 'verdicts'] })
  }

  return jsxs('div', { className: 'flex h-full flex-col', children: [
    jsxs('div', { className: 'flex items-center gap-2 border-b border-(--ui-border) p-3', children: [
      jsx(Codicon, { name: 'shield' }),
      jsx('span', { className: 'text-base font-semibold', children: 'Plugin X-Ray' }),
      jsx('span', { className: 'text-[0.75rem] text-(--ui-text-tertiary)', children: 'It doesn\u2019t watch plugins. It sets traps for them.' }),
      jsxs('div', { className: 'ml-auto flex items-center gap-1.5 text-[0.72rem]', children: [
        counts.RED ? jsx(Badge, { style: { background: TONE.RED.bg, color: '#000' }, children: counts.RED + ' RED' }) : null,
        counts.AMBER ? jsx(Badge, { style: { background: TONE.AMBER.bg, color: '#000' }, children: counts.AMBER + ' AMBER' }) : null,
        counts.GREEN ? jsx(Badge, { style: { background: TONE.GREEN.bg, color: '#000' }, children: counts.GREEN + ' GREEN' }) : null,
      ] }),
    ] }),
    jsxs('div', { className: 'flex items-center gap-2 p-3', children: [
      jsx(Input, {
        value: target, placeholder: 'plugin path, installed name, or owner/repo@sha',
        onChange: (e) => setTarget(e.target.value),
        onKeyDown: (e) => { if (e.key === 'Enter') detonate() },
        className: 'flex-1',
      }),
      jsxs(Button, { onClick: detonate, disabled: !target.trim(), children: [
        jsx(Codicon, { name: 'beaker' }), ' Detonate',
      ] }),
    ] }),
    running.length ? jsx('div', { className: 'px-3 pb-1 text-[0.72rem] text-(--ui-warning)', children: 'Detonating: ' + running.join(', ') }) : null,
    jsx(ScrollArea, { className: 'flex-1', children: jsxs('div', { className: 'space-y-2 p-3', children: [
      rows.length ? rows.map(r => jsx(Card, { row: r }, r.plugin))
        : jsx(EmptyState, { title: 'No detonations yet',
            description: 'Detonate a plugin above, or run `hermes xray detonate <plugin>`.' }),
      alertRows.length ? jsxs('div', { className: 'mt-4', children: [
        jsxs('div', { className: 'mb-1 text-[0.78rem] font-semibold', children: [jsx(Codicon, { name: 'bell' }), ' Runtime bait alerts'] }),
        jsx('div', { className: 'space-y-1', children: alertRows.map((a, i) =>
          jsxs('div', { className: 'flex items-center gap-2 rounded border border-(--ui-border) px-2 py-1 text-[0.74rem]', children: [
            jsx(Pill, { verdict: a.severity }),
            jsx('span', { className: 'font-medium', children: a.plugin }),
            jsx('span', { children: a.detail }),
            jsx('span', { className: 'ml-auto font-mono text-(--ui-text-tertiary)', children: a.location }),
          ] }, i)) }),
      ] }) : null,
    ] }) }),
  ] })
}

export default {
  id: 'xray',
  name: 'Plugin X-Ray',
  defaultEnabled: false,
  register(ctx) {
    CTX = ctx
    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: '/xray' }, render: () => jsx(XRayPage, {}) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: '/xray', label: 'Plugin X-Ray', codicon: 'shield' } },
      {
        id: 'chip', area: STATUSBAR_AREAS.right, order: 125,
        render: () => jsx('button', {
          type: 'button', className: 'px-1.5 text-[0.6875rem] text-(--ui-text-tertiary)',
          onClick: () => { haptic('tap'); host.navigate('/xray') },
          children: 'xray',
        }),
      },
    ])
    ctx.onEvent('plugin.xray.detonation.done', () =>
      queryClient.invalidateQueries({ queryKey: [SOURCE, 'verdicts'] }))
    ctx.onEvent('plugin.xray.detonation.failed', (ev) =>
      host.notifyError(new Error((ev && ev.payload && ev.payload.error) || 'unknown'), 'X-Ray detonation failed'))
  },
}
