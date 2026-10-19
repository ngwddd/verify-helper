/**
 * 验证助手 · 输入框工具栏按钮（浏览器半边）。
 *
 *   单击        → 填入「快速检查」请求
 *   Shift+单击  → 填入「完整检查」请求（含测试与浏览器层）
 *   双击        → 撤销刚才的填入，恢复点击前的草稿
 *
 * 为什么是「填进输入框」而不是直接执行：
 *   Client 侧拿不到 agent 的工具执行权，真正跑验证的是 Host 上的 MCP 工具。
 *   把请求写进输入框，用户看得见要跑什么、也随时能改，比黑盒按钮诚实。
 *
 * 为什么单击要延迟 260ms 才动手：
 *   双击会先触发一次 click。延迟一点点，等第二个 click 到了就当作双击撤销，
 *   不会出现「双击 = 填一次 + 再撤销」的闪烁。
 */
window.__ModuleLoader__.load({
  id: '@local/verify-helper-button',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    const CSS = [
      '.vhb-btn{appearance:none;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;',
      'width:30px;height:30px;padding:0;border:1px solid transparent;border-radius:8px;background:transparent;',
      'color:var(--dsw-alias-label-secondary);transition:color .12s,border-color .12s,background .12s,transform .08s}',
      '.vhb-btn:hover:not(:disabled){color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-layer-2)}',
      '.vhb-btn:active:not(:disabled){transform:scale(.92)}',
      '.vhb-btn:disabled{opacity:.4;cursor:not-allowed}',
      '.vhb-ok{color:var(--dsw-alias-state-success-primary)!important}',
      '.vhb-warn{color:var(--dsw-alias-state-warn-primary)!important}',
      '.vhb-wrap{position:relative;display:inline-flex;align-items:center}',
      '.vhb-tip{position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);z-index:40;',
      'white-space:nowrap;padding:4px 8px;border:1px solid var(--dsw-alias-border-l1);border-radius:6px;',
      'background:var(--dsw-alias-bg-overlay);color:var(--dsw-alias-label-primary);font-size:11px;line-height:1.4;',
      'box-shadow:0 4px 14px rgba(0,0,0,.2);pointer-events:none}',
    ].join('');

    const TAG_ID = '@local/verify-helper-button/style.css';

    function ensureStyle() {
      if (typeof document === 'undefined') return;
      if (document.querySelector('style[data-plugin-css=' + JSON.stringify(TAG_ID) + ']')) return;
      const tag = document.createElement('style');
      tag.dataset.plugin = '@local/verify-helper-button';
      tag.dataset.pluginCss = TAG_ID;
      tag.textContent = CSS;
      document.head.appendChild(tag);
    }

    const PROMPT_FAST =
      '用验证助手检查当前项目（MCP 工具 verify_start，path 用当前工作目录，fast=true）。' +
      '把 PASS/FAIL/UNKNOWN、失败项和风险等级列给我；有 FAIL 就给出最小修复清单，别只说「有问题」。';

    const PROMPT_FULL =
      '用验证助手完整检查当前项目（MCP 工具 verify_start，path 用当前工作目录，不加 fast）。' +
      '重点看 browser 检查有没有抓到 JS 报错，然后按风险等级从高到低列结论和修复清单。';

    const TITLE = '验证助手：点击=快速检查 · Shift+点击=完整检查 · 双击=撤销';

    function Icon() {
      return h('svg', {
        viewBox: '0 0 24 24', width: 16, height: 16, fill: 'none',
        stroke: 'currentColor', strokeWidth: 2, strokeLinecap: 'round',
        strokeLinejoin: 'round', 'aria-hidden': 'true', focusable: 'false',
      },
        h('path', { d: 'M12 3l7 3v6c0 4.2-2.9 7.6-7 9-4.1-1.4-7-4.8-7-9V6l7-3z' }),
        h('path', { d: 'M9 12l2.2 2.2L15.5 10' }));
    }

    function VerifyButton(props) {
      // 这个 slot 一定给 inputActions；useInput 用来读当前草稿，读不到就退化成 null。
      const actions = props.inputActions;
      const useInput = typeof props.useInput === 'function'
        ? props.useInput
        : function () { return undefined; };
      const draft = useInput(function (s) { return s ? s.draft : undefined; });

      const draftRef = React.useRef(draft);
      const prevRef = React.useRef(null);       // 点击前的草稿
      const insertedRef = React.useRef(null);   // 我们填进去的那段
      const pendingRef = React.useRef(null);    // 等待第二击的定时器
      const timerRef = React.useRef(null);
      const [mark, setMark] = React.useState('');   // '' | 'ok' | 'warn'
      const [tip, setTip] = React.useState(null);

      draftRef.current = draft;

      React.useEffect(function () {
        return function () {
          if (pendingRef.current) clearTimeout(pendingRef.current);
          if (timerRef.current) clearTimeout(timerRef.current);
        };
      }, []);

      function flash(kind, text) {
        setMark(kind);
        setTip(text);
        if (timerRef.current) clearTimeout(timerRef.current);
        timerRef.current = setTimeout(function () {
          setMark('');
          setTip(null);
        }, 1800);
      }

      function insert(full) {
        if (!actions) return;
        prevRef.current = draftRef.current || '';
        const text = full ? PROMPT_FULL : PROMPT_FAST;
        insertedRef.current = text;
        actions.setDraft(text);
        if (typeof actions.focus === 'function') actions.focus();
        flash('ok', full ? '已填入：完整检查' : '已填入：快速检查');
      }

      function undo() {
        if (!actions) return;
        const mine = insertedRef.current;
        if (!mine) {
          flash('warn', '没有可撤销的填入');
          return;
        }
        if (draftRef.current !== mine) {
          // 用户已经改过内容 —— 宁可不动，也不能把人写的字冲掉
          flash('warn', '输入框已改动，未撤销');
          return;
        }
        actions.setDraft(prevRef.current || '');
        insertedRef.current = null;
        flash('ok', '已撤销');
      }

      function onClick(e) {
        if (!actions) return;
        const full = !!(e && (e.shiftKey || e.altKey));

        // 第二击落在 260ms 内 = 双击 → 撤销
        if (pendingRef.current) {
          clearTimeout(pendingRef.current);
          pendingRef.current = null;
          undo();
          return;
        }
        pendingRef.current = setTimeout(function () {
          pendingRef.current = null;
          insert(full);
        }, 260);
      }

      return h('div', { className: 'vhb-wrap' },
        tip ? h('div', { className: 'vhb-tip', role: 'status' }, tip) : null,
        h('button', {
          type: 'button',
          className: 'vhb-btn' + (mark === 'ok' ? ' vhb-ok' : mark === 'warn' ? ' vhb-warn' : ''),
          disabled: !actions,
          onClick: onClick,
          title: TITLE,
          'aria-label': '用验证助手检查当前项目（双击撤销）',
        }, h(Icon)));
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ensureStyle();
        ctx.slots.inject('conversation.input.left', () => ctx.slots.register(
          { name: 'conversation.input.left', id: 'verify-helper-button', order: 60, label: '验证助手' },
          VerifyButton,
        ));
      },
    };
  },
});
