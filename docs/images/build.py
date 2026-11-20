#!/usr/bin/env python3
"""Draw every docs diagram, in English and Chinese, from this one script.

Run: python3 build.py
Needs only Python 3 and Google Chrome on macOS (headless screenshots); no pip packages.
English images go to docs/images/, Chinese ones to docs/images/zh/.
Sizes: the canvas is about 1100 wide; titles 24 px and subtitles 20 px, which show at
about 14 px and 12 px at the 60 % width the pages use. Arrows are at least 36 px long.
"""
import pathlib
import subprocess
from html import escape

HERE = pathlib.Path(__file__).parent
OUT, LANG = HERE, "en"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
FONT = "'PingFang SC','Hiragino Sans GB','Heiti SC',sans-serif"
T, S = 24, 20

COL = {
    "blue": ("#E8F0FE", "#3B6FD4"),
    "green": ("#E6F4EA", "#2E8B57"),
    "amber": ("#FEF3DC", "#C98A0C"),
    "red": ("#FCE8E6", "#C8453B"),
    "purple": ("#F1EAFB", "#7A52C7"),
    "gray": ("#F1F3F5", "#6B7480"),
    "white": ("#FFFFFF", "#AEB6BF"),
}
INK, MUTED = "#1F2933", "#52606D"

# Chinese text for every English string used below. A string missing here is drawn as is.
ZH = {
    # architecture tiles
    "People": "人员", "ask, approve, run": "发起、审批、运营",
    "Core API": "核心 API", "queues jobs, never signs": "只排队任务，从不签名",
    "Workflows": "工作流", "survive crashes": "崩溃后接着走",
    "Ledger": "账本", "double entry, Reconcile": "复式记账、对账",
    "Audit trail": "审计记录", "hash chains": "哈希链",
    "Signing zone": "签名区", "checks every job before any key signs": "每个任务先核对，密钥才签名",
    "Hot and cold": "冷热钱包", "limits, refills": "上下限、补充",
    "MPC parties A, B, C": "MPC 参与方 A、B、C", "key shares, each sealed in its own HSM token": "密钥份额，各封存在自己的 HSM 令牌里",
    "EVM": "EVM", "forwarders, nonces": "转发合约、nonce",
    "Bitcoin": "Bitcoin", "coins, change": "UTXO、找零",
    "Solana": "Solana", "durable nonces": "durable nonce",
    "queues sign jobs": "排队签名任务", "asks the parties to sign": "请参与方签名", "signed transactions": "签好的交易",
    # flow
    "Deposit": "充值", "pays in": "客户转入",
    "Credit": "入账", "when final": "确认后",
    "Sweep": "归集", "to hot": "到热钱包",
    "Withdraw": "提现", "approvals": "审批",
    "Sign": "签名", "MPC signs": "MPC 签名",
    "Settle": "结算", "books match": "账链一致",
    "Hot above its upper limit": "热钱包高于上限", "excess moves to cold automatically": "多出的部分自动转冷",
    "Hot below its lower limit": "热钱包低于下限", "refilled from cold by people": "由人从冷钱包补充",
    # identity
    "Person": "人", "logs in with a passkey": "用通行密钥登录",
    # api
    "Caller": "调用者", "a person or a service": "人或服务", "checks who, records it": "核对身份，记录请求",
    "Workflow": "工作流", "carries the work": "把事情办完", "Status": "状态", "the caller reads it later": "调用者稍后来查",
    "checks approvals and signs, apart from the API": "核对批准并签名，与 API 分开",
    "Identity provider": "身份提供方", "signs a token": "签发令牌",
    "checks role, login age": "核对角色和登录时间",
    "Audit": "审计", "who, how, when": "谁、怎么登录、何时",
    "Signing zone": "签名区", "still checks approver keys itself": "仍自己核对审批人密钥",
    # signing zone
    "Business side": "业务侧", "queues a job": "排队一个任务",
    "Gateway": "网关", "checks the job": "核对任务",
    "Cosigners B and C": "B、C 的协签程序", "check again, alone": "各自再核对一遍",
    "Key shares": "密钥份额", "sign together": "一起签名",
    "A check fails": "任何一项核对失败", "nothing is signed, the job says why": "不签名，任务写明原因",
    # ledger
    "Balance": "余额", "customer's coins": "客户的币",
    "Hold": "冻结", "set aside first": "先冻结",
    "Broadcast": "广播", "on its way": "在途",
    "Paid": "付款完成", "final on chain": "链上已确定",
    "Reconcile": "对账", "books and chain agree at every step": "每一步账和链都对得上",
    # workflows
    "Approve": "审批", "Build": "构造", "Confirm": "确认",
    "Worker dies": "worker 死掉", "at any step": "任何一步",
    "New worker": "新 worker", "resumes after the last step": "从上一个完成的步骤继续",
    "Watchdog": "看门狗", "restarts a stalled loop": "重启停滞的循环",
    # mpc
    "Party A": "参与方 A", "Party B": "参与方 B", "Party C": "参与方 C",
    "share sealed in HSM": "份额封存在 HSM",
    "Two-of-three key": "三选二密钥", "any two sign": "任意两方签名",
    "EVM and Solana hot wallets": "EVM、Solana 热钱包",
    "Two-party key tree": "两方密钥树", "A and B both needed": "A 和 B 缺一不可",
    "Bitcoin, Solana deposit addresses": "Bitcoin、Solana 充值地址",
    # tiers
    "Hot wallet": "热钱包", "signs all day": "整天签名", "Cold storage": "冷钱包", "key stays offline": "密钥离线",
    "above upper limit: moves automatically": "高于上限：自动转冷",
    "below lower limit: refilled by people": "低于下限：由人补充", "Air gap": "物理隔离", "M of N cold signers approve": "N 位签名人中 M 位批准",
    "refill file": "补充文件",
    # evm
    "Factory": "工厂合约", "owned by the cold key": "归冷密钥所有",
    "Forwarder": "转发合约", "deployed at sweep time": "归集时才部署",
    "Nonce": "nonce", "numbers each transaction": "给每笔交易编号",
    "Stuck": "卡住", "same nonce, higher fee": "同 nonce、更高手续费",
    "Reverted": "回滚", "release hold, book fee": "释放冻结、记手续费",
    "Used by a stranger": "被别人用掉", "parked with an alert": "挂起并报警",
    "Address fixed in advance. Every transaction gets a nonce:": "地址预先确定；每笔交易都有 nonce：", "gets the funds": "收到资金", "several addresses,": "多个地址，", "one transaction": "一笔交易",
    # bitcoin
    "Public key": "公钥", "derives each address": "推出每个地址",
    "Hot coins": "热钱包的币", "reserve what is needed": "预留够用的",
    "Payment": "付款", "and change back to hot": "找零回热钱包",
    "Stuck transaction": "交易卡住", "replace: same coins, higher fee": "替换：同样的币、更高手续费",
    "Many small coins": "很多小额币", "merge into one": "合并成一枚", "Consolidate": "合并",
    # solana
    "Address": "地址", "from public data": "来自公开数据",
    "Deposit": "充值", "read at finalized": "最终确认后读取",
    "Batched sweep": "批量归集", "several addresses, one transaction": "多个地址，一笔交易",
    "Nonce account": "nonce 账户", "withdrawal signs its value": "提现签它的值",
    "First version to land": "最先上链的版本", "uses it up; others are refused": "把它用掉，其余被拒绝",
    # new in the sweep
    "Identity": "身份", "login, roles": "登录、角色", "queues jobs only": "只排队任务",
    "Deposit": "充值", "credited when confirmed": "确认够了才入账",
    "Send": "发送", "keeps change for a higher fee": "找零里留着加价的余量",
    "Replace": "替换", "same coins, higher fee": "同样的币、更高手续费",
    "Child": "子交易", "pulls a stuck send in": "把卡住的交易拉上链",
    "Cancel": "取消", "coins go back to hot": "币花回热钱包",
    "Batch": "批量", "many withdrawals, one transaction": "多个提现，一笔交易",
    "Write-once storage": "一次写入存储", "an archiver copies every head": "归档程序复制每个链头",
    # audit
    "Core": "核心服务", "Cosigner": "协签程序", "entry": "记录",
    "Kafka": "Kafka", "heads published, so a cut chain stands out": "链头对外发布，截短的链一眼可见",
    # testing
    "Lane": "泳道", "own DB, chains, tokens": "自己的数据库、链、令牌",
    "Group": "测试组", "Every test ends with Reconcile": "每个测试都以对账收尾",
    "Lanes run at the same time": "几条泳道同时运行",
    # key replacement
    "New key": "新密钥", "made, signs nothing yet": "已生成，暂不签名",
    "Takes over": "接手", "new payments use it": "新的付款用它",
    "Old key drains": "旧密钥清空", "funds move to the new key": "资金转到新密钥",
    "Old key retired": "旧密钥退役", "its addresses stay watched": "它的地址继续监控",
    "Emergency": "紧急情况", "a stolen key may only move its funds to the new key": "被盗的密钥只能把资金转到新密钥",
    # deployment
    "Business": "业务", "core, worker, databases": "核心、worker、数据库",
    "Signing core": "签名核心", "gateway and party A": "网关和参与方 A",
    "Party B cluster": "参与方 B 集群", "party B and its cosigner": "参与方 B 和它的协签程序",
    "Party C cluster": "参与方 C 集群", "party C and its cosigner": "参与方 C 和它的协签程序",
    "Signing side": "签名侧", "only calls out, nothing pushes in": "只向外调用，没有东西能推进来",
    "Cold signer": "冷钱包签名机", "offline, never in a cluster": "离线，从不进集群",
    # enclaves
    "Party": "参与方", "starts in": "在飞地里", "an enclave": "启动",
    "Proof": "证明", "of the exact": "确切程序", "program": "的度量结果",
    "Broker": "密钥代理", "checks, then": "核对后", "releases the key": "才放出密钥",
    "Key in memory": "内存里的密钥", "opens the": "打开封存", "sealed shares": "的份额",
    "Simulated today": "目前是模拟", "no real enclave has run it yet": "还没有真正的飞地运行过",
    # services
    "Business side: holds no keys": "业务侧：不持有密钥", "Signing zone: the only part that can sign": "签名区：唯一能签名的部分",
    "Core": "核心服务", "API and ledger": "API 和账本",
    "Worker": "Worker", "runs payments": "把每笔付款办完",
    "Relay": "中继", "events to Kafka": "把事件发到 Kafka",
    "Archiver": "归档服务", "keeps audit heads": "保存审计链头",
    "Approval page": "审批页面", "approvers sign": "审批人在这里签名",
    "checks every job": "核对每个任务", "checks again, alone": "独立再核对一遍",
    "holds one key share": "持有一份密钥份额", "releases a party's key": "给参与方放出密钥",
    "The signing zone fetches its jobs": "签名区自己来取任务", "nothing can push one in": "没有东西能推进去",
}


class D:
    def __init__(self, name, w, h):
        self.name, self.w, self.h, self.o = name, w, h, []

    def box(self, x, y, w, h, title="", sub="", c="blue", size=T, dash=False, sub_size=None):
        f, s = COL[c]
        d = ' stroke-dasharray="8 6"' if dash else ""
        self.o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{f}" stroke="{s}" stroke-width="2"{d}/>')
        lines = sub.split("\n") if sub else []
        sz = sub_size or S
        total = (size if title else -8) + len(lines) * (sz + 8)
        ty = y + (h - total) / 2 + (size * 0.85 if title else -sz * 0.15 - 8)
        if title:
            self.text(x + w / 2, ty, title, size, INK, True)
        for i, l in enumerate(lines):
            self.text(x + w / 2, ty + (i + 1) * (sz + 8), l, sz, MUTED)

    def group(self, x, y, w, h, label, c="gray"):
        f, s = COL[c]
        self.o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="16" fill="{f}" fill-opacity="0.45" stroke="{s}" stroke-width="2"/>')
        self.text(x + 22, y + 34, label, T, INK, True, "start")

    def text(self, x, y, t, size=S, fill=INK, bold=False, anchor="middle"):
        if LANG == "zh":
            t = ZH.get(t, t)
        w = ' font-weight="600"' if bold else ""
        self.o.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" text-anchor="{anchor}"{w}>{escape(t)}</text>')

    def arrow(self, x1, y1, x2, y2, label="", c=MUTED, dash=False, both=False, lx=None, ly=None, anchor="middle"):
        d = ' stroke-dasharray="8 6"' if dash else ""
        st = ' marker-start="url(#hs)"' if both else ""
        self.o.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c}" stroke-width="2.5" marker-end="url(#h)"{st}{d}/>')
        if label:
            self.text(lx if lx is not None else (x1 + x2) / 2, ly if ly is not None else (y1 + y2) / 2 - 10, label, S, MUTED, False, anchor)

    def line(self, x1, y1, x2, y2):
        self.o.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{MUTED}" stroke-width="2.5"/>')

    def write(self):
        defs = (f'<defs><marker id="h" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
                f'<path d="M0 0L10 5L0 10z" fill="{MUTED}"/></marker>'
                f'<marker id="hs" viewBox="0 0 10 10" refX="1" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
                f'<path d="M10 0L0 5L10 10z" fill="{MUTED}"/></marker></defs>')
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}" '
               f'font-family="{FONT}"><rect width="100%" height="100%" fill="#FFFFFF"/>{defs}{"".join(self.o)}</svg>')
        OUT.mkdir(parents=True, exist_ok=True)
        html = OUT / f".{self.name}.html"
        html.write_text(f'<!doctype html><meta charset="utf-8"><style>html,body{{margin:0;background:#fff}}</style>{svg}', encoding="utf-8")
        subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
                        f"--window-size={self.w},{self.h}", f"--screenshot={OUT / (self.name + '.png')}", html.as_uri()],
                       check=True, capture_output=True, timeout=60)
        html.unlink()


def row(d, items, y=20, h=92, x0=30, total=1080, gap=44, size=23, arrows=True):
    """A row of boxes joined by arrows. Returns the box centres."""
    n = len(items)
    w = (total - gap * (n - 1)) / n
    xs = []
    for i, (t, s, c) in enumerate(items):
        x = x0 + i * (w + gap)
        d.box(x, y, w, h, t, s, c, size=size)
        if i and arrows:
            d.arrow(x - gap, y + h / 2, x, y + h / 2)
        xs.append(x + w / 2)
    return xs


def cards(d, items, y, h=92, x0=30, total=1080, gap=20, size=23):
    n = len(items)
    w = (total - gap * (n - 1)) / n
    xs = []
    for i, (t, s, c) in enumerate(items):
        x = x0 + i * (w + gap)
        d.box(x, y, w, h, t, s, c, size=size)
        xs.append(x + w / 2)
    return xs


# ---- README ---------------------------------------------------------------

def flow():
    d = D("flow", 1140, 280)
    row(d, [("Deposit", "pays in", "white"), ("Credit", "when final", "purple"), ("Sweep", "to hot", "amber"),
            ("Withdraw", "approvals", "blue"), ("Sign", "MPC signs", "green"), ("Settle", "books match", "purple")],
        y=20, h=92, gap=36, size=22)
    cards(d, [("Hot above its upper limit", "excess moves to cold automatically", "amber"),
              ("Hot below its lower limit", "refilled from cold by people", "gray")], 160, h=96, gap=40)
    d.write()


def architecture():
    """The README shows this as a grid of tiles so that each box can be a link."""
    H, cols = 78, (190, 570, 950)

    def tile(name, w, h, title, sub, c, left=19, right=19):
        d = D(f"arch-{name}", w, h)
        d.box(left, 2, w - left - right, h - 4, title, sub, c, size=26, sub_size=21)
        return d

    tile("operators", 380, H, "People", "ask, approve, run", "gray").write()

    d = D("arch-a", 380, 58)  # operators to identity
    d.arrow(190, 2, 190, 56)
    d.write()
    tile("identity", 380, H, "Identity", "login, roles", "purple").write()
    d = D("arch-b", 380, 58)  # identity to the API
    d.arrow(190, 2, 190, 56)
    d.write()
    tile("api", 380, H, "Core API", "queues jobs only", "blue").write()

    d = D("arch-down", 1140, 58)  # from the API (centre) to three boxes
    d.line(570, 2, 570, 28)
    d.line(cols[0], 28, cols[2], 28)
    for x in cols:
        d.arrow(x, 28, x, 56)
    d.write()

    tile("workflows", 380, H, "Workflows", "survive crashes", "amber").write()
    tile("ledger", 380, H, "Ledger", "double entry, Reconcile", "amber").write()
    tile("audit", 380, H, "Audit trail", "hash chains", "purple").write()

    d = D("arch-merge", 1140, 58)  # from the row above into hot and cold
    d.arrow(cols[1], 2, cols[1], 56)
    d.write()

    tile("tiers", 380, H, "Hot and cold", "limits, refills", "blue").write()

    d = D("arch-merge2", 1140, 58)
    d.arrow(cols[1], 2, cols[1], 56, "queues sign jobs", lx=cols[1] + 14, ly=36, anchor="start")
    d.write()

    tile("zone", 760, H, "Signing zone", "checks every job before any key signs", "green").write()

    d = D("arch-down2", 1140, 58)
    d.arrow(cols[1], 2, cols[1], 56, "asks the parties to sign", lx=cols[1] + 14, ly=36, anchor="start")
    d.write()

    tile("mpc", 1140, H, "MPC parties A, B, C", "key shares, each sealed in its own HSM token", "green", right=19).write()

    d = D("arch-split", 1140, 58)
    d.line(570, 2, 570, 28)
    d.line(cols[0], 28, cols[2], 28)
    for x in cols:
        d.arrow(x, 28, x, 56)
    d.text(780, 16, "signed transactions", S, MUTED, anchor="start")
    d.write()

    tile("evm", 380, H, "EVM", "forwarders, nonces", "white").write()
    tile("bitcoin", 380, H, "Bitcoin", "coins, change", "white").write()
    tile("solana", 380, H, "Solana", "durable nonces", "white").write()


# ---- concept pages --------------------------------------------------------

def signing_zone():
    d = D("signing-zone", 1140, 262)
    row(d, [("Business side", "queues a job", "gray"), ("Gateway", "checks the job", "amber"),
            ("Cosigners B and C", "check again, alone", "amber"), ("Key shares", "sign together", "green")],
        y=20, h=100, gap=44, size=23)
    d.box(30, 160, 1080, 76, "A check fails", "nothing is signed, the job says why", "red")
    d.write()


def ledger():
    d = D("ledger", 1140, 262)
    row(d, [("Balance", "customer's coins", "purple"), ("Hold", "set aside first", "amber"),
            ("Broadcast", "on its way", "amber"), ("Paid", "final on chain", "green")], y=20, h=100, gap=44, size=23)
    d.box(30, 160, 1080, 76, "Reconcile", "books and chain agree at every step", "blue")
    d.write()


def workflows():
    d = D("workflows", 1140, 292)
    xs = row(d, [("Approve", "", "blue"), ("Build", "", "blue"), ("Sign", "", "green"),
                 ("Broadcast", "", "amber"), ("Confirm", "", "amber"), ("Settle", "", "purple")], y=20, h=70, gap=36, size=23)
    d.box(30, 150, 280, 92, "Worker dies", "at any step", "red")
    d.box(350, 150, 360, 92, "New worker", "resumes after the last step", "green")
    d.box(750, 150, 360, 92, "Watchdog", "restarts a stalled loop", "gray")
    d.arrow(310, 196, 350, 196)
    d.write()


def mpc():
    d = D("mpc", 1140, 330)
    cards(d, [("Party A", "share sealed in HSM", "blue"), ("Party B", "share sealed in HSM", "blue"), ("Party C", "share sealed in HSM", "blue")],
          y=20, h=92, gap=40)
    d.box(30, 160, 520, 120, "Two-of-three key", "any two sign\nEVM and Solana hot wallets", "green")
    d.box(590, 160, 520, 120, "Two-party key tree", "A and B both needed\nBitcoin, Solana deposit addresses", "amber")
    d.write()


def tiers():
    d = D("tiers", 1140, 300)
    d.box(30, 40, 290, 120, "Hot wallet", "signs all day", "amber")
    d.box(820, 40, 290, 120, "Cold storage", "key stays offline", "blue")
    d.arrow(320, 70, 820, 70, "above upper limit: moves automatically", ly=58)
    d.arrow(820, 130, 320, 130, "below lower limit: refilled by people", ly=122)
    d.box(430, 190, 280, 80, "Air gap", "M of N cold signers approve", "gray", size=22)
    d.arrow(570, 190, 570, 138, "", dash=True)
    d.write()


def evm():
    d = D("evm", 1140, 312)
    row(d, [("Factory", "owned by the cold key", "blue"), ("Forwarder", "deployed at sweep time", "gray"),
            ("Hot wallet", "gets the funds", "green")], y=20, h=92, gap=60, total=1080)
    d.text(570, 152, "Address fixed in advance. Every transaction gets a nonce:", T, INK, True)
    cards(d, [("Stuck", "same nonce, higher fee", "amber"), ("Reverted", "release hold, book fee", "gray"),
              ("Used by a stranger", "parked with an alert", "red")], 172, h=100)
    d.write()


def bitcoin():
    d = D("bitcoin", 1140, 312)
    row(d, [("Public key", "derives each address", "blue"), ("Hot coins", "reserve what is needed", "amber"),
            ("Payment", "and change back to hot", "green")], y=20, h=92, gap=60, total=1080)
    cards(d, [("Deposit", "credited when confirmed", "purple"), ("Many small coins", "merge into one", "gray")],
          y=170, h=100, gap=40)
    d.write()


def bitcoin_sending():
    d = D("bitcoin-sending", 1140, 312)
    row(d, [("Send", "keeps change for a higher fee", "amber"), ("Replace", "same coins, higher fee", "amber"),
            ("Child", "pulls a stuck send in", "green")], y=20, h=92, gap=60, total=1080)
    cards(d, [("Cancel", "coins go back to hot", "gray"), ("Batch", "many withdrawals, one transaction", "blue")],
          y=170, h=100, gap=40)
    d.write()


def solana():
    d = D("solana", 1140, 330)
    row(d, [("Address", "from public data", "blue"), ("Deposit", "read at finalized", "purple"),
            ("Batched sweep", "several addresses,\none transaction", "amber"), ("Hot wallet", "", "green")], y=20, h=100, gap=44, size=23)
    d.box(30, 180, 480, 100, "Nonce account", "withdrawal signs its value", "gray")
    d.box(630, 180, 480, 100, "First version to land", "uses it up; others are refused", "green")
    d.arrow(510, 230, 630, 230)
    d.write()


def identity():
    d = D("identity", 1140, 262)
    row(d, [("Person", "logs in with a passkey", "blue"), ("Identity provider", "signs a token", "amber"),
            ("Core API", "checks role, login age", "green"), ("Audit", "who, how, when", "gray")],
        y=20, h=100, gap=44, size=23)
    d.box(30, 160, 1080, 76, "Signing zone", "still checks approver keys itself", "purple")
    d.write()


def api():
    d = D("api", 1140, 262)
    row(d, [("Caller", "a person or a service", "blue"), ("Core API", "checks who, records it", "green"),
            ("Workflow", "carries the work", "amber"), ("Status", "the caller reads it later", "gray")],
        y=20, h=100, gap=44, size=23)
    d.box(30, 160, 1080, 76, "Signing zone", "checks approvals and signs, apart from the API", "purple")
    d.write()


def audit():
    d = D("audit", 1140, 330)
    gx = [30, 410, 790]
    for x, name in zip(gx, ("Core", "Gateway", "Cosigner")):
        d.group(x, 20, 320, 150, name, "gray")
        bw, gap = 70, 36
        for i in range(3):
            bx = x + 24 + i * (bw + gap)
            d.box(bx, 84, bw, 64, "", "entry", "white", sub_size=18)
            if i:
                d.arrow(bx - gap, 116, bx, 116)
    for x in gx:
        d.line(x + 160, 170, x + 160, 206)
    d.line(190, 206, 950, 206)
    d.arrow(290, 206, 290, 232)
    d.arrow(850, 206, 850, 232)
    d.box(30, 232, 520, 76, "Kafka", "heads published, so a cut chain stands out", "purple")
    d.box(590, 232, 520, 76, "Write-once storage", "an archiver copies every head", "green")
    d.write()


def testing():
    d = D("testing", 1140, 330)
    y = 20
    for i in range(3):
        d.box(30, y, 300, 84, "Lane", "own DB, chains, tokens", "blue", size=22, sub_size=19)
        row(d, [("Group", "", "white"), ("Group", "", "white"), ("Reconcile", "", "green")], y=y, h=84, x0=380, total=730, gap=40, size=21)
        y += 100
    d.write()


def key_replacement():
    d = D("key-replacement", 1140, 262)
    row(d, [("New key", "made, signs nothing yet", "gray"), ("Takes over", "new payments use it", "green"),
            ("Old key drains", "funds move to the new key", "amber"), ("Old key retired", "its addresses stay watched", "gray")],
        y=20, h=100, gap=44, size=23)
    d.box(30, 160, 1080, 76, "Emergency", "a stolen key may only move its funds to the new key", "red")
    d.write()


def deployment():
    d = D("deployment", 1140, 272)
    cards(d, [("Business", "core, worker, databases", "gray"), ("Signing core", "gateway and party A", "green"),
              ("Party B cluster", "party B and its cosigner", "green"), ("Party C cluster", "party C and its cosigner", "green")],
          y=20, h=100, gap=24, size=22)
    d.box(30, 160, 520, 80, "Signing side", "only calls out, nothing pushes in", "amber")
    d.box(590, 160, 520, 80, "Cold signer", "offline, never in a cluster", "gray")
    d.write()


def enclaves():
    d = D("enclaves", 1140, 262)
    row(d, [("Party", "starts in\nan enclave", "blue"), ("Proof", "of the exact\nprogram", "amber"),
            ("Broker", "checks, then\nreleases the key", "green"), ("Key in memory", "opens the\nsealed shares", "purple")],
        y=20, h=100, gap=44, size=23)
    d.box(30, 160, 1080, 76, "Simulated today", "no real enclave has run it yet", "red")
    d.write()


def services():
    d = D("services", 1140, 452)
    d.group(30, 20, 1080, 168, "Business side: holds no keys", "gray")
    cards(d, [("Core", "API and ledger", "white"), ("Worker", "runs payments", "white"), ("Relay", "events to Kafka", "white"),
              ("Archiver", "keeps audit heads", "white"), ("Approval page", "approvers sign", "white")],
          y=76, h=92, x0=50, total=1040, gap=14, size=21)
    d.box(250, 206, 640, 60, "The signing zone fetches its jobs", "nothing can push one in", "amber", size=21)
    d.group(30, 284, 1080, 148, "Signing zone: the only part that can sign", "green")
    cards(d, [("Gateway", "checks every job", "white"), ("Cosigner", "checks again, alone", "white"),
              ("Party", "holds one key share", "white"), ("Broker", "releases a party's key", "white")],
          y=336, h=80, x0=50, total=1040, gap=18, size=21)
    d.write()


def build_all():
    for f in (services, deployment, enclaves, key_replacement, flow, architecture, signing_zone, ledger, workflows, mpc, tiers, evm, bitcoin, bitcoin_sending, solana, identity, api, audit, testing):
        f()


for OUT, LANG in ((HERE, "en"), (HERE / "zh", "zh")):
    build_all()
print("ok")
