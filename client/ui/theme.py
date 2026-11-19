C = dict(bg="#16203A", panel="#1B2742", card="#22304F", input="#1A2540", border="#33436A",
         text="#F1F5F9", muted="#9AA8C2", accent="#3B82F6", hover="#2F6FE0", cyan="#22D3EE",
         safe="#10B981", warn="#F59E0B", danger="#EF4444")
BADGE = {"Safe": C["safe"], "Suspicious": C["warn"], "Phishing": C["danger"], "Unscanned": C["muted"]}

_QSS = """
* { font-family: 'Inter','Segoe UI',sans-serif; font-size: 13px; color: @text; }
QWidget#root, QDialog, QMainWindow { background: @bg; }
QFrame#sidebar, QFrame#secpanel { background: @panel; border: none; }
QFrame#chathead, QFrame#composer { background: @panel; border: none; }
QFrame#card { background: @card; border: 1px solid @border; border-radius: 12px; }
QFrame#bubble_mine { background: @accent; border: 1px solid @accent; border-radius: 14px; border-bottom-right-radius: 4px; }
QFrame#bubble_other { background: @card; border: 1px solid @border; border-radius: 14px; border-bottom-left-radius: 4px; }
QFrame#brand { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #1D4ED8,stop:1 #0E7490); }
QLabel { background: transparent; }
QLabel#muted { color: @muted; font-size: 12px; }
QLabel#title { font-size: 22px; font-weight: 700; }
QLabel#h2 { font-size: 11px; font-weight: 700; color: @muted; letter-spacing: 1px; }
QLabel#avatar { background: @accent; border-radius: 18px; font-weight: 700; color: white; }
QLabel#chip { background: rgba(16,185,129,0.15); color: @safe; border-radius: 9px; padding: 3px 10px; font-size: 12px; font-weight: 600; }
QLabel#error { color: @danger; font-size: 12px; }
QLineEdit, QComboBox { background: @input; border: 1px solid @border; border-radius: 10px; padding: 9px 12px; }
QLineEdit:focus, QComboBox:focus { border: 1px solid @accent; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView { background: @card; border: 1px solid @border; selection-background-color: @accent; }
QPushButton { border-radius: 10px; padding: 9px 16px; font-weight: 600; }
QPushButton#primary { background: @accent; color: white; border: none; }
QPushButton#primary:hover { background: @hover; }
QPushButton#danger { background: @danger; color: white; border: none; }
QPushButton#danger:hover { background: #DC2626; }
QPushButton#ghost { background: transparent; border: 1px solid @border; }
QPushButton#ghost:hover { background: @card; }
QPushButton#link { background: transparent; border: none; color: @cyan; padding: 4px; }
QListWidget { background: transparent; border: none; outline: none; }
QListWidget::item { border-radius: 10px; margin: 2px 8px; }
QListWidget::item:hover { background: rgba(255,255,255,0.05); }
QListWidget::item:selected { background: @card; border: 1px solid @border; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: transparent; width: 8px; }
QScrollBar::handle:vertical { background: @border; border-radius: 4px; min-height: 30px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QProgressBar { background: @input; border: none; border-radius: 5px; height: 10px; text-align: center; color: transparent; }
QProgressBar::chunk { background: @danger; border-radius: 5px; }
"""
QSS = _QSS
for _k, _v in C.items():
    QSS = QSS.replace("@" + _k, _v)
