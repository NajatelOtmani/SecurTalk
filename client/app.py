"""Point d'entrée du client SecureTalk AI.  Usage : python app.py --profile alice"""
import argparse, sys
from PySide6.QtWidgets import QApplication
from ui.theme import QSS
from ui.login_window import LoginWindow
from ui.main_window import MainWindow


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--profile", default="alice")
    args = p.parse_args()
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    state = {}

    def show_login(profile, notice=""):
        login = LoginWindow(profile)
        login.logged_in.connect(lambda client: go(client, login))
        if notice:
            login.error.setText(notice)
        login.show()
        state["login"] = login

    def go(client, login):
        main_win = MainWindow(client)
        main_win.session_expired.connect(on_expired)
        main_win.show()
        state["main"] = main_win
        login.close()

    def on_expired(username):
        old = state["main"]
        show_login(username, "Session expirée : reconnectez-vous.")  # d'abord la connexion, ensuite on ferme
        old.close()

    show_login(args.profile)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
