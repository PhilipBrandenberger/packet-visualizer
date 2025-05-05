import tkinter as tk
from analyzer import packet_analyzer
from GUI import GUI

def on_close():
    root.quit()
    root.destroy()

if __name__ == "__main__":
    analyzer = packet_analyzer()
    root = tk.Tk()
    app = GUI(analyzer, root)
    app.root.protocol("WM_DELETE_WINDOW",on_close)
    app.root.mainloop() 
