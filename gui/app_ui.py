import tkinter as tk
from tkinter import scrolledtext, messagebox
from scanner.nmap_scanner import scan_target_and_generate_report

def start_gui():
    def start_scan():
        ip = ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Missing Input", "Please enter a target IP address.")
            return
        output_text.delete(1.0, tk.END)
        try:
            result, report_path = scan_target_and_generate_report(ip)
            output_text.insert(tk.END, result)
            messagebox.showinfo("Scan Complete", f"Report saved to: {report_path}")
        except Exception as e:
            output_text.insert(tk.END, f"[Error] {str(e)}")

    # GUI Layout
    root = tk.Tk()
    root.title("Ethical Hacking Toolkit - Network Scanner")
    root.geometry("800x600")

    tk.Label(root, text="Target IP / Host:").pack(pady=5)
    ip_entry = tk.Entry(root, width=50)
    ip_entry.pack(pady=5)

    tk.Button(root, text="Start Scan", command=start_scan, bg="#4CAF50", fg="white").pack(pady=5)

    output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=30)
    output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    root.mainloop()
