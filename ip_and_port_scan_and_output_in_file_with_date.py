import tkinter as tk
import socket
import threading
import datetime
from functools import partial

def scan(ip, ports, results):
    now = datetime.datetime.now()
    date_string = now.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open("output.txt", "a") as f:
            f.write(f"Scan results for {ip} ({date_string}):\n")
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    msg = f"{ip}:{port} - Open\n"
                    results.insert(tk.END, msg)
                    f.write(msg)
                else:
                    msg = f"{ip}:{port} - Closed\n"
                    results.insert(tk.END, msg)
                    f.write(msg)
                sock.close()
    except:
        pass


def scan_all(entries, results):
    # Get the IP addresses and ports from the input fields
    ips = [entry[0].get() for entry in entries]
    ports = [[] for i in range(len(entries))]
    for i, entry in enumerate(entries):
        port = entry[1].get()
        if port:
            for p in port.split(','):
                ports[i].append(int(p.strip()))

    # Scan all IP addresses and ports in the list
    for i, ip in enumerate(ips):
        scan_ip_port = partial(scan, ip, ports[i], results)
        scan_ip_port()


def start_scan(entries, results):
    # Remove any existing entries from the results Listbox
    results.delete(0, tk.END)

    # Scan all IP addresses and ports provided in the input fields
    scan_all(entries, results)

def add_entry_field(window, entries):
    # IP Address Entry
    ip_entry = tk.Entry(window)
    ip_entry.grid(row=len(entries), column=0)
    ip_entry.insert(tk.END, "127.0.0.1")

    # Port Entry
    port_entry = tk.Entry(window)
    port_entry.grid(row=len(entries), column=1)
    port_entry.insert(tk.END, "")

    entries.append((ip_entry, port_entry))

def remove_entry_field(window, entries, index):
    # Remove the entry field from the window and the entries list
    entry = entries.pop(index)
    entry[0].grid_forget()
    entry[1].grid_forget()

    # Shift the remaining entry fields up one row
    for i in range(index, len(entries)):
        entries[i][0].grid(row=i, column=0)
        entries[i][1].grid(row=i, column=1)

def modify_entry_field(window, entries, index, ip="", ports=""):
    # Modify the IP and Port fields of the specified entry
    entries[index][0].delete(0, tk.END)
    entries[index][0].insert(0, ip)
    entries[index][1].delete(0, tk.END)
    entries[index][1].insert(0, ports)

def create_entry_fields(window, num_fields):
    entries = []
    for i in range(num_fields):
        add_entry_field(window, entries)

    return entries

def create_results_field(window, row):
    results = tk.Listbox(window, height=10, width=50)
    results.grid(row=row, column=0, columnspan=2)
    return results

def create_scan_button(window, entries, results):
    scan_button = tk.Button(window, text="Scan", command=lambda: start_scan(entries, results))
    scan_button.grid(row=len(entries)+1, column=1)

def create_add_button(window, entries):
    add_button = tk.Button(window, text="Add", command=lambda: add_entry_field(window, entries))
    add_button.grid(row=len(entries)+1, column=0)

def create_remove_button(window, entries, index):
    remove_button = tk.Button(window, text="Remove", command=lambda: remove_entry_field(window, entries, index))
    remove_button.grid(row=index, column=2)
    return remove_button

def create_modify_button(window, entries, index):
    modify_button = tk.Button(window, text="Modify", command=lambda: modify_entry_field(window, entries, index))
    modify_button.grid(row=index, column=3)
    return modify_button

def create_entry_buttons(window, entries):
    for i, entry in enumerate(entries):
        remove_button = create_remove_button(window, entries, i)
        modify_button = create_modify_button(window, entries, i)

def main():
    window = tk.Tk()
    window.title("Port Scanner")

    # Create the entry fields for IP addresses and port numbers
    entries = create_entry_fields(window, 2)

    # Create the Listbox for displaying scan results
    results = create_results_field(window, len(entries)+2)

    # Create buttons for scanning, adding, removing, and modifying entry fields
    create_scan_button(window, entries, results)
    create_add_button(window, entries)
    create_entry_buttons(window, entries)

    window.mainloop()

if __name__ == "__main__":
    main()

