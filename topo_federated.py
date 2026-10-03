#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_topology():
    # Menggunakan OVS Switch dengan OpenFlow 1.3 sesuai spesifikasi paper
    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')

    print("*** Menambahkan Kontroler Jaringan Standar (Mencegah Error Port 5000) ***")
    # PERBAIKAN: Menggunakan Controller bawaan lokal agar port 5000 aman dari OpenFlow
    c0 = net.addController(name='c0', controller=Controller)

    print("*** Menambahkan OVS Switch ***")
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')

    print("*** Menambahkan 4 Hosts untuk Federated Agents (Sinkronisasi dengan Backend) ***")
    # PERBAIKAN: Menambahkan h4 agar total menjadi 4 client seperti di backend server
    h1 = net.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4', mac='00:00:00:00:00:04')

    print("*** Menghubungkan Link ***")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    print("*** Memulai Jaringan ***")
    net.start()

    print("*** Menjalankan 4 Local Firewall Agents pada Host ***")
    # PERBAIKAN: Jalankan agen di keempat host menggunakan path venv absolut danielagra
    path_ke_venv = "/home/danielagra/Federated-Firewall/riset_firewall/venv"
    
    h1.cmd(f'{path_ke_venv}/bin/python3 local_agent.py --host h1 --ip 10.0.0.1 > h1_agent.log 2>&1 &')
    h2.cmd(f'{path_ke_venv}/bin/python3 local_agent.py --host h2 --ip 10.0.0.2 > h2_agent.log 2>&1 &')
    h3.cmd(f'{path_ke_venv}/bin/python3 local_agent.py --host h3 --ip 10.0.0.3 > h3_agent.log 2>&1 &')
    h4.cmd(f'{path_ke_venv}/bin/python3 local_agent.py --host h4 --ip 10.0.0.4 > h4_agent.log 2>&1 &')

    print("*** Jaringan Siap. Ketik 'exit' di CLI Mininet jika ingin menyudahi simulasi. ***")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
