from queue import Queue
from scapy.all import sniff

class Sniffer(object):
	"""Sniffe le réseau sur une interface spécifiée et place les paquets dans une FILE"""
	def __init__(self, iface:str, sfilter:str, queue:Queue, stop_event=None):
		self.iface = iface
		self.sfilter = sfilter
		self.queue = queue
		self.stop_event = stop_event
		self.packet_lost = 0

	def send_to_queue(self, pkt):
		try:
			self.queue.put_nowait(pkt)
			print(f"[SNIFFER DEBUG] Packet captured: {pkt.summary()}")
		except Exception:
			self.packet_lost += 1

	def afficher_trafic(self):
		while True:
			try:
				pkt = self.queue.get()
				self.queue.task_done()
				pkt.show()
			except KeyboardInterrupt:
				print("\n[!] Arrêt !!!")
				break

	def start_sniffer(self):
		print(f"[SNIFFER] Starting on interface '{self.iface}' with filter '{self.sfilter}'")
		
		kwargs = {}
		# Patch pour capture localhost (lo)
		if self.iface == "lo":
			try:
				from scapy.config import conf
				kwargs['L2socket'] = conf.L3socket
				print(f"[SNIFFER] Loopback mode enabled (L3socket={conf.L3socket.__name__})")
			except Exception as e:
				print(f"[SNIFFER] Warning: Setup loopback/L3socket failed: {e}")

		# 1. Mode legacy (si pas de stop_event) -> Bloquant (pour compatibilité)
		if not self.stop_event:
			try:
				sniff(iface=self.iface, filter=self.sfilter, prn=self.send_to_queue, store=False, **kwargs)
			except KeyboardInterrupt:
				print("\n[!] Arrêt !!!")
			except PermissionError:
				print(f"\n[CRITICAL ERROR] Permission denied. You must run this application with sudo privileges for packet sniffing.")
				print(f"[HINT] Try running: sudo ./run.sh")
			except Exception as e:
				print(f"[SNIFFER ERROR] {e}")
			return

		# 2. Mode Threadé avec Event
		while not self.stop_event.is_set():
			try:
				# Sniff avec timeout pour vérifier le stop_event régulièrement
				sniff(iface=self.iface, filter=self.sfilter, prn=self.send_to_queue, store=False, timeout=1, **kwargs)
			except KeyboardInterrupt:
				break
			except PermissionError:
				print(f"\n[CRITICAL ERROR] Permission denied during capture. Please restart with sudo.")
				import time
				time.sleep(5) # Avoid tight loop spamming error
			except Exception as e:
				print(f"[SNIFFER ERROR] {e}")
				import time
				time.sleep(1)
		
		print("[SNIFFER] Stopped.")

if __name__ == "__main__":
	from threading import Thread

	print("[i] Lancement du Sniffer")
	
	q = Queue(maxsize=100)
	sniffer = Sniffer(iface="enp4s0", sfilter="udp port 161 or udp port 162", queue=q)
	
	thread_sniff = Thread(target=sniffer.start_sniffer, daemon=True)
	thread_sniff.start()

	try:
		sniffer.afficher_trafic()
	except KeyboardInterrupt:
		print("\n[!] Arrêt du programme.")
