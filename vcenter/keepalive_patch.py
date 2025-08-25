from pyVim.connect import KeepAliveThread


def attach_keepalive(service_instance, interval_sec: int = 600):
    try:
        KeepAliveThread(service_instance, interval_sec)
    except Exception:
        pass
