

devices = []    # Simple in-memory device registry simulating SCADA device inventory.


def add_device(device: dict):
    devices.append(device)


def list_devices():
    return devices


# PREVIOUS VULNERABLE: UNAUTHORIZED READ FROM PLC
# PATCHED: ENFORCEMENT - Check if the queried PLC exists in the device inventory, if it belongs to the approved
#                        SCADA network
def get_device_by_ip(ip: str):
    for d in devices:
        if d["ip"] == ip:
            return d
    return None
