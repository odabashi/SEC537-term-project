

devices = []    # Simple in-memory device registry simulating SCADA device inventory.


def add_device(device: dict):
    devices.append(device)


def list_devices():
    return devices
