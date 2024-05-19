import psutil
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
import time
import subprocess
import platform

def get_system_network_io():
    net_io = psutil.net_io_counters(pernic=False)
    connections = psutil.net_connections(kind='inet')

    total_in_bytes = net_io.bytes_recv
    total_out_bytes = net_io.bytes_sent
    total_in_packets = net_io.packets_recv
    total_out_packets = net_io.packets_sent

    details = []

    for conn in connections:
        if conn.status == psutil.CONN_ESTABLISHED:
            if conn.raddr:
                details.append({
                    'IPV4_SRC_ADDR': conn.laddr.ip,
                    'L4_SRC_PORT': conn.laddr.port,
                    'IPV4_DST_ADDR': conn.raddr.ip,
                    'L4_DST_PORT': conn.raddr.port,
                    'PROTOCOL': conn.type,
                    'TCP_FLAGS': 0,
                    'FLOW_DURATION_MILLISECONDS': 0
                })
            else:
                details.append({
                    'IPV4_SRC_ADDR': conn.raddr.ip if conn.raddr else 'unknown',
                    'L4_SRC_PORT': conn.raddr.port if conn.raddr else 0,
                    'IPV4_DST_ADDR': conn.laddr.ip,
                    'L4_DST_PORT': conn.laddr.port,
                    'PROTOCOL': conn.type,
                    'TCP_FLAGS': 0,
                    'FLOW_DURATION_MILLISECONDS': 0
                })

    return {
        'in_bytes': total_in_bytes,
        'out_bytes': total_out_bytes,
        'in_packets': total_in_packets,
        'out_packets': total_out_packets,
        'details': details
    }


def process_input(data):
    df = pd.DataFrame(data)

    label_encoder = LabelEncoder()
    for col in df.columns:
        if df[col].dtype == 'object':
            df[col] = label_encoder.fit_transform(df[col])

    model = joblib.load('DT_malacious_traffic_classifier.pkl')
    pred = model.predict(df)
    print(f"Prediction: {pred}")
    return pred

def redirect_traffic_to_honeypot(ip_address):
    subprocess.Popen(["netsh", "interface", "portproxy", "add", "v4tov4", "listenport=80", "listenaddress=0.0.0.0", "connectport=honeypot_port", "connectaddress=honeypot_ip"])

def main():
    while True:
        network_io = get_system_network_io()
        if network_io and network_io['details']:
            for detail in network_io['details']:
                prediction=process_input([[
                    detail['IPV4_SRC_ADDR'],
                    detail['L4_SRC_PORT'],
                    detail['IPV4_DST_ADDR'],
                    detail['L4_DST_PORT'],
                    detail['PROTOCOL'],
                    0,
                    network_io['in_bytes'],
                    network_io['out_bytes'],
                    network_io['in_packets'],
                    network_io['out_packets'],
                    detail['TCP_FLAGS'],
                    detail['FLOW_DURATION_MILLISECONDS']
                ]])
                if prediction[0] == 0:
                    if 'Windows' in platform.system():
                        redirect_traffic_to_honeypot(detail['IPV4_SRC_ADDR'])

        time.sleep(5)

if __name__ == "__main__":
    main()
