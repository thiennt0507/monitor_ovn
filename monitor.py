import os
import subprocess
import re
import time
import csv
from lof import outliers
from loop import LocalOutlierProbability
import numpy as np
import signal
import pandas as pd

class Flow:
    def __init__(self, src, dst, bytes, time):
        self.src = src
        self.dst = dst
        self.bytes = bytes
        self.time = time

    def __repr__(self):
        return f"Flow(src={self.src}, dst={self.dst}, bytes={self.bytes}, time={self.time})"

def parse_flow_data(data):
    flows = []
    is_have_flow = False
    for entry in data:
        if 'ipv4' in entry:
            src_match = re.search(r'src=(1[^,/]+)', entry)
            dst_match = re.search(r'dst=(1[^,/]+)', entry)
            bytes_match = re.search(r'bytes:(\d+)', entry)
            
            if src_match and dst_match and bytes_match:
                src = src_match.group(1)
                if (src == '128.0.0.0'):
                    continue

                dst = dst_match.group(1)
                if (dst != '172.24.4.107' and dst != '172.24.4.222'):
                    continue

                bytes = int(bytes_match.group(1))
                
                for _flow in flows:
                    if (_flow.src == src and _flow.dst == dst):
                        is_have_flow = True

                
                if (is_have_flow):
                    is_have_flow = False
                    continue

                flow = Flow(src, dst, bytes, 0)

                
                
                flows.append(flow)
    return flows




x = os.popen('sudo ovs-dpctl dump-flows --names').read()
x = x.split('recirc_id')

old_flows = []

new_flows = []

def compareFlows(old_flows, new_flows):
    sum_vm_test_flow = 0
    sum_vm_test_bytes = 0

    sum_vm_victim_flow = 0
    sum_vm_victim_bytes = 0

    new_flow_test = 0
    new_flow_victim = 0

    for flow in new_flows:
        if (flow.bytes == 0):
            # if (flow.dst == host_test):
            #     new_flow_test += 1
            if (flow.dst == host_victim):
                new_flow_victim += 1
            continue
        new_flow, new_bytes = calcByteAndNewFlows(old_flows, flow)

        if (flow.dst == host_test):
            sum_vm_test_flow += 1
            sum_vm_test_bytes += new_bytes

        elif (flow.dst == host_victim):
            sum_vm_victim_flow += 1
            sum_vm_victim_bytes += new_bytes

    return sum_vm_test_flow , sum_vm_test_bytes, sum_vm_victim_flow + new_flow_victim, sum_vm_victim_bytes

def calcByteAndNewFlows(old_flows, flow):
    new_flow = 0
    new_bytes = 0
    isNewFlow = True
    for old_flow in old_flows:
        if old_flow.src == flow.src and old_flow.dst == flow.dst:
            new_bytes = flow.bytes - old_flow.bytes

            if (new_bytes < 0):
                new_bytes= flow.bytes

            old_flow.bytes = flow.bytes

            isNewFlow = False
            break
    if (isNewFlow):
        new_bytes = flow.bytes
        new_flow = 1
        old_flows.append(flow)
    return new_flow, new_bytes

count = 0

host_test = '172.24.4.222'
host_victim = '172.24.4.107'

process = None

instances = []

data = None

is_ddos = False

anomaly_count = 0

id_victim = '871237a2-f485-4809-be84-acaa4b092ad1'

try:
    with open('flow_data.csv', 'r') as csvfile:
        reader = csv.reader(csvfile)
        # Kiểm tra xem file có rỗng hay không
        if not next(reader):
            # File rỗng, không cần xóa
            pass
        else:
            # File không rỗng, xóa dữ liệu
            with open('flow_data.csv', 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # Ghi tiêu đề cột
                writer.writerow(['new_vm_test_flow/s', 'vm_test_bytes/s', 'new_vm_victim_flow/s', 'vm_victim_bytes/s'])
except FileNotFoundError:
    # File không tồn tại, không cần xử lý
    pass

while (True) :
    x = os.popen('sudo ovs-dpctl dump-flows --names').read().split('recirc_id')

    _flow_vm_test = 0
    _bytes_vm_test = 0

    _flow_vm_victim = 0
    _bytes_vm_victim = 0

    if (count == 0):
        old_flows = parse_flow_data(x)
        for flow in old_flows:
            if (flow.dst == host_test):
                _flow_vm_test += 1
                # _bytes_vm_test += flow.bytes

            elif (flow.dst == host_victim):
                _flow_vm_victim += 1
                # _bytes_vm_victim += flow.bytes
    else:
        new_flows = parse_flow_data(x)
        _flow_vm_test, _bytes_vm_test, _flow_vm_victim, _bytes_vm_victim = compareFlows(old_flows, new_flows)
        
    count += 1 
    time.sleep(1)
    print(f"Count {count}: vm_test: {_flow_vm_test}-{_bytes_vm_test}, vm_victime: {_flow_vm_victim}-{_bytes_vm_victim}")

    with open('flow_data.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([_flow_vm_test, _bytes_vm_test, _flow_vm_victim, _bytes_vm_victim])
    

    instances.append([_flow_vm_victim, _bytes_vm_victim])

    # lof = outliers(5, instances)

    # for outlier in lof:
    # print outlier["lof"],outlier["instance"]

    if (count > 3):

        data = np.array(instances)

        scores = LocalOutlierProbability(data, extent=0.997, n_neighbors=20).fit()

        if (scores[len(scores) - 1] > 0.8):
            anomaly_count += 1
        else:
            anomaly_count = 0

        if (anomaly_count == 10 and _bytes_vm_victim > 100000):
            print("He thong bi tan cong DDOS")
            print("Dang tat floating IP")

            data = subprocess.call('openstack server remove floating ip 71237a2-f485-4809-be84-acaa4b092ad1 172.24.4.107', shell=True)
    
        if (count == 300):
            df = pd.DataFrame(scores)
            df.to_csv("loop_score.csv")
            break


# lof = LOF(instances)

# for instance in [[0,0],[5,5],[10,10],[-8,-8]]:
#     value = lof.local_outlier_factor(5, instance)
#     print(value, instance)

# parsed_flows = parse_flow_data(x)

# for flow in parsed_flows:
#     if (flow.src == '192.168.233.112'):
#         print(flow)

            







