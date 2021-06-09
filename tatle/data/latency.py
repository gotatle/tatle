#!/usr/bin/python


import matplotlib.pyplot as plt
import numpy as np
import sys

def get_data_from_file(filename):
    lines = open(filename, 'r').readlines()
    data = list(map(lambda x: int(x.rstrip()), lines))
    #data = list(map(lambda x: x / 1000000.0, data))
    return data

honest_input_files = [
        "keygen_10_honest.txt",
        "keygen_15_honest.txt",
        "keygen_20_honest.txt",
        "keygen_30_honest.txt"
]

malicious_input_files = [
        "keygen_10_malicious.txt",
        "keygen_15_malicious.txt",
        "keygen_20_malicious.txt",
        "keygen_30_malicious.txt"
]
malicious_input_files = honest_input_files


output_file = "latency.pdf"

honest_data = [get_data_from_file(f) for f in honest_input_files]
malicious_data = [get_data_from_file(f) for f in malicious_input_files]

fig, axes = plt.subplots(figsize=(8,4))
bplot1 = plt.boxplot(honest_data, vert=True,   patch_artist=True, positions = [1,3,5,7], sym='k.')
bplot2 = plt.boxplot(malicious_data, vert=True,   patch_artist=True, positions = [2,4,6,8], sym='k.')

colors = ['lightblue', 'lightgreen']
for bplot, color in zip([bplot1, bplot2], colors):
    for patch in bplot['boxes']:
        patch.set_facecolor(color)

titles = ['Semi-Honest', 'Malicious']

plt.ylabel('Latency (millisec)')
plt.yticks(np.arange(0,500,step=50))
plt.ylim(0,500)
#plt.title('Latency Measurement')
plt.tight_layout()
#axes.set_xticklabels(['Acme', 'ML', 'PSI', 'Survey'])
#axes.set_xticks([0.4, 4.5, 8.5, 11.5], ['Acme', 'ML', 'PSI', 'Survey'])
plt.setp(axes, xticks=[0.4, 4.5, 8.5, 11.5], xticklabels=['2^10', '2^15', '2^20', '2^30'])
axes.legend([bplot1["boxes"][0], bplot2["boxes"][0]], ['Hyperledger', 'Tendermint'], loc=2,prop={'size': 9})
#plt.show()
plt.savefig(output_file)
