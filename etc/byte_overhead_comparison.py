import numpy as np
import matplotlib.pyplot as plt

plt.rcParams.update({'font.size': 10})

protocols = ['AZT', 'AODV', 'SUAP', 'SEAR']

hops = [1, 2, 3, 4, 5, 10, 15, 20, 25]

azt_overhead = [962, 2058, 3154, 4250, 5346, 10826, 16306, 21786, 27266]
aodv_overhead = [349, 695, 1047, 1399, 1751, 3511, 5273, 7039, 8805]
suap_overhead = [769, 1538, 2307, 3076, 3845, 7690, 11535, 15380, 19225]
sear_overhead = [959, 1986, 3013, 4040, 5067, 10827, 15978, 21327, 26589]

plt.figure(figsize=(8, 5))

m_azt, b_azt = np.polyfit(hops, azt_overhead, 1)
x_fit = np.array([1, 25])
y_fit_azt = m_azt * x_fit + b_azt

m_aodv, b_aodv = np.polyfit(hops, aodv_overhead, 1)
y_fit_aodv = m_aodv * x_fit + b_aodv

m_suap, b_suap = np.polyfit(hops, suap_overhead, 1)
y_fit_suap = m_suap * x_fit + b_suap

m_sear, b_sear = np.polyfit(hops, sear_overhead, 1)
y_fit_sear = m_sear * x_fit + b_sear

plt.scatter(hops, azt_overhead, color='#b30000', s=30, label='AZT Data')
plt.plot(x_fit, y_fit_azt, color='#b30000', linewidth=1.5, linestyle='--', 
         label=f'AZT Fit (y = {m_azt:.2f}x + {b_azt:.2f})')

plt.scatter(hops, aodv_overhead, color='#ff0000', s=30, label='AODV Data')
plt.plot(x_fit, y_fit_aodv, color='#ff0000', linewidth=1.5, linestyle='--', 
         label=f'AODV Fit (y = {m_aodv:.2f}x + {b_aodv:.2f})')

plt.scatter(hops, suap_overhead, color='#00ff00', s=30, label='SUAP Data')
plt.plot(x_fit, y_fit_suap, color='#00ff00', linewidth=1.5, linestyle='--', 
         label=f'SUAP Fit (y = {m_suap:.2f}x + {b_suap:.2f})')

plt.scatter(hops, sear_overhead, color='#ffbfbf', s=30, label='SEAR Data')
plt.plot(x_fit, y_fit_sear, color='#ffbfbf', linewidth=1.5, linestyle='--', 
         label=f'SEAR Fit (y = {m_sear:.2f}x + {b_sear:.2f})')

plt.grid(True, alpha=0.3)
plt.xlabel('Number of Hops', fontsize=12)
plt.ylabel('Overhead (Bytes)', fontsize=12)
plt.title('Simulation Byte Overhead Comparison: AZT vs AODV vs SUAP vs SEAR', fontsize=14)
plt.legend(fontsize=8, loc='upper left')

plt.xticks(fontsize=10)
plt.yticks(fontsize=10)

plt.tight_layout()
plt.savefig('byte_overhead_comparison.pdf', format='pdf', dpi=300, bbox_inches='tight')
plt.show()