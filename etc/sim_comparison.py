import numpy as np
import matplotlib.pyplot as plt

# Increase the font size for better readability
plt.rcParams.update({'font.size': 10})  # Increased from 6 to 10

aodv_data = {
    'hops': [1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
    'times': [1.3, 4.0, 4.0, 5.0, 6.3, 10.0, 10.3, 13.1, 14.0, 13.9, 14.6, 17.8, 17.4, 
              18.1, 19.0, 20.7, 22.1, 21.6, 24.3, 24.9, 26.5]
}

secure_data = {
    'hops': [1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
    'times': [1.8, 6.2, 7.0, 18.4, 21.9, 22.2, 24.3, 23.1, 22.0, 22.9, 28.3, 28.6, 26.9, 
              27.3, 26.0, 27.3, 29.4, 29.9, 30.0, 30.1, 31.0]
}

suap_data = {
    'hops': [1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
    'times': [9.3, 22.6, 32.38, 36, 47.3, 58.9, 64.78, 72.38, 76.4, 77.88, 86.9, 90.22, 88.44, 
              92.1, 102.9, 101.2, 108.2, 109.56, 113.67, 119.13, 123.13]
}

sear_data = {
    'hops': [1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
    'times': [1.66, 7, 12.6, 17.33, 19.04, 20.15, 20.5, 21.2, 21.6, 22.7, 23.78, 24.3, 24.76, 
              25.1, 25.4, 24.76, 26.4, 27.83, 29.1, 29.44, 30.6]
}

# Make figure smaller but maintain readability
plt.figure(figsize=(8, 5))  # Reduced from 12x7 to 8x5

# AODV data and fit
m_aodv, b_aodv = np.polyfit(aodv_data['hops'], aodv_data['times'], 1)
x_fit_aodv = np.array([1, 25])
y_fit_aodv = m_aodv * x_fit_aodv + b_aodv

plt.scatter(aodv_data['hops'], aodv_data['times'], color='#ff0000', s=30, label='AODV Data')  # Reduced marker size
plt.plot(x_fit_aodv, y_fit_aodv, color='#ff0000', linewidth=1.5, linestyle='--', 
         label=f'AODV Fit (y = {m_aodv:.2f}x + {b_aodv:.2f})')

# AZT data and fit
a_secure, b_secure = np.polyfit(np.log(secure_data['hops']), secure_data['times'], 1)
x_fit_secure = np.linspace(1, 25, 100)
y_fit_secure = a_secure * np.log(x_fit_secure) + b_secure

plt.scatter(secure_data['hops'], secure_data['times'], color='#b30000', s=30, label='AZT Data')
plt.plot(x_fit_secure, y_fit_secure, color='#b30000', linewidth=1.5, linestyle='--',
         label=f'AZT Fit (y = {a_secure:.2f}ln(x) + {b_secure:.2f})')

a_sear, b_sear = np.polyfit(np.log(sear_data['hops']), sear_data['times'], 1)
x_fit_sear = np.linspace(1, 25, 100)
y_fit_sear = a_sear * np.log(x_fit_sear) + b_sear

plt.scatter(sear_data['hops'], sear_data['times'], color='#ffbfbf', s=30, label='SEAR Data')
plt.plot(x_fit_sear, y_fit_sear, color='#ffbfbf', linewidth=1.5, linestyle='--', 
         label=f'SEAR Fit (y = {a_sear:.2f}ln(x) + {b_sear:.2f})')

# SUAP data and fit
m_suap, b_suap = np.polyfit(suap_data['hops'], suap_data['times'], 1)
x_fit_suap = np.array([1, 25])
y_fit_suap = m_suap * x_fit_suap + b_suap
plt.scatter(suap_data['hops'], suap_data['times'], color='#00ff00', s=30, label='SUAP Data')
plt.plot(x_fit_suap, y_fit_suap, color='#00ff00', linewidth=1.5, linestyle='--', 
         label=f'SUAP Fit (y = {m_suap:.2f}x + {b_suap:.2f})')

plt.grid(True, alpha=0.3)
plt.xlabel('Number of Hops', fontsize=12)  # Increased font size
plt.ylabel('Time (ms)', fontsize=12)  # Increased font size
plt.title('Simulation Response Time Comparison: AZT vs AODV vs SUAP vs SEAR', fontsize=14)  # Increased font size

# Place legend outside the plot box
plt.legend(fontsize=8, loc='lower center', bbox_to_anchor=(0.5, -.5), borderaxespad=0)

plt.xticks(fontsize=10)  # Increased tick font size
plt.yticks(fontsize=10)  # Increased tick font size

# Adjust layout to make room for the legend
plt.tight_layout()
plt.subplots_adjust(right=0.78)  # Reduce the right margin to make space for legend

plt.savefig('sim_comparison_zoom.pdf', format='pdf', bbox_inches='tight', dpi=300)
plt.show()