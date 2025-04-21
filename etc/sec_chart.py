import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

protocols = ['AODV', 'SEAR', 'SUAP', 'AZT']
attack_types = [
    'Black Hole', 'Gray Hole', 'Wormhole', 
    'Impersonation', 'Hop Count Fraud',
    'Seq Num Manip', 'Spoofing',
    'Sybil', 'Message Forgery', 'Hello Flooding', 'Signature DoS', 'Select Forward',
    'Physical Access'
]

data = np.array([ 
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # AODV
    [2, 2, 1, 2, 2, 2, 2, 1, 2, 0, 2, 1, 0], # SEAR
    [2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 1, 0], # SUAP
    [2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1]  # AZT
])

df = pd.DataFrame(data, index=protocols, columns=attack_types)

# Decreased figure width from 10 to 8
plt.figure(figsize=(8, 4))

colors = [
'#ff9e9e', 
'#fff0a0',
'#a0e6a0']
cmap = sns.color_palette(colors, as_cmap=True)

ax = sns.heatmap(df, cmap=cmap, linewidths=1, linecolor='white', 
                cbar=False, vmin=0, vmax=2)
plt.xticks(np.arange(len(attack_types)) + 0.5, attack_types, rotation=45, ha='right', fontsize=12, weight='bold')
plt.yticks(np.arange(len(protocols)) + 0.5, protocols, rotation=0, fontsize=14, va='center', weight='bold')

# Adjust the aspect ratio to make the boxes shorter
ax.set_aspect('auto')

# Adjust bottom margin to make room for legend
plt.tight_layout()
plt.subplots_adjust(bottom=0.5)

# Move legend further down
legend_labels = ['Vulnerable', 'Partially Protected', 'Protected']
legend_colors = colors
patches = [plt.Rectangle((0, 0), 1, 1, color=color) for color in legend_colors]

plt.legend(patches, legend_labels, loc='upper center', bbox_to_anchor=(0.5, -.7),
           fontsize=12, framealpha=1, ncol=3, prop={'weight': 'bold'})

plt.savefig('protocol_security_comparison.pdf', bbox_inches='tight', dpi=300)
plt.show()