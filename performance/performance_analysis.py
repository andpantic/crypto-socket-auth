import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

sns.set_style('whitegrid')

aes_df = pd.read_csv('aes_performance.csv')
rsa_df = pd.read_csv('rsa_performance.csv')

aes_encrypt = aes_df[aes_df['operation'] == 'encrypt']['duration_ms'].reset_index(drop=True)
aes_decrypt = aes_df[aes_df['operation'] == 'decrypt']['duration_ms'].reset_index(drop=True)
aes_auth    = aes_df[aes_df['operation'] == 'auth_total']['duration_ms'].reset_index(drop=True)

rsa_encrypt = rsa_df[rsa_df['operation'] == 'encrypt']['duration_ms'].reset_index(drop=True)
rsa_decrypt = rsa_df[rsa_df['operation'] == 'decrypt']['duration_ms'].reset_index(drop=True)
rsa_auth    = rsa_df[rsa_df['operation'] == 'auth_total']['duration_ms'].reset_index(drop=True)

aes_color = '#2E86AB'
rsa_color = '#D62828'

# encryption
plt.figure(figsize=(8, 5))
plt.plot(range(len(aes_encrypt)), aes_encrypt, linewidth=2.2, color=aes_color, label='AES-GCM')
plt.plot(range(len(rsa_encrypt)), rsa_encrypt, linewidth=2.2, color=rsa_color, label='RSA')
plt.title('AES-GCM vs RSA: Encryption Times', fontsize=14, fontweight='bold')
plt.ylabel('Duration (ms)')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('aes_rsa_encryption_times.png', dpi=300, bbox_inches='tight')
plt.show()

# decryption
plt.figure(figsize=(8, 5))
plt.plot(range(len(aes_decrypt)), aes_decrypt, linewidth=2.2, color=aes_color, label='AES-GCM')
plt.plot(range(len(rsa_decrypt)), rsa_decrypt, linewidth=2.2, color=rsa_color, label='RSA')
plt.title('AES-GCM vs RSA: Decryption Times', fontsize=14, fontweight='bold')
plt.ylabel('Duration (ms)')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('aes_rsa_decryption_times.png', dpi=300, bbox_inches='tight')
plt.show()

# authentication
plt.figure(figsize=(8, 5))
plt.plot(range(len(aes_auth)), aes_auth, linewidth=2.2, color=aes_color, label='AES-GCM')
plt.plot(range(len(rsa_auth)), rsa_auth, linewidth=2.2, color=rsa_color, label='RSA')
plt.title('AES-GCM vs RSA: Authentication Times', fontsize=14, fontweight='bold')
plt.ylabel('Duration (ms)')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('aes_rsa_authentication_times.png', dpi=300, bbox_inches='tight')
plt.show()

print("=== AES Averages ===")
print(f"Encryption: {aes_encrypt.mean():.2f} ms")
print(f"Decryption: {aes_decrypt.mean():.2f} ms")
print(f"Authentication: {aes_auth.mean():.2f} ms")
print("\n=== RSA Averages ===")
print(f"Encryption: {rsa_encrypt.mean():.2f} ms")
print(f"Decryption: {rsa_decrypt.mean():.2f} ms")
print(f"Authentication: {rsa_auth.mean():.2f} ms")
